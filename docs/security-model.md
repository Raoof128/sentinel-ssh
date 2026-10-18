# Security model

> **The gateway enforces the tool interface. The SSH account may permit more; it is not a remote sandbox.**

This page states what SentinelSSH v0.1 protects, against whom, and where it stops. Every guarantee listed is enforced in code and exercised by tests, most of them against a real sshd in a disposable container that has the attacks planted in it.

- [Threat model](#threat-model)
- [Guarantees](#guarantees)
- [Containment on the host](#containment-on-the-host)
- [The SSH client](#the-ssh-client)
- [Local trust inputs](#local-trust-inputs)
- [Untrusted remote content](#untrusted-remote-content)
- [Resource bounds](#resource-bounds)
- [Limits of observer mode](#limits-of-observer-mode)
- [Deployment checklist](#deployment-checklist)
- [How this was tested](#how-this-was-tested)

## Threat model

| Party | Trusted? | What SentinelSSH assumes |
|---|---|---|
| **The operator** (you) | Yes | Writes the configuration, chooses the hosts, roots and ids, and owns the gateway machine and account. |
| **The AI agent** | No | May be confused or manipulated by content it reads (prompt injection). It may request anything the tool schemas allow, in any order, at any rate. |
| **Content on the host** | No | File names, file contents, log lines, process arguments and service text may be crafted by an attacker. |
| **Other local accounts** on the gateway machine | No | May try to swap directories, sockets or the `ssh` binary that the gateway relies on. |
| **The network** | No | Protected by SSH with a pinned host key. |
| **The target host's OS and SSH account** | Partly | The host's own utilities are assumed genuine. The account is assumed to be limited by the host's ordinary permissions, and SentinelSSH adds no remote enforcement in v0.1. |

The central goal is that **an agent, or content it reads, cannot turn the typed tools into anything broader**: no arbitrary command, no path outside a registered root, no download from a root without `export`, no secret into model context through the bulk transfer path.

## Guarantees

1. **No arbitrary execution.** No tool accepts a command. Each tool's remote command is fixed and built from allowlisted programs. Static flags are checked by a runtime assertion, and every runtime value is single-quoted. The quality gate rejects shell metacharacters in flag literals.
2. **Deny by default.** Each call is authorised against the configuration before the host is contacted. Unregistered hosts, roots, services, log sources and health checks do not exist as far as the agent can tell. A root the principal cannot read answers exactly like an unknown one.
3. **Scoped paths.** A path is a root alias plus a relative path. `.` and `..` components, absolute paths, empty components, control characters and over-long paths are rejected locally. On the host the target is pinned (below), so symlinks cannot lead outside the root.
4. **Export is separate from read.** Downloads need `export = true`, which itself requires `read = true`. A nested root without `export` stays closed to downloads through an exportable parent.
5. **Pinned host keys.** Each host's key is configured. An unknown or changed key stops the call with `HOST_KEY_CHANGED`, and nothing is dispatched.
6. **Bytes stay out of context.** Downloads are streamed into owner-only artefacts and verified against a SHA-256 taken on the host. A mismatch, short stream or source change deletes the partial file. Results are bounded, and larger ones move to an artefact.
7. **Bounded everything.** Result sizes, transfer size and time, concurrency, queues, request size and the operation registry all have limits (see [resource bounds](#resource-bounds)).

## Containment on the host

Every file-level tool runs inside a fixed POSIX `sh` prologue that pins its target before anything is read. The prologue uses GNU `realpath`, `stat`, `cd -P` and `/dev/fd`.

| Pin | Used by | What is checked |
|---|---|---|
| **Directory** | `ssh_files_list` | The target must be a real directory (`lstat`), not a symlink. It is entered with `cd -P`, and the resolved working directory must lie inside the resolved root and outside every excluded root. The listing then reads `.`, the pinned directory. |
| **Tree** | `ssh_disk_usage` | As for a directory, and additionally refused when an excluded root lies inside it, because `du` cannot skip a subtree exactly. |
| **Entry** | `ssh_file_stat` | The parent directory is pinned as above. The entry is described in place without following a final symlink, and it must not itself be an excluded root. |
| **File** | read, hash, download | The parent is pinned. The entry must be a regular file by `lstat`. It is opened **once** on descriptor 3. That descriptor's real path must lie inside the root and outside excluded roots, it must be a regular file, and its link count must be 1. Only descriptor 3 is read afterwards. |
| **Exact file** | log sources | The file must resolve to exactly its configured path, be a regular file, and have one link. It is read through descriptor 3. |

What this defeats (each case is a planted attack in the test fixture):

- **Symlink swaps and check-then-use races.** A path swapped for a symlink to a secret after the check cannot redirect the read, because the read uses the descriptor that was checked. A live attacker swapping a file between a decoy, a symlink and a hard link to the secret during 120 reads, hashes and downloads never obtained it.
- **Hard links.** A hard link to a secret has a real path inside the root. Refusing link counts above 1 closes it.
- **Prefix tricks.** A sibling directory named `/srv/app` followed by a newline, or `/srv/apple`, is not inside `/srv/app`. Paths are compared component-wise, and resolved names containing a newline are refused.
- **Special files.** FIFOs and devices are refused by type before they are opened, so a read cannot block on them.
- **Nested forbidden roots.** A `read = false` root inside a readable one is skipped by listings (by inode, with `find ! -samefile`), refused for disk usage, and refused for stat.
- **The filesystem root.** A root or excluded root that resolves to `/` counts as containing everything, so the check cannot fail open. `/` itself cannot be registered.

Refusals map to typed errors: `POLICY_DENIED` for containment, `NOT_FOUND` for a missing target, and `REMOTE_FAILURE` when the account lacks permission.

## The SSH client

SentinelSSH runs your system's OpenSSH client with a fully specified command line:

- `-F /dev/null`, so neither `~/.ssh/config` nor `/etc/ssh/ssh_config` is read. This was verified with options set in the system file.
- `StrictHostKeyChecking=yes`, with a `known_hosts` file the gateway writes per host trust identity, plus `HostKeyAlias`. Pins for different hosts never share a file.
- Agent forwarding, X11, port forwarding, tunnels, `ProxyCommand`, `LocalCommand` and TTY allocation are all disabled, and the effective-config check confirms no `ProxyJump` or forward is set. `BatchMode=yes` means it never prompts. With an identity file, `IdentityAgent=none` keeps the agent out entirely.
- An explicit identity with `IdentitiesOnly=yes`. If the identity file is missing, the gateway refuses rather than let OpenSSH fall back to your default keys. With agent auth, either no on-disk key or exactly one pinned agent key is offered.
- Before the first call to each host, `ssh -G` confirms the effective configuration matches. Before every call, the identity file and the per-host `known_hosts` are re-verified.
- Connections are reused with `ControlMaster` for 60 seconds. The socket is in the private runtime directory, named by a digest of the host's full trust identity: host id, address, port, user, pinned key, credential and identity-file content. A changed pin or key never reuses an old connection. The runtime directory's device and inode are re-checked before every spawn.
- The client runs in its own process group with a cleared, minimal environment, and the whole group is killed on timeout or cancellation.
- Every remote command is wrapped as `LC_ALL=C; export LC_ALL; exec timeout -k 5 <secs> sh -c '<cmd>'`. Output is parsed in a fixed locale, and a hung command is killed on the host.

## Local trust inputs

On the gateway machine, the configuration file and identity files must be owned by you with mode `0600` or stricter. Artefact and runtime directories must be real `0700` directories owned by you. Every ancestor of those directories and of `ssh_binary`, along both the written path and the resolved one, must be owned by root or you, and not writable by others unless sticky. A symlink component is judged by its owner. `ssh_binary` must resolve to a file that only root or you can modify. These checks stop another local account from swapping something the gateway trusts.

## Untrusted remote content

- Every result that carries remote text is labelled `content_trust: "untrusted"`. The server instructions tell agents to treat it as data, never as instructions.
- Names, log lines, process arguments and service text are display-escaped (file contents are returned exactly as stored). Control characters, Unicode format characters (zero-width, bidirectional overrides, tags), line and paragraph separators, and every default-ignorable code point become `\u{XXXX}`, and backslashes are doubled, so a name cannot hide or reorder text.
- Section markers in multi-part output carry a random nonce per call, so remote content cannot forge a section boundary.
- Error messages about the host are fixed text. Raw remote stderr, which can contain attacker-chosen file names, goes only to the local log. Capability errors are recognised only in the exact formats the shell and GNU tools print, for programs the command actually ran, so a crafted file name cannot pose as a "not found" message.
- Process arguments pass through a best-effort credential filter (see [`ssh_process_list`](tools.md#ssh_process_list)). It is a filter, not a guarantee.
- Health-check results withhold URL queries and fragments; URLs with embedded credentials are rejected at load.

## Resource bounds

| Bound | Default |
|---|---|
| Result size | 8 KiB concise, 64 KiB full; larger results move to an artefact |
| Request line on stdin | 1 MiB; a longer line ends the session |
| Concurrency | 64 active operations, 4 reads per host, 1 download per host |
| Queues | 128 pending in total, 32 per host, 5 s wait |
| Timeouts | 10 s connect, 30 s per read command (also enforced on the host), 30 s idle and 600 s total per download |
| Transfers | 256 MiB per file, 1 GiB of live artefacts per principal, 24 h retention |
| Registry | 4096 operation records |
| Errors | Messages clipped to 512 characters, details to 256 |

The request-line limit, the registry size and the error clipping are fixed constants. Everything else is a budget, configurable within checked ranges; see the [configuration reference](configuration.md#gatewaybudgets).

## Limits of observer mode

These are deliberate, documented limits of v0.1. Later stages of the spec address them.

- **No remote enforcement.** Anyone holding the observer account's key can run anything that account may run. The gateway controls what the *agent* can ask for, not what the *key* can do. Use a dedicated, low-privilege account, a `restrict` key and file permissions that expose only what you register. The planned Stage 2 broker moves enforcement onto the host.
- **The prologue trusts the host.** Containment relies on the host's own `realpath`, `stat`, `/dev/fd` and shell being genuine, and on the account being unable to replace them. A compromised host is out of scope.
- **Cancellation is not confirmed remotely.** Cancelling stops the local client. The host-side `timeout` ends the command at the latest when the read timeout expires, but `remote_termination` stays `unconfirmed`.
- **Same-account visibility.** The process list hides this call's own processes, but other sessions of the same account (including other gateway connections) remain visible, as any `ps` would show them.
- **Roots should be real directories.** A root whose own path is a symlink resolves correctly for containment, but listing the root itself is refused.
- **No changes, approvals or uploads.** Plan, stage and change effects are denied for every role.
- **Not independently reviewed.** v0.1 has been red-teamed by its authors, not audited by a third party.

## Deployment checklist

- [ ] A dedicated account on each host, with a POSIX login shell and the least access that works.
- [ ] A key used only for SentinelSSH, marked `restrict` (and ideally `from="..."`) in `authorized_keys`.
- [ ] Host keys obtained out of band and pinned in the configuration.
- [ ] Roots registered as narrowly as possible; `export = true` only where downloads are needed.
- [ ] Secrets kept outside every readable root, or inside a nested `read = false` root.
- [ ] Configuration and identity files at mode `0600`.
- [ ] `sentinel-ssh doctor --connect` passes.

## How this was tested

- **Unit and contract tests** use a scripted fake backend that asserts on the exact remote command text, plus property tests for path scoping and the operation state machine.
- **End-to-end tests** run the real OpenSSH backend against a disposable Debian sshd container. It is seeded with synthetic data and planted attacks: symlinks and hard links to a fake secret, a newline-named sibling, nested forbidden roots, FIFOs, non-UTF-8 names, an injected log line, and a live swap-race attacker.
- **The quality gate** (`scripts/check.sh`) requires every product source line to execute at least once under those tests, alongside formatting, lints, `forbid(unsafe_code)`, a secret scan and a scan of remote flag literals.
- Several findings came from automated security review of each commit. Each was fixed with a test that failed first, and the key ones were mutation-checked.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).
