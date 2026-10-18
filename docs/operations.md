# Operations

How to run SentinelSSH day to day: the commands, logging, local state, host-key rotation and troubleshooting.

- [Commands](#commands)
- [Logging](#logging)
- [Local state](#local-state)
- [Rotating a host key](#rotating-a-host-key)
- [Adding or removing a host](#adding-or-removing-a-host)
- [Onboarding a host safely](#onboarding-a-host-safely)
- [Running as root](#running-as-root)
- [Troubleshooting](#troubleshooting)

## Commands

| Command | What it does | Network |
|---|---|---|
| `sentinel-ssh serve [--config PATH]` | Runs the MCP server on stdin/stdout until the client disconnects. | yes, on tool calls |
| `sentinel-ssh doctor [--config PATH]` | Checks the configuration, private directories, identity files and the SSH client. | no |
| `sentinel-ssh doctor --connect [--config PATH]` | Also connects to each host and runs `true`. | yes, read-only |
| `sentinel-ssh config lint [--config PATH]` | Loads and validates the configuration only. | no |
| `sentinel-ssh schemas` | Prints every tool's input and output JSON Schema. | no |
| `sentinel-ssh --version` | Prints the version. | no |

`doctor` and `config lint` exit `0` on success and `1` on any failure, so they can gate a deployment script. `doctor` creates the private directories if they do not exist yet.

## Logging

`serve` writes logs to **stderr only**, because stdout is the MCP channel. The level comes from `SENTINEL_LOG`, using `tracing` filter syntax, and defaults to `sentinel_gateway=info`.

```bash
SENTINEL_LOG=sentinel_gateway=debug sentinel-ssh serve
```

What goes where:

- Agents receive fixed error messages only.
- Raw remote stderr (which can name absolute paths or carry attacker-chosen text) and SSH client failures are logged at `warn`, so look there when a result says "details are in the gateway log".
- Command lines are not logged above `debug`.

Most MCP clients show or store a server's stderr. Check your client's documentation for where.

## Local state

| Location | Contents | Lifetime |
|---|---|---|
| `artifact_dir` (default `~/.local/share/sentinel-ssh/artifacts`) | Downloads and spilled results: `art_<id>.bin` with `art_<id>.json` metadata, both mode `0600` | `artifact_retention_hours` (24 h), swept every 10 minutes while serving |
| `runtime_dir` (default `~/.local/state/sentinel-ssh/run`) | `kh-<digest>` known_hosts files, `c-<digest>` connection sockets | Sockets close 60 s after the last call |
| In memory | Operation records | Finished records are kept for 1 h, at most 4096 in total; all are lost when the server exits |

Each principal's live artefacts are capped by `max_artifact_bytes` (1 GiB). Deleting `artifact_dir` while the server is stopped is safe, and so is deleting `runtime_dir`.

## Rotating a host key

1. Obtain the new key through a trusted channel (see [getting started](getting-started.md#3-pin-the-host-key)).
2. Replace `host_key` for that host in the configuration.
3. Restart the MCP server (most clients restart it when you reconnect).

The `known_hosts` file and the connection socket are named after a digest of the host's whole trust identity. The new pin therefore gets a fresh file and a fresh connection automatically, and the old ones are simply unused. Never "fix" a `HOST_KEY_CHANGED` by pasting in whatever key the host now presents without checking it out of band: that is exactly the attack the pin exists to stop.

## Adding or removing a host

Edit the configuration and restart the server. The configuration is read once at start-up. Run `sentinel-ssh doctor --connect` after any change.

## Onboarding a host safely

The pattern used to bring real hosts under SentinelSSH, each step reversible:

1. **Pin the host key from a trusted source.** Compare the key the network presents with your existing `known_hosts` entry, or with what the host reports from its console (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`). Never pin a key you have only seen over the network you are about to trust.
2. **Use a key per host,** generated for SentinelSSH and stored outside `~/.ssh` (for example `~/.config/sentinel-ssh/keys/<host>`, mode `0600`). Mark it `restrict` in `authorized_keys`.
3. **Prefer an unprivileged account:** `useradd -m -s /bin/sh sentinel-observer`, add it to `adm` to read logs, no sudo.
4. **Check sshd's access rules first.** If `sshd -T` shows `AllowUsers` or `AllowGroups`, the new account cannot log in. Add it with a drop-in (`/etc/ssh/sshd_config.d/60-sentinel-observer.conf` containing `AllowUsers sentinel-observer`; OpenSSH appends to the list), keep an existing session open, run `sshd -t`, reload, and confirm a **fresh** login for your existing admin user before closing the old session.
5. **Register narrowly.** Logs and services are usually enough. Leave out directories that hold credentials: application folders with `.env` files, WordPress `wp-config.php`, Moodle `config.php`, VPN configs with private keys.
6. **Verify:** `sentinel-ssh doctor --connect`, then a few read-only calls and a few that must be refused.

To undo: delete the key's line from `authorized_keys`, `userdel -r sentinel-observer`, and remove any drop-in, then `sshd -t && systemctl reload ssh`.

## Running as root

`user = "root"` with a root key is accepted. The tools stay exactly as read-only and as scoped to registered roots; what changes is reach and risk:

- **Reach:** root-only files inside registered roots become readable (for example a database slow log or `btmp`), and disk usage no longer skips unreadable subtrees.
- **Risk:** the key file is a full root credential. Anyone who copies it owns the host, outside SentinelSSH entirely. Containment then rests only on the gateway, because the account blocks nothing.

If you choose it, use a dedicated root key per host marked `restrict`, keep registered roots as narrow as before, and prefer it only for hosts you could rebuild. A targeted alternative is to grant the unprivileged observer read access to the specific root-only files you need (for example group membership or an ACL).

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `config file ... must be mode 0600` | The config is group or world readable | `chmod 600` the file |
| `... must be owned by the current user` | The file or directory belongs to another account | Fix ownership, or point the setting elsewhere |
| `ancestor ... is owned or writable by other users` | A parent directory of `artifact_dir`, `runtime_dir` or `ssh_binary` is writable by others | Tighten that directory, or move the setting under your home directory |
| `runtime_dir is too long for an SSH ControlPath socket` | Socket paths are limited to about 100 bytes | Use a `runtime_dir` of at most 63 bytes |
| `HOST_KEY_CHANGED` | The host presents a key other than the pinned one | Check the real key out of band. Update the pin only if the change is expected. |
| `AUTHENTICATION_FAILED` | The key is not authorised for the account, or `restrict`/`from=` rejected it | Check `authorized_keys`, the user name and the key path |
| `identity file ... must be ...` or refuses to connect | The identity file is missing or too permissive | Create it or `chmod 600` it. The gateway refuses rather than fall back to your default keys. |
| `SSH_AUTH_SOCK is not set` | Agent auth with no running agent | Start an agent and add the key, or switch to `identity_file` |
| `ssh.binary ... OpenSSH` version failure | The client is older than 8.9, or not OpenSSH | Install a newer OpenSSH, or set `ssh_binary` to one |
| `CAPABILITY_UNSUPPORTED: remote utility missing` | A required GNU tool is absent on the host | Install coreutils, findutils, procps or grep; see [supported platforms](supported-platforms.md) |
| `does not support the required options (GNU utilities required)` | BusyBox or BSD userland | Not supported in v0.1 |
| Service tools say systemd is not reachable | No systemd, or `scope = "user"` with no user session | Expected on such hosts; use other tools |
| `REMOTE_FAILURE: the SSH account cannot read this path` | Host permissions | Grant the account read access, or stop registering the path |
| `REMOTE_FAILURE: the registered root does not exist on the host` | Wrong `path` for a root | Correct the configuration |
| `POLICY_DENIED: unknown root '...'` for a root you configured | The root has `read = false` | Expected: unreadable roots are hidden |
| `POLICY_DENIED: hard-linked files are refused` | The target file has more than one name | Expected; read it through its single-link original, or register that location |
| `BUDGET_EXCEEDED: gateway queue is full` | Too many calls at once | Retry after a second, or raise `max_pending_operations` |
| `TIMEOUT` | The command ran past `read_timeout_secs` | Narrow the request (`last_bytes`, a deeper `path`), or raise the budget |
| The client says the server exited right after a huge request | A request line over 1 MiB | Expected protection; send smaller requests |
