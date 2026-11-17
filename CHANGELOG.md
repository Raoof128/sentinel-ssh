# Changelog

All notable changes to SentinelSSH are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

Red-team hardening of observer mode. Everything below is on `main` but is not part of the `v0.1.0` tag.

### Raouf: 2026-11-17d (Australia/Sydney) — fake-ssh race fixed, rendered-command test, `-` operands, redaction limits

- **Scope:** test support, tests, `ssh/command.rs`, `ssh/openssh.rs`, `tools/processes.rs`, `tools/health.rs`, CI, docs.
- **Summary:** Closes the three follow-ups of 2026-11-17c and records an adversarial read of the command builder, the OpenSSH argv and each tool.
  - **The "Text file busy" race is fixed at its cause.** The fake-`ssh` helpers wrote a script and the gateway executed it at once. On Linux `execve` fails with ETXTBSY while any process holds the file open for writing, and a `fork` on another test thread copies that descriptor into its child until the child reaches `exec`. `sentinel_testkit::configs::write_executable` now has a child process write the script, so the test process never holds a write descriptor that a fork could copy. `tests/openssh_argv.rs` uses the same helper. CI no longer sets `RUST_TEST_THREADS=1`.
  - **Every tool's remote command is rendered with hostile inputs and checked as text** (`tests/rendered_commands.rs`): the fixed text is the same as for a harmless value, each utility gets only its listed read-only options, the only redirections are four known forms, and no value can be read as an option or as stdin. The checks are themselves tested against 31 bad commands.
  - **Finding, fixed: a file named `-`.** GNU `stat` reads the operand `-` as standard input even after `--`. For a path whose last component was `-`, the type check before a read looked at the session's stdin and refused the file as "not a regular file", and `ssh_file_stat` described stdin as if it were the file. It failed closed for reads and returned a wrong answer for stat; nothing outside a root was reachable. Entry operands are now written `./<name>` (`operand`, `entry_operand`), for `contained` and for `exact_file`.
  - **Hardening, no known attack:** `VerifyHostKeyDNS=no` and `NoHostAuthenticationForLocalhost=no` are pinned in the argv (the two client options that accept a host key outside the pinned file; both were already off by default and unreachable through `-F /dev/null`). Health checks run `curl -g`, so a registered URL is requested once, as written.
  - **Redaction reviewed.** Added: the same-word forms of program password options (`curl -uuser:pw`, `--user=user:pw`, `sshpass -ppw`), JSON members with a credential-ish name, `redis-cli -a`, the `mongo` tools' `-p`, `sqlcmd -P`, `mosquitto -P`, and more self-identifying token formats. What it still cannot catch is listed in `docs/security-model.md` and pinned by `redaction_limits_are_the_documented_ones`.
  - **Adversarial read, nothing else found.** Argument injection: every caller string is single-quoted and comes after `--` or as an option's argument; numbers are range-checked integers. Path escape and link races: the prologue pins by working directory and open descriptor, and the fixture's planted attacks still pass. Globbing: no unquoted expansion of a caller value. Environment: the client runs with a cleared environment; on the host only `LC_ALL` is set, and the account's `PATH` decides which utilities run, which is now stated as a limit. OpenSSH: `-F /dev/null`, forwarding, proxy and local commands off, the control socket in a 0700 directory whose identity is re-checked before every spawn.
  - **Docs:** `AGENT.md` and the v0.1 task plan now open with a line saying they are AI-assistant working documents; the note about the developer's machine is gone. README says Rust 1.97.1, as `rust-toolchain.toml` does.
- **Files changed:** `crates/sentinel-testkit/src/configs.rs`, `crates/sentinel-testkit/tests/script_exec_race.rs` (new), `crates/sentinel-testkit/docker/seed.sh`, `crates/sentinel-gateway/src/ssh/command.rs`, `crates/sentinel-gateway/src/ssh/openssh.rs`, `crates/sentinel-gateway/src/tools/files.rs`, `crates/sentinel-gateway/src/tools/health.rs`, `crates/sentinel-gateway/src/tools/processes.rs`, `crates/sentinel-gateway/tests/rendered_commands.rs` (new), `crates/sentinel-gateway/tests/{e2e_fixture,hardening,openssh_argv,tools_download,tools_edge_cases,tools_file_level}.rs`, `crates/sentinel-gateway/tests/snapshots/openssh_argv__argv_is_fully_controlled.snap`, `.github/workflows/ci.yml`, `README.md`, `docs/security-model.md`, `docs/tools.md`, `docs/configuration.md`, `docs/superpowers/plans/2026-10-18-sentinelssh-v0.1-observer.md`, `AGENT.md`, `CHANGELOG.md`.
- **Verification:** in a Linux container (`rust:1.97.1-bookworm`, 4 CPUs, non-root user) the new stress test passed, the whole suite passed 5 times in a row at the default thread count (311 tests each), and the same stress test failed with "Text file busy" within a few rounds when the helper was switched back to writing in-process. `bash scripts/check.sh` passed locally against the Docker fixture: 3877/3877 product lines executed, 323 tests, including a new end-to-end test that reads, stats, hashes and downloads files named `-`, `--help` and `-rf`. Both CI jobs on the pull request.
- **Follow-ups:** none open from this entry. The rendered-command test reads commands as text; running them in a real shell with a tracing wrapper would be a stronger form of the same check.

### Raouf: 2026-11-17c (Australia/Sydney) — limits of root and sudo modes; full gate in CI

- **Scope:** docs, CI.
- **Summary:** The operations guide suggested a "narrower" sudoers rule for `elevation = "sudo"`. None can exist for this design: the gateway's commands run as `sudo -n -- timeout ... sh -c '<command>'`, so any rule that lets them through permits arbitrary root commands for whoever holds the key. The sentence is replaced, and the security model lists root and sudo modes under its limits, including that the process list then returns root's process arguments. The README gains a Testing section (what the quick gate covers, that the end-to-end and red-team suites skip without a fixture, what line coverage does and does not show) and the Quick start says it needs a clone and points at the key-setup steps. CI gains a second job that runs the full gate. This supersedes the 2026-11-05 follow-up that suggested a narrow sudoers rule.
- **Files changed:** `docs/operations.md`, `docs/security-model.md`, `README.md`, `.github/workflows/ci.yml`, `docs/superpowers/plans/2026-10-18-sentinelssh-v0.1-observer.md`, `AGENT.md`, `CHANGELOG.md`.
- **Verification:** on pull request #4 both CI jobs passed, including the first run of the full gate on a hosted runner: Docker sshd fixture, end-to-end and red-team suites, 100% product line coverage. No product code changed.
- **Follow-ups:** add a test that scans every rendered remote command for write-capable flags (`find -delete`, `-exec`, a non-null `curl -o`); the program allowlist is by name only. The second CI run of the full gate failed once in `openssh_argv::run_collects_output_and_exit` with "Text file busy": a race between writing a fake `ssh` script and another test thread forking. CI now runs tests on one thread; the helper in `sentinel-testkit` should be made race-free instead.

### Raouf: 2026-11-17b (Australia/Sydney) — design plan moved under docs, how-it-was-built note

- **Scope:** docs only.
- **Summary:** A reader's first view of the file list showed a 1,262-line plan at the repository root that says "No product has been implemented". It now lives at `docs/design/2026-10-18-comprehensive-plan.md` under a banner saying it is the pre-implementation plan and that v0.1 implements part of it. The changelog's description of the hosts used for live validation no longer names the provider or their hardening. The README gained a short "How it was built" section stating that most of the code was written with AI coding assistants.
- **Files changed:** `docs/design/2026-10-18-comprehensive-plan.md` (moved from the root, banner added), `README.md`, `docs/README.md`, `docs/adrs/ADR-001-interfaces-and-backend.md`, `docs/superpowers/plans/2026-10-18-sentinelssh-v0.1-observer.md`, `CHANGELOG.md`, `AGENT.md`.
- **Verification:** `git grep` finds no remaining link to the old path except the historical file tree in the v0.1 plan; the CI quick gate on the pull request. No code changed.
- **Follow-ups:** none.

### Raouf: 2026-11-17 (Australia/Sydney) — Apache-2.0 licence and a CI quick gate

- **Scope:** licence, CI, docs.
- **Summary:** The repository had no licence (`Cargo.toml` said `UNLICENSED` and the README reserved all rights) and no CI. It is now released under the Apache License 2.0: `LICENSE` holds the canonical text, the workspace manifest declares `Apache-2.0`, and the README and CONTRIBUTING say so. A GitHub Actions workflow runs the quick gate (`bash scripts/check.sh --quick`) on every push to `main` and every pull request. A developer-machine path was removed from the v0.1 plan document.
- **Files changed:** `LICENSE` (new), `.github/workflows/ci.yml` (new), `Cargo.toml`, `README.md`, `CONTRIBUTING.md`, `docs/superpowers/plans/2026-10-18-sentinelssh-v0.1-observer.md`, `AGENT.md`, `CHANGELOG.md`.
- **Verification:** the new workflow's quick gate on the pull request. No product code changed, so the full gate was not re-run; its last pass is the 2026-11-05 entry.
- **Follow-ups:** CI runs the quick gate only. Running the full gate there needs the Docker sshd fixture and `cargo-llvm-cov` on the runner.

### Raouf: 2026-11-05 (Australia/Sydney) — root reach via sudo elevation, gate repair, audit

- **Scope:** gateway (config, OpenSSH backend, doctor, process list, error mapping), quality gate, docs.
- **Summary:** A full audit found the root problem. Hosts that forbid root login but give the account passwordless sudo could only be inspected with that account's rights: root-only files were permission-denied and `disk_usage` was always `partial`. Added the per-host `elevation = "sudo"` (`exec sudo -n -- timeout -k 5 N sh -c '…'`). `doctor --connect` proves uid 0, a sudo refusal is `AUTHENTICATION_FAILED`, and the sudo wrappers are hidden. The audit also found that the `check.sh` flag-literal scan had never run (`find -exec` replaced the `{}` in its awk regex), and fixed it.
- **Files changed:** `crates/sentinel-gateway/src/{config.rs, ssh/backend.rs, ssh/mod.rs, ssh/openssh.rs, tools/pipeline.rs, tools/processes.rs}`, tests `config.rs`, `doctor.rs`, `openssh_argv.rs`, `tools_host_level.rs`, `scripts/check.sh`, `docs/configuration.md`, `docs/operations.md`, `CHANGELOG.md`, `AGENT.md` (new).
- **Verification:** `bash scripts/check.sh` full gate passed: fmt, clippy, unsafe, secrets, contracts, Docker fixture e2e and red-team suites, 100% product line coverage (3834/3834). `cargo audit`: no advisories. Live: `doctor --connect` passed on every configured host, and uid 0 was proved on the three sudo-elevated hosts. A 32-case live tool matrix passed: root reads, the observer stays denied, and traversal, unregistered roots, symlinks, unknown ids, non-export downloads and regex are all refused. Fresh Claude Code and Codex sessions both answered a server question through Sentinel alone.
- **Follow-ups:** merge PR #1. Consider a narrow sudoers rule limited to the gateway's programs instead of blanket NOPASSWD. The process list still shows the root `systemd --user` manager and parallel-connection `sshd` sessions (cosmetic).

### Security

- **Containment redesign.** File-level tools pin their targets on the host instead of checking a path and then using it. Directories are entered with `cd -P`; files are opened once on a descriptor whose real path, type and link count are checked, and only that descriptor is read. This closes symlink-swap races between check and read.
- Hard-linked files (more than one link) are refused for reads, hashes and downloads. The descriptor's path is re-checked after its link count, so unlinking an in-root hard link to a secret mid-check cannot slip past. Each check uses the raw `readlink` text, so a symlink named `<x> (deleted)` cannot hide the suffix, and binds the path to the descriptor's own inode.
- Log sources must resolve to exactly their configured path and have a single link.
- A `read = false` root nested in a readable one is skipped by listings, refused for disk usage over its parent, and refused for stat. Unreadable roots answer as unknown roots.
- A root or excluded root resolving to `/` can no longer fail open, and `/` cannot be registered as a root.
- Every remote command runs under `timeout` on the host as well as locally.
- Capability errors are recognised only in exact shell and GNU formats, for programs the command ran, so remote file names cannot spoof them.
- Wider process-argument redaction: `curl -u`, `sshpass -p`, `openssl -k`, JWTs, GitHub and Slack tokens, signed-URL parameters, cookie and token headers, URL passwords containing `/` or `@`, and underscore-joined lower-case names.
- Every remote string in host, service, disk and stat results is display-escaped and labelled untrusted. The escape set covers every default-ignorable code point.
- The process list hides the gateway's own shell, `timeout` wrapper and session.
- Known_hosts files and connection sockets are keyed by each host's full trust identity, and the runtime directory is re-checked before every spawn.
- A per-principal artefact quota (`max_artifact_bytes`), reserved atomically for the length of a transfer.
- Health-check URLs may not embed credentials, and results withhold URL queries and fragments.
- Trust checks judge symlink components by owner, cover a symlinked `ssh_binary`, and refuse relative paths.

### Added

- **Root reach without root login.** Per-host `elevation = "sudo"` runs every remote command as root through `sudo -n -- timeout … sh -c '…'`, for hosts where `PermitRootLogin no` is the rule but the account has passwordless sudo. The tools stay read-only and root-scoped. `doctor --connect` proves uid 0 (`host.<id>.elevation`). A sudo refusal is `AUTHENTICATION_FAILED` with a clear message instead of a misleading permission error. The process list hides the `sudo` wrappers. Refused for `user = "root"` and with `scope = "user"` services. Validated live on three NOPASSWD `deploy` hosts: `btmp` reads and full disk usage now succeed where they were permission-denied.
- `max_pending_per_host` budget (default 32).
- MCP `isError` on failed, cancelled and outcome-unknown results.
- Client cancellation (`notifications/cancelled`) and batch cancellation reach the operations they started.
- A 1 MiB limit on each stdin request line.
- A 4096-record cap on the operation registry.
- Directory listings are sorted on the host, so a truncated listing is a true prefix of the cursor's order.
- `scripts/check.sh` quality gate: fmt, clippy, `forbid(unsafe_code)`, secret and flag-literal scans, tool-contract freshness, and 100% line coverage of product code.
- An end-to-end red-team suite against the Docker fixture, including a live swap-race attacker.
- Full documentation set under `docs/`, plus `SECURITY.md` and `CONTRIBUTING.md`.
- Operations guide: onboarding a host safely (key pinning, per-host `restrict` keys, the `AllowUsers` drop-in with a held-session reload) and the trade-offs of running as root.
- Validated against six live hosts, in observer mode and in root mode: `doctor --connect` and live read-only and refusal calls passed on all of them.

### Changed

- `scripts/check.sh`: the flag-literal scan never ran. `find -exec` replaced the `{}` inside its awk regex with a file name, awk failed, and the gate passed on empty output. The program now goes through a variable, and an awk failure fails the gate.
- Every budget is range-checked at load.
- Relative paths are limited to 4096 bytes, and 255 bytes per component.
- Local tools take a scheduler slot (operation get and cancel excepted).
- Failure envelopes clip echoed messages and details.
- A disk usage that skipped unreadable subtrees is reported as `partial`.

### Fixed

- A result that failed to spill to an artefact now keeps its real operation id.
- A dropped artefact writer removes its partial file.

## [0.1.0] - 2026-10-18

First development release: observer mode.

### Added

- `sentinel-ssh` stdio MCP server supporting protocol versions `2026-07-28` and `2025-11-25`.
- 17 typed read-only tools: hosts list, capabilities, host inspect, health check, disk usage, process list, service status, logs search, files list, file read, file stat, file hash, transfer download, artefact read, batch inspect, operation get, operation cancel.
- Deny-by-default policy over registered roots, services, log sources and health checks, with separate read and export permissions.
- OpenSSH backend with pinned host keys, `-F /dev/null`, an explicit option set, effective-config verification and connection reuse.
- SHA-256-verified downloads into private artefacts; bounded results that spill to artefacts.
- `doctor`, `config lint` and `schemas` commands.
- A Docker sshd fixture and an end-to-end enforcement suite.

[Unreleased]: https://github.com/Raoof128/sentinel-ssh/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Raoof128/sentinel-ssh/releases/tag/v0.1.0
