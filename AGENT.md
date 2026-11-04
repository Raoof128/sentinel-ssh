# AGENT.md

Rules for any coding agent (Claude Code, Codex, others) working in this repo. Read this and `CHANGELOG.md` before changing anything. `CONTRIBUTING.md` and `docs/development.md` are the long form.

## Constraints

- **Observer mode is read-only.** Never add a way to write, delete, restart or run arbitrary commands on a host.
- **Remote commands only through `RemoteCommand`** (`crates/sentinel-gateway/src/ssh/command.rs`): allowlisted programs, quoted values, metacharacter-free flag literals. The only wrapper around them is `build_argv` in `ssh/openssh.rs` (`timeout`, and `sudo -n` when `elevation = "sudo"`).
- **Policy before I/O. Containment before reads:** file tools pin targets with the containment prologue, and there are no check-then-use races.
- **Remote text is untrusted:** escape it with `display_escape`, label it `content_trust: "untrusted"`, and keep it out of error messages, which use fixed text and log raw stderr locally.
- **Test first, then the full gate:** `bash scripts/check.sh` (Docker fixture, red-team e2e, 100% product line coverage). `--quick` is the inner loop only. Never point the tests at a live host.
- **Regenerate `docs/tool-contracts.md`** (`bash scripts/gen-tool-contracts.sh`) when a tool schema changes, and update the docs that describe changed behaviour.
- **The repository is public.** Never commit real host ids, addresses, users, keys or client names. The fixture uses synthetic data only.
- **No `unsafe`, and no new dependencies without need.** Commits are small, with `feat:` / `fix:` / `test:` / `docs:` subjects. Commit or push only when the owner asks.
- **Low disk on the dev Mac:** build lean (`CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0`). Delete nothing outside `target/` without asking.

## Log

Newest first. Each entry uses the `Raouf:` template.

### Raouf: 2026-11-05 (Australia/Sydney) — root reach via sudo elevation, gate repair, audit

- **Scope:** gateway (config, OpenSSH backend, doctor, process list, error mapping), quality gate, docs.
- **Summary:** A full audit found the root problem. Hosts that forbid root login but give the account passwordless sudo could only be inspected with that account's rights: root-only files were permission-denied and `disk_usage` was always `partial`. Added the per-host `elevation = "sudo"` (`exec sudo -n -- timeout -k 5 N sh -c '…'`). `doctor --connect` proves uid 0, a sudo refusal is `AUTHENTICATION_FAILED`, and the sudo wrappers are hidden. The audit also found that the `check.sh` flag-literal scan had never run (`find -exec` replaced the `{}` in its awk regex), and fixed it.
- **Files changed:** `crates/sentinel-gateway/src/{config.rs, ssh/backend.rs, ssh/mod.rs, ssh/openssh.rs, tools/pipeline.rs, tools/processes.rs}`, tests `config.rs`, `doctor.rs`, `openssh_argv.rs`, `tools_host_level.rs`, `scripts/check.sh`, `docs/configuration.md`, `docs/operations.md`, `CHANGELOG.md`, `AGENT.md` (new).
- **Verification:** `bash scripts/check.sh` full gate passed: fmt, clippy, unsafe, secrets, contracts, Docker fixture e2e and red-team suites, 100% product line coverage (3834/3834). `cargo audit`: no advisories. Live: `doctor --connect` passed on every configured host, and uid 0 was proved on the three sudo-elevated hosts. A 32-case live tool matrix passed: root reads, the observer stays denied, and traversal, unregistered roots, symlinks, unknown ids, non-export downloads and regex are all refused. Fresh Claude Code and Codex sessions both answered a server question through Sentinel alone.
- **Follow-ups:** merge PR #1. Consider a narrow sudoers rule limited to the gateway's programs instead of blanket NOPASSWD. The process list still shows the root `systemd --user` manager and parallel-connection `sshd` sessions (cosmetic).
