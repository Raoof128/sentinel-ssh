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

### Raouf: 2026-11-17c (Australia/Sydney) — limits of root and sudo modes; full gate in CI

- **Scope:** docs, CI.
- **Summary:** The operations guide suggested a "narrower" sudoers rule for `elevation = "sudo"`. None can exist for this design: the gateway's commands run as `sudo -n -- timeout ... sh -c '<command>'`, so any rule that lets them through permits arbitrary root commands for whoever holds the key. The sentence is replaced, and the security model lists root and sudo modes under its limits, including that the process list then returns root's process arguments. The README gains a Testing section (what the quick gate covers, that the end-to-end and red-team suites skip without a fixture, what line coverage does and does not show) and the Quick start says it needs a clone and points at the key-setup steps. CI gains a second job that runs the full gate. This supersedes the 2026-11-05 follow-up that suggested a narrow sudoers rule.
- **Files changed:** `docs/operations.md`, `docs/security-model.md`, `README.md`, `.github/workflows/ci.yml`, `docs/superpowers/plans/2026-10-18-sentinelssh-v0.1-observer.md`, `AGENT.md`, `CHANGELOG.md`.
- **Verification:** on pull request #4 both CI jobs passed, including the first run of the full gate on a hosted runner: Docker sshd fixture, end-to-end and red-team suites, 100% product line coverage. No product code changed.
- **Follow-ups:** add a test that scans every rendered remote command for write-capable flags (`find -delete`, `-exec`, a non-null `curl -o`); the program allowlist is by name only.

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
