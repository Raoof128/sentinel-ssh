# AGENT.md

> **AI-assistant working document.** The rules below are instructions to coding assistants, and the log is the record they keep. For people, [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/development.md](docs/development.md) are the guides.

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
- **Build lean when disk is short:** `CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0`. Delete nothing outside `target/` without asking.

## Log

Newest first. Each entry uses the `Raouf:` template.

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
