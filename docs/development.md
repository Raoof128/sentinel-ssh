# Development

How to build, test and change SentinelSSH. See [CONTRIBUTING.md](../CONTRIBUTING.md) for the review rules, and the [architecture](architecture.md) for how the pieces fit.

- [Prerequisites](#prerequisites)
- [Build](#build)
- [The quality gate](#the-quality-gate)
- [Tests](#tests)
- [The Docker sshd fixture](#the-docker-sshd-fixture)
- [Tool contracts](#tool-contracts)
- [Conventions](#conventions)

## Prerequisites

| Tool | Why |
|---|---|
| Rust 1.97.1 | Pinned by `rust-toolchain.toml`, with `rustfmt` and `clippy` |
| OpenSSH client 8.9+ | The backend and its tests use the real `ssh` |
| Docker | End-to-end tests and the full gate |
| `cargo-llvm-cov` 0.9 and `llvm-tools-preview` | Line coverage in the full gate |

```bash
cargo install cargo-llvm-cov --locked
```

```bash
rustup component add llvm-tools-preview
```

## Build

```bash
cargo build --workspace
```

```bash
cargo run -p sentinel-gateway --bin sentinel-ssh -- --help
```

## The quality gate

`scripts/check.sh` runs every check and stops at the first failure. Run it before every commit.

```bash
bash scripts/check.sh
```

| Step | Fails when |
|---|---|
| Format | `cargo fmt --check` finds a difference |
| Lints | `cargo clippy --all-targets -D warnings` warns |
| Unsafe | A crate lacks `#![forbid(unsafe_code)]`, or any `unsafe` block appears |
| Secret scan | A tracked file contains a private-key header or an AWS, GitHub, Slack or OpenAI key shape, or a key file is tracked |
| Flag literals | A remote `.flag("...")` in production code contains a shell metacharacter |
| Tool contracts | `docs/tool-contracts.md` is not regenerated and committed |
| Fixture | Docker is not available, or the sshd fixture does not start |
| Tests and coverage | Any test fails, or **any product source line** (outside `sentinel-testkit`) is not executed at least once |

Modes:

- `--quick` runs the static steps and the unit and contract tests: no Docker, no coverage. Use it as the fast inner loop.
- `--large` runs the full gate plus the 256 MiB download test.

The coverage requirement is strict on purpose: a line no test executes is a line no test checks. Lines are counted after merging generic instantiations (from the lcov report), and an uncovered line is listed by file and number. When a line cannot be reached, remove it rather than exempting it.

## Tests

```bash
cargo test --workspace
```

Without the fixture, end-to-end tests print `skipped: no ssh fixture` and pass, so this works anywhere.

| Suite | Covers |
|---|---|
| `sentinel-core/tests/*` | Identifiers, error contract, envelope, operation state machine (property tests), policy, path scoping and escaping (property tests) |
| `config`, `doctor`, `cli` | Loading, every validation rule, trust checks, doctor output, the CLI |
| `openssh_argv` | The exact `ssh` argv (snapshot), known_hosts and ControlPath identity, effective-config verification, timeouts, process-group kills |
| `scheduler`, `artifacts` | Slots, queues, cancellation while queued, the artefact store and its failure paths (injected sink faults) |
| `tools_*`, `hardening`, `mcp_hardening` | Each tool against a scripted fake backend that asserts on the exact remote command text; red-team regressions |
| `server`, `protocol` | The MCP server in-process and as a child process speaking JSON-RPC: both protocol versions, the catalogue snapshot, `isError`, input limits |
| `e2e_fixture`, `e2e_containment` | The real OpenSSH backend against the Docker sshd, including the planted attacks |

Snapshots use `insta`. After an intended schema or argv change, review the diff, then accept it:

```bash
INSTA_UPDATE=always cargo test -p sentinel-gateway --test protocol
```

## The Docker sshd fixture

A disposable Debian sshd on `127.0.0.1:2222`, seeded with **synthetic data only** by `crates/sentinel-testkit/docker/seed.sh`. It is never a real host.

```bash
bash scripts/fixture-up.sh
```

```bash
set -a && . target/fixture/fixture.env && set +a && cargo test --workspace
```

```bash
bash scripts/fixture-down.sh
```

`fixture-up.sh` generates a throwaway client key and a deliberately wrong host key under `target/fixture/`. It reads the real host key through `docker exec`, a trusted local channel, and writes the `SENTINEL_TEST_*` variables to `target/fixture/fixture.env`. Build with `LARGE=1 bash scripts/fixture-up.sh` for the 256 MiB file, and add `-- --include-ignored` to run its test.

The seed plants these attacks, each with a test that must refuse it:
- a hard link and a symlinked log source pointing at a fake secret;
- a sibling directory named `/srv/app` plus a newline;
- a backslash in a file name, and names that are not UTF-8;
- a FIFO, and a file a live attacker swaps during reads;
- a root-only directory and file;
- a `read = false` root nested inside a readable one;
- a log line that tries to instruct the agent.

Never point the tests at a live host.

## Tool contracts

`docs/tool-contracts.md` is generated from the code and checked by the gate:

```bash
bash scripts/gen-tool-contracts.sh
```

Commit the result with any change to a tool's parameters, results or description.

## Conventions

- **Test first.** A change starts with a test that fails for the right reason. A bug fix starts with a test that reproduces the bug.
- **Remote commands only through `RemoteCommand`.** Never format a shell string. Add programs to the allowlist deliberately, and keep flag literals free of metacharacters.
- **Fixed error text.** Never put raw remote output, absolute paths or account names into an error message; log them instead.
- **Escape remote text** with `display_escape` and mark results that carry it with `content_trust: "untrusted"`.
- **Operator-tunable limits are budgets** with a default and a checked range in `Budgets::validate`. Hard safety limits (request line, registry size) are constants.
- **No `unsafe`, no new dependencies without need.** The workspace forbids unsafe code.
- **Commits** are small, with plain subjects (`fix: ...`, `test: ...`, `docs: ...`).
