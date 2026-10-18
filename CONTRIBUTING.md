# Contributing

Thank you for helping. SentinelSSH guards access to real servers, so changes are held to a strict standard. This page explains it.

## Before you start

- For anything larger than a small fix, open an issue first to agree the approach.
- Report security problems privately: see [SECURITY.md](SECURITY.md).
- No licence has been chosen yet. Until one is, contributions cannot be accepted under clear terms. Please raise this in an issue before investing significant work.

## Workflow

1. Set up the toolchain and the test fixture: see [docs/development.md](docs/development.md).
2. **Write the test first.** A feature starts with a test that fails for the right reason, and a bug fix starts with one that reproduces the bug.
3. Make the smallest change that passes it.
4. Run the full gate and make sure it passes. It requires every product line to be covered:
   ```bash
   bash scripts/check.sh
   ```
5. Regenerate `docs/tool-contracts.md` if you changed a tool's schema or description, and update the other docs that describe the behaviour you changed.
6. Open a pull request that explains *why*, and what the change guarantees.

## What reviewers look for

- **No new way to run arbitrary commands.** Remote commands are built only with `RemoteCommand`, from allowlisted programs, with every runtime value quoted.
- **Policy before I/O.** Authorisation happens before anything reaches a host.
- **Containment preserved.** File-level tools pin their targets with the containment prologue, so no new check-then-use races.
- **Remote text is untrusted.** It is escaped, labelled `content_trust: "untrusted"`, and never placed in error messages.
- **Bounded.** New limits are budgets with defaults and checked ranges.
- **Honest documentation.** A guarantee is documented only if a test enforces it, and every new limit is documented too.

## Style

- `cargo fmt` and `cargo clippy -D warnings` clean; `#![forbid(unsafe_code)]` everywhere.
- Comments explain *why*, not what.
- Commit subjects are short and prefixed: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`.
