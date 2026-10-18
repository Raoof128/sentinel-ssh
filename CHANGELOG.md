# Changelog

All notable changes to SentinelSSH are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

Red-team hardening of observer mode. Everything below is on `main` but is not part of the `v0.1.0` tag.

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

- `max_pending_per_host` budget (default 32).
- MCP `isError` on failed, cancelled and outcome-unknown results.
- Client cancellation (`notifications/cancelled`) and batch cancellation reach the operations they started.
- A 1 MiB limit on each stdin request line.
- A 4096-record cap on the operation registry.
- Directory listings are sorted on the host, so a truncated listing is a true prefix of the cursor's order.
- `scripts/check.sh` quality gate: fmt, clippy, `forbid(unsafe_code)`, secret and flag-literal scans, tool-contract freshness, and 100% line coverage of product code.
- An end-to-end red-team suite against the Docker fixture, including a live swap-race attacker.
- Full documentation set under `docs/`, plus `SECURITY.md` and `CONTRIBUTING.md`.

### Changed

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
