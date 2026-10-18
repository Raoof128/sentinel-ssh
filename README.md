# SentinelSSH

**Policy-scoped SSH inspection for AI agents, over the Model Context Protocol.**

SentinelSSH is a local MCP server that lets an AI agent inspect Linux hosts you register, through 17 typed, read-only tools, without ever handing it a shell. It speaks MCP on stdio and reaches the hosts with your system's native OpenSSH client.

```text
 AI agent ──MCP (stdio)──▶ sentinel-ssh ──OpenSSH──▶ registered Linux hosts
                           │ policy, scope, budgets,
                           │ host-key pinning, artefacts
```

> **The gateway enforces the tool interface. The SSH account may permit more; it is not a remote sandbox.**
> v0.1 is *observer mode*: every guarantee lives in the gateway, not on the host. Use a dedicated, low-privilege account. See the [security model](docs/security-model.md).

## Why

Giving an agent `ssh host 'any command'` gives it everything the account can do, and puts every byte it reads into model context. SentinelSSH takes the opposite approach:

- **No raw shell.** No tool runs an arbitrary command. Each tool builds its own fixed remote command, with every value shell-quoted.
- **Names, not paths.** An agent addresses a registered *root alias* plus a relative path (`root: "app", path: "logs/api.log"`). Services, log sources and health checks are configuration ids, never unit names, file paths or URLs.
- **Deny by default.** Every call is authorised against the configuration before anything reaches the host. Downloads need `export = true` on the root.
- **Bytes stay out of context.** Downloads become SHA-256-verified, owner-only *artefacts*, which the agent reads by handle and range. Results are bounded, and anything larger moves to an artefact.
- **Typed outcomes.** Every result is an envelope with an `operation_id`, an `outcome` and either `data` or a typed `error` that says how to retry.

## Features

| Area | What v0.1 provides |
|---|---|
| Inspection | Host facts, disk usage, process list (with credential redaction), systemd service state, registered HTTP or service health checks |
| Files | Directory listing with paging, ranged reads (UTF-8 or base64), stat, SHA-256 |
| Logs | Fixed-string search of registered log sources, optionally over the last N bytes only |
| Transfer | Download to a verified local artefact; ranged artefact reads |
| Control | Operation lookup and cancellation, batches of up to 16 reads, a capabilities self-description |
| SSH | Pinned host keys, `-F /dev/null`, an explicit option set, effective-config verification, connection reuse |
| Containment | Targets pinned on the host by `realpath` and an open descriptor; symlinks, special files and hard links refused; `..` never accepted |
| Limits | Result, transfer, queue, concurrency, timeout and input-size budgets, all range-checked |
| Protocol | MCP `2026-07-28` (`server/discover`) and `2025-11-25` (`initialize`) |

The full list is in the [tool reference](docs/tools.md).

## Quick start

You need Rust 1.97 (pinned by `rust-toolchain.toml`), OpenSSH 8.9 or newer on the gateway machine, and a Linux host with GNU userland.

```bash
cargo install --locked --path crates/sentinel-gateway
```

1. On the host, create a dedicated account and give it a key used only by SentinelSSH:
   ```bash
   sudo useradd -m -s /bin/sh sentinel-observer
   ```
2. Fetch the host key **through a channel you trust** (the console or your provider's dashboard, not the network you are about to trust):
   ```bash
   cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub
   ```
3. Write `~/.config/sentinel-ssh/config.toml` with mode `0600`:
   ```toml
   schema_version = 1

   [gateway]

   [principal]
   id = "me"
   role = "observer"

   [[hosts]]
   id = "staging-api-1"
   environment = "staging"
   address = "203.0.113.10"
   user = "sentinel-observer"
   host_key = "ssh-ed25519 AAAA..."
   auth = { method = "identity_file", path = "~/.ssh/sentinel_observer_ed25519" }

   [hosts.roots.app]
   path = "/srv/app"
   read = true
   export = true

   [hosts.log_sources.api]
   path = "/var/log/app/api.log"
   ```
4. Check the setup. This never changes anything on the host:
   ```bash
   sentinel-ssh doctor --connect
   ```
5. Register the server with your MCP client, for example Claude Code:
   ```bash
   claude mcp add sentinel-ssh -- sentinel-ssh serve
   ```

The [getting-started guide](docs/getting-started.md) walks through each step, and the [configuration reference](docs/configuration.md) covers every field.

## Documentation

| Document | Contents |
|---|---|
| [Getting started](docs/getting-started.md) | Install, prepare a host, configure, verify, connect a client |
| [Configuration reference](docs/configuration.md) | Every field, default, range and validation rule |
| [Tool reference](docs/tools.md) | The 17 tools, their parameters, results and refusals |
| [Results and errors](docs/results-and-errors.md) | Envelopes, outcomes, error codes, retry strategies, operations |
| [Security model](docs/security-model.md) | Threat model, guarantees, limits, containment design |
| [Architecture](docs/architecture.md) | Crates, the request pipeline, the SSH backend, the remote prologue |
| [Operations](docs/operations.md) | Running, logging, artefacts, troubleshooting |
| [Development](docs/development.md) | Building, the quality gate, the test fixture |
| [Supported platforms](docs/supported-platforms.md) | Gateway and target-host requirements |
| [Tool contracts](docs/tool-contracts.md) | Generated JSON Schemas for every tool |
| [ADR-001](docs/adrs/ADR-001-interfaces-and-backend.md) | Interface and backend decisions |
| [Design spec](SentinelSSH_Comprehensive_Plan_2026-10-18.md) | The full product vision this release implements part of |

## Project status

v0.1 is a **development release**, not a supported product. It implements the spec's observer mode. Later stages are not built yet: a protected host-side broker, approvals and changes, uploads, signed releases and an independent security review. See the [changelog](CHANGELOG.md).

Security issues: [SECURITY.md](SECURITY.md). Contributions: [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

No licence has been chosen yet. Until one is, all rights are reserved: you may read the code, but you have no right to use, modify or redistribute it.
