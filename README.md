# SentinelSSH

Policy-scoped SSH inspection for AI agents, over MCP.

**v0.1 is observer mode:** a local stdio MCP server that gives an agent 17 typed, read-only tools over native OpenSSH to Linux hosts you register. There is no raw shell tool. Paths are always a registered root alias plus a relative path; services, log sources and health checks are configuration ids. File bytes never enter model context: downloads become SHA-256-verified artefacts the agent reads by handle.

Design spec: [`SentinelSSH_Comprehensive_Plan_2026-10-18.md`](SentinelSSH_Comprehensive_Plan_2026-10-18.md). Tool contracts: [`docs/tool-contracts.md`](docs/tool-contracts.md) (generated). Decisions: [`docs/adrs/ADR-001-interfaces-and-backend.md`](docs/adrs/ADR-001-interfaces-and-backend.md).

## Guarantees and limits

> The gateway enforces the tool interface. The SSH account may permit more; it is not a remote sandbox.

What v0.1 does enforce, and tests:

- Host keys are pinned per host. An unknown or changed key stops dispatch (`HOST_KEY_CHANGED`, retry `never`).
- The SSH client runs with `-F /dev/null` and an explicit option set: no agent, X11 or port forwarding, no proxy or local commands, no TTY. Before the first dispatch to each host, `ssh -G` confirms the effective configuration. If the configured identity file is missing the gateway refuses, because OpenSSH would otherwise fall back to your default `~/.ssh` keys.
- Every call is checked against deny-by-default policy before anything reaches the host. Exports (downloads) need `export = true` on the root.
- `..`, absolute paths, empty components and control characters are rejected. On the host, the root and the target's parent directory are resolved with `realpath`, and the call is refused unless the target stays inside the registered root, so a symlinked directory cannot lead outside it. A target that is itself a symlink or special file is refused by a remote type guard.
- Results are bounded (8 KiB by default, 64 KiB with `detail: "full"`). Larger results move to a private artefact.
- Remote text is labelled `content_trust: "untrusted"`. Control and bidirectional characters are escaped, and best-effort redaction removes credentials from process arguments.

What v0.1 does **not** do:

- **No remote enforcement.** Anyone holding the observer account's key can run anything that account may run. Use a dedicated, low-privilege account. The Stage 2 broker adds host-side enforcement.
- **Check and use are separate commands.** Containment is checked on the host immediately before the read, but a concurrent rename on the host between the two can still race them. The Stage 2 broker closes this with descriptor-relative opens.
- **Roots should be real directories.** A root whose own path is a symlink resolves for containment, but listing the root itself is refused as "not a directory".
- **Cancellation is not confirmed remotely.** Cancelling signals the local `ssh` process; `remote_termination` stays `unconfirmed`.
- **No changes.** Plan, approve, apply and upload come in v0.2. Every `Change`, `Stage` and `Plan` effect is denied.
- **ControlMaster.** The client keeps an authenticated connection open for 60 s after the last call. The socket lives in the gateway's private runtime directory and its name is a digest of the host's trust identity (host id, address, user, pinned key, credential).
- **System SSH configuration is trusted.** `/etc/ssh/ssh_config` and its `Include`s still apply. `doctor` verifies they are root-owned and flags `ProxyCommand`, `LocalCommand` and `Match exec`.

## Quickstart

1. On the target host, create a dedicated account with a POSIX login shell (`sh`, `bash` or `dash`), plus a key used only by SentinelSSH:
   ```bash
   sudo useradd -m -s /bin/sh sentinel-observer
   ```
   Add the public half of a new key to `~sentinel-observer/.ssh/authorized_keys`. Give the account read access only to what you will register.
2. Get the host key **through a channel you trust** (the console, your cloud provider's dashboard, or `ssh-keygen -lf` run on the host), not just from the network:
   ```bash
   cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub
   ```
3. Write `~/.config/sentinel-ssh/config.toml` and make it owner-only (`chmod 600`):
   ```toml
   schema_version = 1

   [gateway]
   # artifact_dir, runtime_dir and ssh_binary have sensible defaults

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

   [hosts.services.api]
   unit = "app-api.service"
   scope = "system"

   [hosts.log_sources.api]
   path = "/var/log/app/api.log"

   [hosts.health_checks.api_http]
   kind = "http"
   url = "http://127.0.0.1:8080/health"
   expect_status = 200
   timeout_secs = 5
   ```
4. Check the setup. This never changes anything on the host:
   ```bash
   sentinel-ssh doctor --connect
   ```
5. Register it as a stdio MCP server in your client, for example Claude Code:
   ```bash
   claude mcp add sentinel-ssh -- sentinel-ssh serve
   ```

## Tools

`ssh_hosts_list`, `ssh_host_inspect`, `ssh_health_check`, `ssh_disk_usage`, `ssh_process_list`, `ssh_service_status`, `ssh_logs_search`, `ssh_files_list`, `ssh_file_read`, `ssh_file_stat`, `ssh_file_hash`, `ssh_batch_inspect`, `ssh_operation_get`, `ssh_operation_cancel`, `ssh_artifact_read`, `ssh_capabilities_get`, `ssh_transfer_download`.

Each result is an envelope with `schema_version`, `operation_id` and `outcome`, plus either `data` or a typed `error` with a `retry` strategy. Only malformed calls are JSON-RPC errors. Both MCP `2026-07-28` (`server/discover`, per-request `_meta`) and `2025-11-25` (`initialize`) are supported.

## Target host requirements

Linux with GNU coreutils, findutils, procps and grep, plus `curl` for HTTP health checks. systemd is optional; without it, service tools return `CAPABILITY_UNSUPPORTED`. The account's login shell must be POSIX `sh` compatible. See [`docs/supported-platforms.md`](docs/supported-platforms.md).

## Development

```bash
cargo test --workspace
```

End-to-end tests run against a disposable Docker sshd with synthetic data (Docker must be running):

```bash
bash scripts/fixture-up.sh
```

```bash
set -a && . target/fixture/fixture.env && set +a && cargo test --workspace
```

Add `LARGE=1` to `fixture-up.sh` and `-- --include-ignored` to the test run for the 256 MiB download test. Run `bash scripts/fixture-down.sh` to remove the fixture. Never point the tests at a live host.

Regenerate the tool contracts after a schema change with `bash scripts/gen-tool-contracts.sh`.

## Status

v0.1.0 is a development release, not a supported product. The spec's Stage 2 (protected broker, approvals, upload) through Stage 5 (signed releases, independent security review) are not built yet. Licence: not yet chosen; all rights reserved.
