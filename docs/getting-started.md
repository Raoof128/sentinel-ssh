# Getting started

This guide takes you from a fresh checkout to an agent inspecting a host. It takes about fifteen minutes. Every command that touches the target host is marked, and none of the gateway's own commands change anything there.

- [1. Install the gateway](#1-install-the-gateway)
- [2. Prepare the target host](#2-prepare-the-target-host)
- [3. Pin the host key](#3-pin-the-host-key)
- [4. Write the configuration](#4-write-the-configuration)
- [5. Verify with the doctor](#5-verify-with-the-doctor)
- [6. Connect an MCP client](#6-connect-an-mcp-client)
- [7. First calls](#7-first-calls)

## 1. Install the gateway

Requirements on the machine that runs the gateway:

| Requirement | Version |
|---|---|
| Rust toolchain | 1.97.1, pinned by `rust-toolchain.toml` (rustup installs it automatically) |
| OpenSSH client | 8.9 or newer, at `/usr/bin/ssh` by default |
| Operating system | macOS or Linux; see [supported platforms](supported-platforms.md) |

Build and install the `sentinel-ssh` binary from the repository root:

```bash
cargo install --locked --path crates/sentinel-gateway
```

```bash
sentinel-ssh --version
```

## 2. Prepare the target host

*Run on the target host.*

The gateway's guarantees are about what the **agent** can ask for. The account itself can still do anything its permissions allow (see the [security model](security-model.md)), so give SentinelSSH an account of its own with as little access as possible.

1. Create the account with a POSIX login shell (`sh`, `dash`, `bash` or `zsh`; not `fish` or `csh`):
   ```bash
   sudo useradd -m -s /bin/sh sentinel-observer
   ```
2. Give it read access only to what you will register: application directories, log files, nothing else. Group membership (for example `adm` for `/var/log`) is usually enough.
3. Make sure the host has GNU coreutils, findutils, procps and grep, plus `curl` if you will register HTTP health checks. Standard Debian, Ubuntu, RHEL and Fedora installs have them.

*Run on the gateway machine.* Create a key used only for this account:

```bash
ssh-keygen -t ed25519 -N '' -f ~/.ssh/sentinel_observer_ed25519 -C sentinel-ssh
```

The key has no passphrase because the gateway runs `ssh` non-interactively (`BatchMode=yes`) and, with `identity_file` auth, without an agent. Protect it with file permissions (`0600`) and the `restrict` option below. To keep a passphrase, load the key into `ssh-agent` and use `auth = { method = "agent", public_key = "..." }` instead.

*Run on the target host.* Authorise it, restricted so that the key cannot open a terminal or forward anything even outside SentinelSSH:

```bash
sudo install -d -m 700 -o sentinel-observer -g sentinel-observer ~sentinel-observer/.ssh
```

```bash
echo 'restrict ssh-ed25519 AAAA...your-public-key... sentinel-ssh' | sudo tee -a ~sentinel-observer/.ssh/authorized_keys
```

```bash
sudo chown sentinel-observer: ~sentinel-observer/.ssh/authorized_keys && sudo chmod 600 ~sentinel-observer/.ssh/authorized_keys
```

`restrict` disables PTY allocation, agent, X11 and port forwarding for this key. SentinelSSH needs none of them. You can add `from="<gateway address>"` to limit where the key is accepted from.

## 3. Pin the host key

SentinelSSH never trusts a host key on first use. You give it the key, and any other key stops every call with `HOST_KEY_CHANGED`.

Get the key **through a channel you already trust**: the provider's console, a serial or KVM session, or a configuration-management record. Do not use `ssh-keyscan` over the network you are about to trust.

*Run on the target host:*

```bash
cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub
```

The result looks like `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...`: the key type and the base64 body, with no hostname and no comment. Supported types are `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521` and `ssh-rsa`.

## 4. Write the configuration

The default location is `$XDG_CONFIG_HOME/sentinel-ssh/config.toml`, or `~/.config/sentinel-ssh/config.toml` when `XDG_CONFIG_HOME` is unset. `serve`, `doctor` and `config lint` accept `--config <path>` to use another file.

```toml
schema_version = 1

[gateway]
# Defaults: artifact_dir = "~/.local/share/sentinel-ssh/artifacts",
#           runtime_dir  = "~/.local/state/sentinel-ssh/run",
#           ssh_binary   = "/usr/bin/ssh"

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

# Directories the agent may name. `read` allows listing and reading;
# `export` additionally allows downloads.
[hosts.roots.app]
path = "/srv/app"
read = true
export = true

[hosts.roots.logs]
path = "/var/log/app"
read = true

# systemd units the agent may inspect, by id.
[hosts.services.api]
unit = "app-api.service"
scope = "system"

# Individual log files the agent may search, by id.
[hosts.log_sources.api]
path = "/var/log/app/api.log"

# Checks the agent may run, by id. The URL is fetched from the host itself.
[hosts.health_checks.api_http]
kind = "http"
url = "http://127.0.0.1:8080/health"
expect_status = 200
timeout_secs = 5

[hosts.health_checks.api_active]
kind = "service_active"
service = "api"
```

The file must be owned by you with no group or other permission bits:

```bash
chmod 600 ~/.config/sentinel-ssh/config.toml
```

Check it without connecting anywhere:

```bash
sentinel-ssh config lint
```

The [configuration reference](configuration.md) explains every field and every validation rule.

## 5. Verify with the doctor

```bash
sentinel-ssh doctor --connect
```

Without `--connect`, the doctor checks local inputs only. With it, it also connects to each host and runs `true`, which proves the key pin, authentication and shell. Example output:

```text
[ok] config.permissions: owner-only (0600) and owned by the current user
[ok] config.load: 1 host(s)
[ok] ssh.binary: OpenSSH_9.9p2, LibreSSL 3.3.6
[ok] dirs.artifact: /Users/me/.local/share/sentinel-ssh/artifacts (0700, owned by the current user)
[ok] dirs.runtime: /Users/me/.local/state/sentinel-ssh/run (0700, owned by the current user)
[ok] host.staging-api-1.identity: /Users/me/.ssh/sentinel_observer_ed25519
[ok] host.staging-api-1.controlpath_length: 56 of 86 bytes
[ok] host.staging-api-1.connect: connected in 412 ms
```

The doctor exits non-zero if any check fails. Each failure names its cause; see [troubleshooting](operations.md#troubleshooting) for the common ones.

## 6. Connect an MCP client

SentinelSSH is a stdio server: the client starts `sentinel-ssh serve` and talks to it over stdin and stdout.

**Claude Code:**

```bash
claude mcp add sentinel-ssh -- sentinel-ssh serve
```

Add `--scope user` to make it available in every project. Confirm it with `claude mcp get sentinel-ssh`, which should report `Connected`.

**OpenAI Codex CLI:**

```bash
codex mcp add sentinel-ssh -- sentinel-ssh serve
```

This adds an `[mcp_servers.sentinel-ssh]` entry to `~/.codex/config.toml`. Check it with `codex mcp get sentinel-ssh`.

If your client is launched from a desktop app rather than a shell, it may not have `~/.cargo/bin` on its `PATH`. Use the absolute path to the binary instead (find it with `command -v sentinel-ssh`).

**Any client that takes a JSON server definition:**

```json
{
  "mcpServers": {
    "sentinel-ssh": {
      "command": "sentinel-ssh",
      "args": ["serve", "--config", "/Users/me/.config/sentinel-ssh/config.toml"]
    }
  }
}
```

Logs go to stderr. Set `SENTINEL_LOG` (for example `SENTINEL_LOG=sentinel_gateway=debug`) to change the level; see [operations](operations.md#logging).

## 7. First calls

The server's instructions tell the agent to start with `ssh_hosts_list`. A typical sequence:

1. `ssh_hosts_list`: learn host ids and their registered roots, services, log sources and health checks.
2. `ssh_host_inspect` with `{"host_id": "staging-api-1"}`: kernel, CPUs, load, memory, uptime.
3. `ssh_logs_search` with `{"host_id": "staging-api-1", "source_id": "api", "pattern": "ERROR", "last_bytes": 1048576}`: recent errors.
4. `ssh_files_list` with `{"host_id": "staging-api-1", "root": "app", "path": "config"}`, then `ssh_file_read` on what it finds.
5. `ssh_transfer_download` with `{"host_id": "staging-api-1", "root": "app", "path": "data/dump.json"}`: an artefact handle, then `ssh_artifact_read` by range.

Every result has the same envelope shape; [results and errors](results-and-errors.md) explains how to read it.
