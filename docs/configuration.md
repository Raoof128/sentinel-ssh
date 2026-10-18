# Configuration reference

SentinelSSH reads one TOML file. Anything ambiguous is rejected at load time with `CONFIG_INVALID` and a message naming the field, so a configuration that loads is one the gateway fully understands. Unknown keys are rejected in every table.

- [File location and permissions](#file-location-and-permissions)
- [Top level](#top-level)
- [`[gateway]`](#gateway)
- [`[gateway.budgets]`](#gatewaybudgets)
- [`[principal]`](#principal)
- [`[[hosts]]`](#hosts)
- [`[hosts.roots.<alias>]`](#hostsrootsalias)
- [`[hosts.services.<id>]`](#hostsservicesid)
- [`[hosts.log_sources.<id>]`](#hostslog_sourcesid)
- [`[hosts.health_checks.<id>]`](#hostshealth_checksid)
- [Validating a configuration](#validating-a-configuration)

## File location and permissions

| Source | Path |
|---|---|
| `--config <path>` on `serve`, `doctor` or `config lint` | that path |
| `XDG_CONFIG_HOME` set | `$XDG_CONFIG_HOME/sentinel-ssh/config.toml` |
| otherwise | `~/.config/sentinel-ssh/config.toml` |

The file must be **owned by the current user** and have **no group or other permission bits** (mode `0600` or stricter). The same rule applies to identity files.

Paths in the gateway and auth settings may start with `~/`, which expands to your home directory. After expansion they must be absolute and must not contain `%`, because OpenSSH expands `%` tokens in paths, and the checked path would then differ from the one used.

## Top level

| Key | Type | Required | Notes |
|---|---|---|---|
| `schema_version` | integer | yes | Must be `1`. |
| `gateway` | table | yes | May be empty. |
| `principal` | table | yes | |
| `hosts` | array of tables | no | Host ids must be unique. |

## `[gateway]`

| Key | Default | Notes |
|---|---|---|
| `artifact_dir` | `~/.local/share/sentinel-ssh/artifacts` | Where downloads and spilled results live. |
| `runtime_dir` | `~/.local/state/sentinel-ssh/run` | Per-host `known_hosts` files and SSH connection sockets. |
| `ssh_binary` | `/usr/bin/ssh` | The OpenSSH client. It runs with your credential, so it must be trusted (see below). |

**Private directories.** `artifact_dir` and `runtime_dir` are created with mode `0700` if absent. They must then be real directories (not symlinks), owned by you, with no group or other bits.

**Trusted chains.** Every existing ancestor of these directories, and of `ssh_binary`, must be owned by root or by you. It must also not be writable by group or others, unless it is sticky like `/tmp`. Both the path as written and its fully resolved form are checked, and a symlink component is judged by its owner. Otherwise another account could swap a directory or the client out from under the gateway.

**`ssh_binary`** must be absolute and must resolve to a file owned by root or you that nobody else can write. If the configured path is itself a symlink (for example a package manager's `bin` link), that link must be owned by root or you too.

**ControlPath length.** Connection sockets live at `<runtime_dir>/c-<20 hex>`. Unix socket paths are short (103 bytes on macOS), and OpenSSH first binds a temporary name 17 bytes longer, so `runtime_dir` may be at most **63 bytes**. The doctor reports the margin as `controlpath_length`.

## `[gateway.budgets]`

Every budget is a bound somewhere: zero would wedge the gateway, and the upper limits keep a typo from switching a limit off. Values outside the range are rejected at load.

| Key | Default | Allowed range | What it bounds |
|---|---|---|---|
| `max_active_operations` | 64 | 1–4096 | Operations running at once, all hosts |
| `max_pending_operations` | 128 | 1–65536 | Operations waiting for a slot, all hosts |
| `max_pending_per_host` | 32 | 1–`max_pending_operations` | Waiters for one host |
| `per_host_reads` | 4 | 1–64 | Concurrent reads per host (downloads use a separate single slot per host) |
| `max_batch_items` | 16 | 1–64 | Items in one `ssh_batch_inspect` |
| `queue_wait_secs` | 5 | 1–300 | How long a call waits for a slot before `BUDGET_EXCEEDED` |
| `connect_timeout_secs` | 10 | 1–300 | SSH connection establishment |
| `read_timeout_secs` | 30 | 1–3600 | A whole read command, enforced locally and by `timeout` on the host |
| `default_result_bytes` | 8192 | 1024–`max_result_bytes` | Result size with `detail: "concise"` (the default) |
| `max_result_bytes` | 65536 | 1024–1048576 | Result size with `detail: "full"` |
| `transfer_chunk_bytes` | 65536 | 4096–16777216 | Reserved: validated, but downloads currently use a fixed 64 KiB buffer |
| `max_transfer_bytes` | 268435456 (256 MiB) | 1–2⁴⁰ | Largest file `ssh_transfer_download` or `ssh_file_hash` accepts |
| `transfer_idle_timeout_secs` | 30 | 1–3600 | A download with no bytes for this long fails |
| `transfer_total_timeout_secs` | 600 | 1–86400 | A whole download |
| `artifact_retention_hours` | 24 | 1–8760 | Artefacts expire after this |
| `max_artifact_bytes` | 1073741824 (1 GiB) | 1–2⁴² | Live artefact bytes per principal |

These defaults are the spec's initial design values (§11.3). They are not tuned; adjust them from measurements.

## `[principal]`

v0.1 serves one local principal over stdio.

| Key | Notes |
|---|---|
| `id` | 1–63 characters: lower-case letters, digits and `-`, starting with a letter or digit. Owns operations and artefacts. |
| `role` | `observer`, `operator` or `administrator`. In v0.1 every role is limited to observer mode: plan, stage and change effects are denied for all of them. |

## `[[hosts]]`

| Key | Required | Notes |
|---|---|---|
| `id` | yes | Unique. Same rule as the principal id. This is the only host identifier the agent ever sees. |
| `environment` | yes | Free text label returned by `ssh_hosts_list`, such as `staging`. |
| `address` | yes | Hostname or IP. Must not start with `-` or contain whitespace, `@` or `%` (each could change the meaning of the `ssh` command line). |
| `port` | no | Default `22`. |
| `user` | yes | The SSH account. Must not start with `-` or contain whitespace or `@`. |
| `host_key` | yes | `"<type> <base64>"`, exactly two fields. Types: `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, `ssh-rsa`. The algorithm name embedded in the key body must match the declared type. |
| `auth` | yes | See below. |
| `roots`, `services`, `log_sources`, `health_checks` | no | Tables keyed by alias or id. Anything not registered is unreachable. |

### `auth`

```toml
auth = { method = "identity_file", path = "~/.ssh/sentinel_observer_ed25519" }
```

The identity file must exist and be private (owned by you, no group or other bits). It is re-checked before every connection: if it were missing, OpenSSH would otherwise silently fall back to your default `~/.ssh` keys.

```toml
auth = { method = "agent" }
auth = { method = "agent", public_key = "~/.ssh/sentinel_observer_ed25519.pub" }
```

Agent authentication uses `SSH_AUTH_SOCK`. Without `public_key`, no on-disk key is offered. With `public_key`, only that one agent key is offered, even if the agent holds others.

## `[hosts.roots.<alias>]`

A root is a directory the agent may address by alias. Aliases are 1–64 characters: letters, digits, `_` and `-`.

| Key | Default | Notes |
|---|---|---|
| `path` | required | Absolute and normalised: no trailing slash, no `.` or `..` components, no control characters. `/` is refused; register the directories you mean. |
| `read` | `false` | Allows listing, reading, stat, hashing and disk usage. |
| `export` | `false` | Allows `ssh_transfer_download`. Requires `read = true`. |

Roots may nest. The more restrictive root wins inside its own subtree:

- A root with `read = false` inside a readable one is skipped by listings of the parent. `ssh_disk_usage` over a parent of it is refused. Every request that names it is answered "unknown root", exactly like an unregistered alias.
- A root with `export = false` inside an exportable one blocks downloads of its files through the parent alias. Reading them through either alias is still allowed.

A root whose own path is a symlink resolves correctly for containment, but listing the root itself is refused as "not a directory". Register real directories.

## `[hosts.services.<id>]`

| Key | Notes |
|---|---|
| `unit` | systemd unit name, 1–255 characters from letters, digits and `:_.@\-`. |
| `scope` | `system`, or `user` for `systemctl --user`. |

## `[hosts.log_sources.<id>]`

| Key | Notes |
|---|---|
| `path` | Absolute, normalised path to one file. On the host it must resolve to exactly this path and be a regular file with one link: a symlinked or hard-linked log source is refused. |

## `[hosts.health_checks.<id>]`

Two kinds:

```toml
[hosts.health_checks.api_http]
kind = "http"
url = "http://127.0.0.1:8080/health"
expect_status = 200
timeout_secs = 5
```

The URL is fetched **from the host** with `curl` (so `127.0.0.1` means the host's own loopback). It must be `http://` or `https://` without whitespace or control characters. It must not embed credentials (`user:password@`): they would travel in the remote command line and in results. `timeout_secs` is 1–60. Results return the URL with any query and fragment replaced by `?<redacted>`.

```toml
[hosts.health_checks.api_active]
kind = "service_active"
service = "api"
```

`service` must be an id registered under `[hosts.services]`. The check passes when the unit is `active`.

## Validating a configuration

```bash
sentinel-ssh config lint
```

`config lint` loads and validates the file without touching the network, and prints `ok: N host(s)` or the first error. `sentinel-ssh doctor` adds the checks on directories, identity files and the SSH client, and `doctor --connect` also connects to each host.
