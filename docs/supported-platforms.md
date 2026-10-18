# Supported platforms (v0.1)

| Side | Supported | Notes |
|---|---|---|
| Gateway | macOS 26+ (arm64), Linux x86_64 and aarch64 | Requires the OpenSSH client 8.9 or newer at the configured `ssh_binary`. Checked by `sentinel-ssh doctor`. |
| Target host | Linux | Requires GNU coreutils (`stat -c`, `du -B1`, `df -B1 -P`, `head -c`, `tail -c`, `sha256sum`), GNU findutils (`find -printf`), procps (`ps -eo ... --sort`), GNU grep. `curl` for HTTP health checks. systemd is optional: without it, service tools return `CAPABILITY_UNSUPPORTED`. |

BusyBox and non-GNU utilities are not supported: tools that depend on missing options return `CAPABILITY_UNSUPPORTED` rather than guessing.

Command templates were verified against Ubuntu 24.04.3 (OpenSSH 9.6p1, kernel 6.8) on 18 October 2026.

The target account's login shell must be POSIX `sh` compatible (`sh`, `dash`, `bash`, `zsh`): OpenSSH sends each remote command as one string interpreted by that shell. `fish` and `csh` accounts are not supported.
