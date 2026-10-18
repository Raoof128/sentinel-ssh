//! Gateway configuration (spec §9.2, §11.3, §15.1). Loaded from an owner-only TOML file; anything ambiguous is rejected.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use base64::Engine;
use schemars::JsonSchema;
use sentinel_core::error::{ErrorCode, Result, SentinelError};
use sentinel_core::identity::{HostId, HostVisibility, Principal, PrincipalId, Role};
use sentinel_core::policy::{HostPolicy, PolicyEngine, RootPolicy};
use serde::{Deserialize, Serialize};

/// Unix domain socket paths are limited to 104 bytes on macOS; keep slack for `%C` (40 hex chars).
pub const MAX_CONTROL_PATH: usize = 100;

fn invalid(msg: impl Into<String>) -> SentinelError {
    SentinelError::new(ErrorCode::ConfigInvalid, msg)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub gateway: GatewaySettings,
    pub principal: PrincipalSettings,
    #[serde(default)]
    pub hosts: Vec<HostConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewaySettings {
    #[serde(default = "default_artifact_dir")]
    pub artifact_dir: PathBuf,
    #[serde(default = "default_runtime_dir")]
    pub runtime_dir: PathBuf,
    #[serde(default = "default_ssh_binary")]
    pub ssh_binary: PathBuf,
    #[serde(default)]
    pub budgets: Budgets,
}

fn default_artifact_dir() -> PathBuf {
    PathBuf::from("~/.local/share/sentinel-ssh/artifacts")
}
fn default_runtime_dir() -> PathBuf {
    PathBuf::from("~/.local/state/sentinel-ssh/run")
}
fn default_ssh_binary() -> PathBuf {
    PathBuf::from("/usr/bin/ssh")
}

/// Initial design defaults from spec §11.3. Not proven optimal; adjust through a measured process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Budgets {
    pub max_active_operations: usize,
    pub max_pending_operations: usize,
    pub per_host_reads: usize,
    pub max_batch_items: usize,
    pub queue_wait_secs: u64,
    pub connect_timeout_secs: u64,
    pub read_timeout_secs: u64,
    pub default_result_bytes: usize,
    pub max_result_bytes: usize,
    pub transfer_chunk_bytes: usize,
    pub max_transfer_bytes: u64,
    pub transfer_idle_timeout_secs: u64,
    pub transfer_total_timeout_secs: u64,
    pub artifact_retention_hours: u64,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            max_active_operations: 64,
            max_pending_operations: 128,
            per_host_reads: 4,
            max_batch_items: 16,
            queue_wait_secs: 5,
            connect_timeout_secs: 10,
            read_timeout_secs: 30,
            default_result_bytes: 8192,
            max_result_bytes: 65536,
            transfer_chunk_bytes: 65536,
            max_transfer_bytes: 268_435_456,
            transfer_idle_timeout_secs: 30,
            transfer_total_timeout_secs: 600,
            artifact_retention_hours: 24,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalSettings {
    pub id: String,
    pub role: Role,
}

/// A pinned host public key in the form `<keytype> <base64>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKey {
    pub key_type: String,
    pub base64: String,
}

const KEY_TYPES: [&str; 5] = [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
];

impl FromStr for HostKey {
    type Err = SentinelError;
    fn from_str(s: &str) -> Result<Self> {
        let form = "host_key must be exactly \"<keytype> <base64>\" (for example the 2nd and 3rd fields of a known_hosts line, without hostname or comment)";
        let parts: Vec<&str> = s.split_whitespace().collect();
        let [key_type, b64] = parts.as_slice() else {
            return Err(invalid(form));
        };
        if !KEY_TYPES.contains(key_type) {
            return Err(invalid(format!("{form}; unsupported key type '{key_type}'")));
        }
        let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(b64) else {
            return Err(invalid(format!("{form}; key body is not valid base64")));
        };
        // An SSH public key blob starts with its own algorithm name (RFC 4253 §6.6): a length, then the name.
        let embedded = blob
            .get(..4)
            .map(|l| u32::from_be_bytes([l[0], l[1], l[2], l[3]]) as usize)
            .and_then(|n| blob.get(4..4 + n));
        if embedded != Some(key_type.as_bytes()) {
            return Err(invalid(format!(
                "{form}; the key body's algorithm does not match the declared type '{key_type}'"
            )));
        }
        Ok(HostKey {
            key_type: (*key_type).to_owned(),
            base64: (*b64).to_owned(),
        })
    }
}

impl fmt::Display for HostKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.key_type, self.base64)
    }
}

impl<'de> Deserialize<'de> for HostKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(|e: SentinelError| serde::de::Error::custom(e.message))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthConfig {
    IdentityFile { path: PathBuf },
    Agent,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootConfig {
    pub path: String,
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub export: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnitScope {
    System,
    User,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub unit: String,
    pub scope: UnitScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSourceConfig {
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HealthCheckConfig {
    Http {
        url: String,
        expect_status: u16,
        timeout_secs: u64,
    },
    ServiceActive {
        service: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    pub id: HostId,
    pub environment: String,
    pub address: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub user: String,
    pub host_key: HostKey,
    pub auth: AuthConfig,
    #[serde(default)]
    pub roots: BTreeMap<String, RootConfig>,
    #[serde(default)]
    pub services: BTreeMap<String, ServiceConfig>,
    #[serde(default)]
    pub log_sources: BTreeMap<String, LogSourceConfig>,
    #[serde(default)]
    pub health_checks: BTreeMap<String, HealthCheckConfig>,
}

fn default_port() -> u16 {
    22
}

pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").filter(|h| !h.is_empty()).map(PathBuf::from)
}

pub fn expand_tilde(p: &Path) -> PathBuf {
    match (p.strip_prefix("~"), home_dir()) {
        (Ok(rest), Some(home)) => home.join(rest),
        _ => p.to_path_buf(),
    }
}

/// `$XDG_CONFIG_HOME/sentinel-ssh/config.toml`, else `~/.config/sentinel-ssh/config.toml`.
pub fn default_config_path() -> PathBuf {
    match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        Some(x) => PathBuf::from(x).join("sentinel-ssh/config.toml"),
        None => expand_tilde(Path::new("~/.config/sentinel-ssh/config.toml")),
    }
}

/// Checks the file is owned by the current user and has no group/other permission bits.
pub fn check_private_file(path: &Path, what: &str) -> Result<()> {
    let meta = std::fs::metadata(path).map_err(|e| invalid(format!("cannot read {what} {}: {e}", path.display())))?;
    if meta.uid() != rustix::process::getuid().as_raw() {
        return Err(invalid(format!("{what} {} must be owned by the current user", path.display())));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(invalid(format!(
            "{what} {} must be mode 0600 (owner-only); found {:o}",
            path.display(),
            meta.mode() & 0o777
        )));
    }
    Ok(())
}

/// Creates `dir` (and parents) with mode 0700 if absent, then requires: not a symlink, a directory, owned by the current user,
/// no group/other permission bits. Used for every gateway-private directory (artefacts, SSH runtime files).
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if std::fs::symlink_metadata(dir).is_err() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| invalid(format!("cannot create {}: {e}", dir.display())))?;
    }
    let meta = std::fs::symlink_metadata(dir).map_err(|e| invalid(format!("cannot inspect {}: {e}", dir.display())))?;
    if meta.file_type().is_symlink() {
        return Err(invalid(format!(
            "{} is a symlink; private directories must be real directories",
            dir.display()
        )));
    }
    if !meta.is_dir() {
        return Err(invalid(format!("{} is not a directory", dir.display())));
    }
    if meta.uid() != rustix::process::getuid().as_raw() {
        return Err(invalid(format!("{} must be owned by the current user", dir.display())));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(invalid(format!(
            "{} must be mode 0700; found {:o}",
            dir.display(),
            meta.mode() & 0o777
        )));
    }
    Ok(())
}

fn validate_abs_path(p: &str, what: &str) -> Result<()> {
    let ok = p.starts_with('/')
        && (p == "/" || !p.ends_with('/'))
        && p[1..].split('/').all(|c| !c.is_empty() && c != "." && c != "..")
        && !p.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}');
    if ok || p == "/" {
        Ok(())
    } else {
        Err(invalid(format!(
            "{what} '{p}' must be an absolute, normalised path without a trailing slash"
        )))
    }
}

fn valid_unit(u: &str) -> bool {
    !u.is_empty() && u.len() <= 255 && u.chars().all(|c| c.is_ascii_alphanumeric() || ":_.@\\-".contains(c))
}

fn valid_alias(a: &str) -> bool {
    !a.is_empty() && a.len() <= 64 && a.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn valid_url(u: &str) -> bool {
    (u.starts_with("http://") || u.starts_with("https://")) && !u.chars().any(|c| c.is_whitespace() || (c as u32) < 0x20)
}

pub fn load_config(path: &Path) -> Result<Config> {
    check_private_file(path, "config file")?;
    let text = std::fs::read_to_string(path).map_err(|e| invalid(format!("cannot read config {}: {e}", path.display())))?;
    let mut cfg: Config = toml::from_str(&text).map_err(|e| invalid(format!("config parse error: {e}")))?;
    if cfg.schema_version != 1 {
        return Err(invalid(format!(
            "unsupported schema_version {}; this gateway reads 1",
            cfg.schema_version
        )));
    }
    PrincipalId::parse(&cfg.principal.id).map_err(|_| invalid("principal.id must match ^[a-z0-9][a-z0-9-]{0,62}$"))?;
    cfg.gateway.artifact_dir = expand_tilde(&cfg.gateway.artifact_dir);
    cfg.gateway.runtime_dir = expand_tilde(&cfg.gateway.runtime_dir);
    cfg.gateway.ssh_binary = expand_tilde(&cfg.gateway.ssh_binary);
    let cp_len = cfg.gateway.runtime_dir.as_os_str().len() + "/c-".len() + 40;
    if cp_len > MAX_CONTROL_PATH {
        return Err(invalid(format!(
            "runtime_dir is too long for an SSH ControlPath socket ({cp_len} > {MAX_CONTROL_PATH} bytes)"
        )));
    }
    let mut seen = BTreeSet::new();
    for h in &mut cfg.hosts {
        if !seen.insert(h.id.clone()) {
            return Err(invalid(format!("duplicate host id '{}'", h.id)));
        }
        if h.address.is_empty() || h.address.starts_with('-') || h.address.chars().any(|c| c.is_whitespace()) {
            return Err(invalid(format!("host '{}': invalid address", h.id)));
        }
        if h.user.is_empty() || h.user.starts_with('-') || h.user.chars().any(|c| c.is_whitespace() || c == '@') {
            return Err(invalid(format!("host '{}': invalid user", h.id)));
        }
        if let AuthConfig::IdentityFile { path } = &mut h.auth {
            *path = expand_tilde(path);
        }
        for (alias, r) in &h.roots {
            if !valid_alias(alias) {
                return Err(invalid(format!("host '{}': invalid root alias '{alias}'", h.id)));
            }
            validate_abs_path(&r.path, &format!("host '{}' root '{alias}' path", h.id))?;
            if r.export && !r.read {
                return Err(invalid(format!("host '{}' root '{alias}': export requires read = true", h.id)));
            }
        }
        for (id, s) in &h.services {
            if !valid_alias(id) || !valid_unit(&s.unit) {
                return Err(invalid(format!(
                    "host '{}': invalid service '{id}' or unit name '{}'",
                    h.id, s.unit
                )));
            }
        }
        for (id, l) in &h.log_sources {
            if !valid_alias(id) {
                return Err(invalid(format!("host '{}': invalid log source id '{id}'", h.id)));
            }
            validate_abs_path(&l.path, &format!("host '{}' log source '{id}' path", h.id))?;
        }
        for (id, hc) in &h.health_checks {
            if !valid_alias(id) {
                return Err(invalid(format!("host '{}': invalid health check id '{id}'", h.id)));
            }
            match hc {
                HealthCheckConfig::Http { url, timeout_secs, .. } => {
                    if !valid_url(url) || *timeout_secs == 0 || *timeout_secs > 60 {
                        return Err(invalid(format!(
                            "host '{}' health check '{id}': url must be http(s) without spaces; timeout 1-60 s",
                            h.id
                        )));
                    }
                }
                HealthCheckConfig::ServiceActive { service } => {
                    if !h.services.contains_key(service) {
                        return Err(invalid(format!(
                            "host '{}' health check '{id}' references unknown service '{service}'",
                            h.id
                        )));
                    }
                }
            }
        }
    }
    Ok(cfg)
}

impl Config {
    pub fn host(&self, id: &HostId) -> Option<&HostConfig> {
        self.hosts.iter().find(|h| &h.id == id)
    }

    pub fn policy(&self) -> PolicyEngine {
        PolicyEngine::new(
            self.hosts
                .iter()
                .map(|h| HostPolicy {
                    host_id: h.id.clone(),
                    environment: h.environment.clone(),
                    roots: h
                        .roots
                        .iter()
                        .map(|(a, r)| {
                            (
                                a.clone(),
                                RootPolicy {
                                    alias: a.clone(),
                                    path: r.path.clone(),
                                    read: r.read,
                                    export: r.export,
                                },
                            )
                        })
                        .collect(),
                    services: h.services.keys().cloned().collect(),
                    log_sources: h.log_sources.keys().cloned().collect(),
                    health_checks: h.health_checks.keys().cloned().collect(),
                })
                .collect(),
        )
    }

    /// The single local principal of a stdio deployment. Validated in `load_config`.
    pub fn principal(&self) -> Principal {
        Principal {
            id: PrincipalId::parse(&self.principal.id).expect("validated in load_config"),
            role: self.principal.role,
            visible_hosts: HostVisibility::All,
        }
    }
}
