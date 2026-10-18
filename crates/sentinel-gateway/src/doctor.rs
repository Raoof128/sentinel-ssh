//! `sentinel-ssh doctor` (spec §15.1): checks configuration, trust inputs and the local SSH client without any remote mutation.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::{AuthConfig, Config, MAX_CONTROL_PATH, check_private_file, ensure_private_dir, load_config};

pub const SYSTEM_SSH_CONFIG: &str = "/etc/ssh/ssh_config";
const MIN_OPENSSH: (u32, u32) = (8, 9);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorCheck {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Default)]
pub struct DoctorReport {
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    fn push(&mut self, name: impl Into<String>, ok: bool, detail: impl Into<String>) {
        self.checks.push(DoctorCheck {
            name: name.into(),
            ok,
            detail: detail.into(),
        });
    }

    pub fn ok(&self) -> bool {
        self.checks.iter().all(|c| c.ok)
    }

    pub fn render(&self) -> String {
        self.checks
            .iter()
            .map(|c| format!("[{}] {}: {}\n", if c.ok { "ok" } else { "FAIL" }, c.name, c.detail))
            .collect()
    }
}

pub fn run_doctor(config_path: &Path, connect: bool) -> DoctorReport {
    run_doctor_with_system_config(config_path, connect, Path::new(SYSTEM_SSH_CONFIG))
}

pub fn run_doctor_with_system_config(config_path: &Path, connect: bool, system_ssh_config: &Path) -> DoctorReport {
    let mut r = DoctorReport::default();
    match check_private_file(config_path, "config file") {
        Ok(()) => r.push("config.permissions", true, "owner-only (0600) and owned by the current user"),
        Err(e) => r.push("config.permissions", false, e.message),
    }
    let cfg = match load_config(config_path) {
        Ok(c) => {
            r.push("config.load", true, format!("{} host(s)", c.hosts.len()));
            c
        }
        Err(e) => {
            r.push("config.load", false, e.message);
            check_system_config(&mut r, system_ssh_config);
            return r;
        }
    };
    check_ssh_binary(&mut r, &cfg.gateway.ssh_binary);
    check_system_config(&mut r, system_ssh_config);
    check_private_dir(&mut r, "dirs.artifact", &cfg.gateway.artifact_dir);
    check_private_dir(&mut r, "dirs.runtime", &cfg.gateway.runtime_dir);
    for h in &cfg.hosts {
        match &h.auth {
            AuthConfig::IdentityFile { path } => match check_private_file(path, "identity file") {
                Ok(()) => r.push(format!("host.{}.identity", h.id), true, path.display().to_string()),
                Err(e) => r.push(format!("host.{}.identity", h.id), false, e.message),
            },
            AuthConfig::Agent => {
                let ok = std::env::var_os("SSH_AUTH_SOCK").is_some();
                r.push(
                    format!("host.{}.identity", h.id),
                    ok,
                    if ok {
                        "ssh-agent via SSH_AUTH_SOCK"
                    } else {
                        "SSH_AUTH_SOCK is not set"
                    },
                );
            }
        }
        let cp = cfg.gateway.runtime_dir.as_os_str().len() + 3 + 40;
        r.push(
            format!("host.{}.controlpath_length", h.id),
            cp <= MAX_CONTROL_PATH,
            format!("{cp} of {MAX_CONTROL_PATH} bytes"),
        );
    }
    if connect {
        connect_checks(&mut r, &cfg);
    }
    r
}

/// Filled in by the SSH backend (Task 7); kept separate so doctor never mutates remote state.
fn connect_checks(r: &mut DoctorReport, cfg: &Config) {
    for (name, ok, detail) in crate::ssh::doctor_connect(cfg) {
        r.push(name, ok, detail);
    }
}

fn parse_openssh_version(s: &str) -> Option<(u32, u32)> {
    let rest = s.split("OpenSSH_").nth(1)?;
    let mut it = rest.split(|c: char| !c.is_ascii_digit());
    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
}

fn check_ssh_binary(r: &mut DoctorReport, bin: &Path) {
    match Command::new(bin).arg("-V").output() {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stderr).trim().to_string();
            match parse_openssh_version(&text) {
                Some(v) if v >= MIN_OPENSSH => r.push("ssh.binary", true, text),
                Some(_) => r.push(
                    "ssh.binary",
                    false,
                    format!("{text}: OpenSSH {}.{} or newer required", MIN_OPENSSH.0, MIN_OPENSSH.1),
                ),
                None => r.push("ssh.binary", false, format!("{}: not an OpenSSH client ({text})", bin.display())),
            }
        }
        Err(e) => r.push("ssh.binary", false, format!("{}: {e}", bin.display())),
    }
}

fn check_private_dir(r: &mut DoctorReport, name: &str, dir: &Path) {
    match ensure_private_dir(dir) {
        Ok(()) => r.push(name, true, format!("{} (0700, owned by the current user)", dir.display())),
        Err(e) => r.push(name, false, e.message),
    }
}

/// `ssh -F /dev/null` skips the user config but OpenSSH still reads the system file and its `Include`s.
/// The gateway trusts them as administrator-owned; this check verifies that assumption and flags executable directives.
fn check_system_config(r: &mut DoctorReport, path: &Path) {
    let mut problems = Vec::new();
    let mut warnings = Vec::new();
    let mut files = vec![path.to_path_buf()];
    let mut i = 0;
    while i < files.len() && i < 64 {
        let f = files[i].clone();
        i += 1;
        let Ok(meta) = std::fs::metadata(&f) else { continue };
        if meta.uid() != 0 {
            problems.push(format!("{} is not owned by root", f.display()));
        }
        if meta.permissions().mode() & 0o022 != 0 {
            problems.push(format!("{} is group- or world-writable", f.display()));
        }
        let Ok(text) = std::fs::read_to_string(&f) else { continue };
        for (n, line) in text.lines().enumerate() {
            let t = line.trim();
            if t.starts_with('#') || t.is_empty() {
                continue;
            }
            let lower = t.to_ascii_lowercase();
            let mut words = lower.split(|c: char| c.is_whitespace() || c == '=').filter(|w| !w.is_empty());
            let kw = words.next().unwrap_or("");
            let arg = words.next().unwrap_or("");
            let flag = match kw {
                "proxycommand" if arg != "none" => Some("ProxyCommand"),
                "localcommand" => Some("LocalCommand"),
                "permitlocalcommand" if arg == "yes" => Some("PermitLocalCommand yes"),
                "match" if lower.contains("exec") => Some("Match exec"),
                "proxyjump" if arg != "none" => Some("ProxyJump"),
                _ => None,
            };
            if let Some(what) = flag {
                warnings.push(format!("{}:{} {what}", f.display(), n + 1));
            }
            if kw == "include" {
                for pat in t.split_whitespace().skip(1) {
                    let p = if pat.starts_with('/') {
                        PathBuf::from(pat)
                    } else {
                        Path::new("/etc/ssh").join(pat)
                    };
                    if !p.starts_with("/etc/ssh/") {
                        warnings.push(format!("{}:{} Include outside /etc/ssh: {pat}", f.display(), n + 1));
                    }
                    files.extend(expand_simple_glob(&p));
                }
            }
        }
    }
    let ok = problems.is_empty();
    let mut detail = Vec::new();
    if ok {
        detail.push(format!("{} and includes are administrator-owned", path.display()));
    }
    detail.extend(problems);
    if !warnings.is_empty() {
        detail.push(format!(
            "executable or routing directives (explicit -o options override them for the same keyword): {}",
            warnings.join("; ")
        ));
    }
    r.push("ssh.system_config", ok, detail.join("; "));
}

/// Supports the `dir/*` and `dir/*.conf` patterns OpenSSH distributions use; other patterns are taken literally.
fn expand_simple_glob(p: &Path) -> Vec<PathBuf> {
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let Some(suffix) = name.strip_prefix('*') else {
        return vec![p.to_path_buf()];
    };
    let Some(dir) = p.parent() else { return vec![] };
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|f| f.is_file() && f.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.ends_with(suffix)))
        .collect();
    out.sort();
    out
}
