//! `sentinel-ssh doctor` (spec §15.1): checks configuration, trust inputs and the local SSH client without any remote mutation.

use std::path::Path;
use std::process::Command;

use crate::config::{AuthConfig, CONTROL_PATH_SUFFIX, Config, MAX_CONTROL_PATH, check_private_file, ensure_private_dir, load_config};

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
            return r;
        }
    };
    check_ssh_binary(&mut r, &cfg.gateway.ssh_binary);
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
        let cp = cfg.gateway.runtime_dir.as_os_str().len() + CONTROL_PATH_SUFFIX;
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
    if let Err(e) = crate::config::check_trusted_executable(bin)
        && bin.exists()
    {
        r.push("ssh.binary", false, e.message);
        return;
    }
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
