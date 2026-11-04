//! SSH transport.

pub mod backend;
pub mod command;
pub mod openssh;

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use sentinel_core::error::ErrorCode;

use crate::config::{Config, Elevation, HostConfig};
use backend::{ELEVATION_REFUSED, ExitKind, RunBudget, SshBackend, classify_ssh_failure, elevation_refused};
use command::RemoteCommand;
use openssh::OpenSshBackend;

/// `doctor --connect`: runs `true` on each host, and proves uid 0 on hosts with `elevation = "sudo"`. Returns `(check name, ok, detail)` per host. No remote mutation.
pub fn doctor_connect(cfg: &Config) -> Vec<(String, bool, String)> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime always builds");
    let backend = match OpenSshBackend::unmultiplexed(&cfg.gateway) {
        Ok(b) => b,
        Err(e) => return vec![("connect".into(), false, e.message)],
    };
    let budget = RunBudget {
        timeout: Duration::from_secs(cfg.gateway.budgets.connect_timeout_secs + 10),
        max_stdout_bytes: 1024,
        max_stderr_bytes: 4096,
    };
    let mut checks = Vec::new();
    for h in &cfg.hosts {
        let name = format!("host.{}.connect", h.id);
        let r = rt.block_on(backend.run(h, &RemoteCommand::new("true"), &budget, CancellationToken::new()));
        let connected = matches!(&r, Ok(o) if o.exit == ExitKind::Code(0));
        checks.push(match r {
            Ok(o) if o.exit == ExitKind::Code(0) => (name, true, format!("connected in {} ms", o.duration.as_millis())),
            Ok(o) => {
                let code = if elevation_refused(h, &o.exit, &o.stderr) {
                    Some(ErrorCode::AuthenticationFailed)
                } else {
                    classify_ssh_failure(&o.exit, &o.stderr)
                };
                // A hostile server controls this text: escape it so it cannot draw on the operator's terminal.
                let msg = sentinel_core::scope::display_escape(String::from_utf8_lossy(&o.stderr).trim());
                (name, false, format!("{code:?}: {msg}"))
            }
            Err(e) => (name, false, format!("{:?}: {}", e.code, e.message)),
        });
        if connected && h.elevation == Elevation::Sudo {
            checks.push(elevation_check(&rt, &backend, h, &budget));
        }
    }
    checks
}

/// Proves `elevation = "sudo"` really yields root: the owner of `/proc/self` is the probing process's effective uid.
fn elevation_check(rt: &tokio::runtime::Runtime, backend: &OpenSshBackend, h: &HostConfig, budget: &RunBudget) -> (String, bool, String) {
    let name = format!("host.{}.elevation", h.id);
    let probe = RemoteCommand::new("stat").flag("-L").flag("-c").arg("%u").arg("/proc/self");
    match rt.block_on(backend.run(h, &probe, budget, CancellationToken::new())) {
        Ok(o) if o.exit == ExitKind::Code(0) && String::from_utf8_lossy(&o.stdout).trim() == "0" => {
            (name, true, "sudo -n runs the gateway's commands as root (uid 0)".into())
        }
        Ok(o) if elevation_refused(h, &o.exit, &o.stderr) => (name, false, ELEVATION_REFUSED.into()),
        Ok(o) => (
            name,
            false,
            format!(
                "expected uid 0 under sudo, got '{}' (exit {:?})",
                sentinel_core::scope::display_escape(String::from_utf8_lossy(&o.stdout).trim()),
                o.exit
            ),
        ),
        Err(e) => (name, false, format!("{:?}: {}", e.code, e.message)),
    }
}
