//! SSH transport.

pub mod backend;
pub mod command;
pub mod openssh;

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::config::Config;
use backend::{ExitKind, RunBudget, SshBackend, classify_ssh_failure};
use command::RemoteCommand;
use openssh::OpenSshBackend;

/// `doctor --connect`: runs `true` on each host. Returns `(check name, ok, detail)` per host. No remote mutation.
pub fn doctor_connect(cfg: &Config) -> Vec<(String, bool, String)> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime always builds");
    let backend = match OpenSshBackend::new(&cfg.gateway) {
        Ok(b) => b,
        Err(e) => return vec![("connect".into(), false, e.message)],
    };
    let budget = RunBudget {
        timeout: Duration::from_secs(cfg.gateway.budgets.connect_timeout_secs + 10),
        max_stdout_bytes: 1024,
        max_stderr_bytes: 4096,
    };
    cfg.hosts
        .iter()
        .map(|h| {
            let name = format!("host.{}.connect", h.id);
            let r = rt.block_on(backend.run(h, &RemoteCommand::new("true"), &budget, CancellationToken::new()));
            match r {
                Ok(o) if o.exit == ExitKind::Code(0) => (name, true, format!("connected in {} ms", o.duration.as_millis())),
                Ok(o) => {
                    let code = classify_ssh_failure(&o.exit, &o.stderr);
                    let msg = String::from_utf8_lossy(&o.stderr).trim().to_owned();
                    (name, false, format!("{code:?}: {msg}"))
                }
                Err(e) => (name, false, format!("{:?}: {}", e.code, e.message)),
            }
        })
        .collect()
}
