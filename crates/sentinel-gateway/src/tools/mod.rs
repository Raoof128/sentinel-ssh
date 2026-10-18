//! The 17 v0.1 tools. Each is a plain async function over [`AppContext`]; `mcp::server` adapts them to rmcp.

pub mod capabilities;
pub mod disk;
pub mod health;
pub mod hosts;
pub mod pipeline;
pub mod processes;
pub mod services;

use std::sync::Arc;
use std::time::Duration;

use sentinel_core::error::Result;
use sentinel_core::identity::Principal;
use sentinel_core::policy::PolicyEngine;

use crate::artifacts::ArtifactStore;
use crate::config::Config;
use crate::jobs::operations::Operations;
use crate::jobs::scheduler::Scheduler;
use crate::ssh::backend::SshBackend;

/// Every advertised tool, sorted ascending (spec §7.1 core tools plus §7.3 #26 download).
pub const TOOL_NAMES: [&str; 17] = [
    "ssh_artifact_read",
    "ssh_batch_inspect",
    "ssh_capabilities_get",
    "ssh_disk_usage",
    "ssh_file_hash",
    "ssh_file_read",
    "ssh_file_stat",
    "ssh_files_list",
    "ssh_health_check",
    "ssh_host_inspect",
    "ssh_hosts_list",
    "ssh_logs_search",
    "ssh_operation_cancel",
    "ssh_operation_get",
    "ssh_process_list",
    "ssh_service_status",
    "ssh_transfer_download",
];

/// The observer-mode guarantee, stated verbatim in capabilities, server instructions and README (spec §5.1, §5.5).
pub const GUARANTEE_STATEMENT: &str =
    "The gateway enforces the tool interface. The SSH account may permit more; it is not a remote sandbox.";
pub const SYMLINK_CONTAINMENT: &str = "final path component only; symlinked parent directories are not detected in observer mode";

/// Marks remote-sourced text so agents treat it as data (spec §9.7).
pub const UNTRUSTED: &str = "untrusted";

#[derive(Clone)]
pub struct AppContext {
    pub config: Arc<Config>,
    pub policy: Arc<PolicyEngine>,
    pub principal: Principal,
    pub backend: Arc<dyn SshBackend>,
    pub scheduler: Arc<Scheduler>,
    pub operations: Arc<Operations>,
    pub artifacts: Arc<ArtifactStore>,
}

impl AppContext {
    pub fn new(config: Config, backend: Arc<dyn SshBackend>) -> Result<Self> {
        let artifacts = ArtifactStore::open(
            &config.gateway.artifact_dir,
            Duration::from_secs(config.gateway.budgets.artifact_retention_hours * 3600),
        )?;
        Ok(Self {
            policy: Arc::new(config.policy()),
            principal: config.principal(),
            scheduler: Arc::new(Scheduler::new(&config.gateway.budgets)),
            operations: Arc::new(Operations::new()),
            artifacts: Arc::new(artifacts),
            backend,
            config: Arc::new(config),
        })
    }
}

/// Validates an optional bounded integer parameter.
pub(crate) fn bounded(value: Option<u32>, default: u32, max: u32, field: &str) -> Result<u32> {
    use sentinel_core::error::{ErrorCode, SentinelError};
    let v = value.unwrap_or(default);
    if v == 0 || v > max {
        return Err(
            SentinelError::new(ErrorCode::InvalidInput, format!("{field} must be between 1 and {max}")).with_detail("field", field),
        );
    }
    Ok(v)
}
