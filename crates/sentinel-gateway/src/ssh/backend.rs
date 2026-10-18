//! The SSH backend interface (spec §13.2 `SshBackend.connect/dispatch`). A backend returns dispatch evidence, never an assumed
//! remote success: callers classify exit statuses and stderr.

use std::time::Duration;

use async_trait::async_trait;
use schemars::JsonSchema;
use sentinel_core::error::{ErrorCode, Result};
use sentinel_core::operation::RemoteTermination;
use serde::Serialize;
use tokio::io::AsyncWrite;
use tokio_util::sync::CancellationToken;

use crate::config::HostConfig;
use crate::ssh::command::RemoteCommand;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunBudget {
    pub timeout: Duration,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamBudget {
    pub idle_timeout: Duration,
    pub total_timeout: Duration,
    pub max_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    Code(i32),
    Signal(i32),
    Killed,
}

#[derive(Debug, Clone)]
pub struct RunOutcome {
    pub exit: ExitKind,
    pub stdout: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr: Vec<u8>,
    pub stderr_truncated: bool,
    pub duration: Duration,
}

#[derive(Debug, Clone)]
pub struct StreamOutcome {
    pub exit: ExitKind,
    pub bytes: u64,
    pub stderr: Vec<u8>,
    pub duration: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct BackendCapabilities {
    pub name: String,
    pub host_key_pinning: bool,
    pub remote_termination: RemoteTermination,
    pub connection_reuse: bool,
}

#[async_trait]
pub trait SshBackend: Send + Sync {
    async fn run(&self, host: &HostConfig, cmd: &RemoteCommand, budget: &RunBudget, cancel: CancellationToken) -> Result<RunOutcome>;

    async fn stream_stdout(
        &self,
        host: &HostConfig,
        cmd: &RemoteCommand,
        budget: &StreamBudget,
        cancel: CancellationToken,
        sink: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> Result<StreamOutcome>;

    fn capabilities(&self) -> BackendCapabilities;
}

/// Maps an OpenSSH client failure (exit 255) to a typed code. Remote-command exit statuses (0-254) return `None`.
pub fn classify_ssh_failure(exit: &ExitKind, stderr: &[u8]) -> Option<ErrorCode> {
    if *exit != ExitKind::Code(255) {
        return None;
    }
    let s = String::from_utf8_lossy(stderr);
    Some(
        if s.contains("REMOTE HOST IDENTIFICATION HAS CHANGED") || s.contains("Host key verification failed") {
            ErrorCode::HostKeyChanged
        } else if s.contains("Permission denied") {
            ErrorCode::AuthenticationFailed
        } else {
            ErrorCode::ConnectionFailed
        },
    )
}
