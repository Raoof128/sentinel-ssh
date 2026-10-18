//! A scripted `SshBackend` for tool-contract tests. Commands are matched by substring of the rendered remote command,
//! first match wins. Every dispatched command is recorded so tests can assert what (and whether anything) was sent.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sentinel_core::error::{ErrorCode, Result, SentinelError};
use sentinel_core::operation::RemoteTermination;
use sentinel_gateway::config::HostConfig;
use sentinel_gateway::ssh::backend::{BackendCapabilities, ExitKind, RunBudget, RunOutcome, SshBackend, StreamBudget, StreamOutcome};
use sentinel_gateway::ssh::command::RemoteCommand;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Default)]
pub struct Script {
    pub matches: String,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit: i32,
    pub delay: Duration,
    /// Fail at the transport level with this code instead of producing output.
    pub error: Option<ErrorCode>,
}

#[derive(Debug, Default)]
struct Inner {
    scripts: Vec<Script>,
    calls: Vec<String>,
    fail: Option<ErrorCode>,
}

#[derive(Debug, Clone, Default)]
pub struct FakeBackend {
    inner: Arc<Mutex<Inner>>,
}

impl FakeBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn on(self, matches: &str, stdout: impl Into<Vec<u8>>) -> Self {
        self.on_script(Script {
            matches: matches.into(),
            stdout: stdout.into(),
            ..Script::default()
        })
    }

    pub fn on_script(self, s: Script) -> Self {
        self.inner.lock().unwrap().scripts.push(s);
        self
    }

    /// Every call returns `Err(code)` as an SSH client failure would after classification.
    pub fn fail_connect(self, code: ErrorCode) -> Self {
        self.inner.lock().unwrap().fail = Some(code);
        self
    }

    /// Rendered commands in dispatch order.
    pub fn calls(&self) -> Vec<String> {
        self.inner.lock().unwrap().calls.clone()
    }

    fn dispatch(&self, cmd: &RemoteCommand) -> Result<Script> {
        let rendered = cmd.render();
        let mut g = self.inner.lock().unwrap();
        g.calls.push(rendered.clone());
        // Mirror the OS: a process argument cannot contain NUL, so the real backend could never dispatch this.
        if rendered.contains('\0') {
            return Err(SentinelError::new(
                ErrorCode::ConnectionFailed,
                "fake: command contains a NUL byte and cannot be passed to ssh",
            ));
        }
        if let Some(code) = g.fail {
            return Err(SentinelError::new(code, "fake: connection failure"));
        }
        let script = g
            .scripts
            .iter()
            .find(|s| rendered.contains(&s.matches))
            .cloned()
            .ok_or_else(|| SentinelError::new(ErrorCode::RemoteFailure, format!("fake: no script for {rendered}")))?;
        match script.error {
            Some(code) => Err(SentinelError::new(code, "fake: scripted transport failure")),
            None => Ok(script),
        }
    }

    async fn wait(delay: Duration, limit: Duration, cancel: &CancellationToken) -> Result<()> {
        tokio::select! {
            _ = tokio::time::sleep(delay) => Ok(()),
            _ = tokio::time::sleep(limit) => Err(SentinelError::new(ErrorCode::Timeout, "fake: budget exceeded").with_detail("remote_termination", "unconfirmed")),
            _ = cancel.cancelled() => Err(SentinelError::new(ErrorCode::Timeout, "cancelled").with_detail("cancelled", true).with_detail("remote_termination", "unconfirmed")),
        }
    }
}

#[async_trait]
impl SshBackend for FakeBackend {
    async fn run(&self, _host: &HostConfig, cmd: &RemoteCommand, budget: &RunBudget, cancel: CancellationToken) -> Result<RunOutcome> {
        let start = Instant::now();
        let s = self.dispatch(cmd)?;
        Self::wait(s.delay, budget.timeout, &cancel).await?;
        let mut stdout = s.stdout;
        let stdout_truncated = stdout.len() > budget.max_stdout_bytes;
        stdout.truncate(budget.max_stdout_bytes);
        let mut stderr = s.stderr;
        let stderr_truncated = stderr.len() > budget.max_stderr_bytes;
        stderr.truncate(budget.max_stderr_bytes);
        Ok(RunOutcome {
            exit: ExitKind::Code(s.exit),
            stdout,
            stdout_truncated,
            stderr,
            stderr_truncated,
            duration: start.elapsed(),
        })
    }

    async fn stream_stdout(
        &self,
        _host: &HostConfig,
        cmd: &RemoteCommand,
        budget: &StreamBudget,
        cancel: CancellationToken,
        sink: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> Result<StreamOutcome> {
        let start = Instant::now();
        let s = self.dispatch(cmd)?;
        Self::wait(s.delay, budget.total_timeout, &cancel).await?;
        let mut bytes = 0u64;
        for chunk in s.stdout.chunks(64 * 1024) {
            bytes += chunk.len() as u64;
            if bytes > budget.max_bytes {
                return Err(SentinelError::new(ErrorCode::BudgetExceeded, "fake: stream over budget"));
            }
            sink.write_all(chunk)
                .await
                .map_err(|e| SentinelError::new(ErrorCode::Internal, e.to_string()))?;
        }
        sink.flush()
            .await
            .map_err(|e| SentinelError::new(ErrorCode::Internal, e.to_string()))?;
        Ok(StreamOutcome {
            exit: ExitKind::Code(s.exit),
            bytes,
            stderr: s.stderr,
            duration: start.elapsed(),
        })
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: "fake".into(),
            host_key_pinning: true,
            remote_termination: RemoteTermination::Unconfirmed,
            connection_reuse: false,
        }
    }
}
