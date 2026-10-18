//! The one path every tool takes (spec §8.3 ordering, observer subset): validate → authorise → record → schedule → run →
//! record outcome → envelope. A denial is recorded as `rejected` and never reaches the backend.

use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use regex::Regex;
use sentinel_core::effect::Effect;
use sentinel_core::envelope::{EvidenceSource, Outcome, ResultEnvelope};
use sentinel_core::error::{ErrorCode, Result, SentinelError};
use sentinel_core::identity::{HostId, OperationId};
use sentinel_core::policy::ResourceRef;
use sentinel_core::scope::ScopedPath;

use crate::config::HostConfig;
use crate::jobs::operations::RunningOp;
use crate::ssh::backend::{ExitKind, RunBudget, RunOutcome, classify_ssh_failure};
use crate::ssh::command::{
    EXCLUDED, EXCLUDED_EXIT, HARDLINK, HARDLINK_EXIT, KIND_MISMATCH, KIND_MISMATCH_EXIT, MISSING, MISSING_EXIT, NESTED_EXCLUDED,
    NESTED_EXCLUDED_EXIT, NO_ACCESS, NO_ACCESS_EXIT, Pin, ROOT_MISSING, ROOT_MISSING_EXIT, RemoteCommand, SCOPE_ESCAPE, SCOPE_ESCAPE_EXIT,
    TOO_LARGE, TOO_LARGE_EXIT, contained,
};
use crate::tools::AppContext;

pub const NON_UTF8_WARNING: &str = "non_utf8_replaced";
pub const REMOTE_OUTPUT_TRUNCATED: &str = "remote_output_truncated";

#[derive(Debug, Default)]
struct Extras {
    warnings: Vec<String>,
    next_cursor: Option<String>,
    partial: bool,
}

/// What a tool body can use: the context, the resolved host, its operation and a run budget.
#[derive(Clone)]
pub struct ToolRun {
    pub ctx: AppContext,
    pub host: HostConfig,
    pub op: RunningOp,
    pub budget: RunBudget,
    extras: Arc<Mutex<Extras>>,
}

fn missing_utility_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // dash `sh: 1: X: not found`, bash `bash: line 1: X: command not found`, BusyBox ash `sh: X: not found`.
        // The shell prefix is required and the line must end there: a remote file name inside another tool's error
        // message cannot pose as one (red team M3).
        Regex::new(r"(?m)^[\w./-]*sh: (?:\d+: |line \d+: )?([\w.-]+): (?:not found|command not found)$").unwrap()
    })
}

fn unsupported_option_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // GNU getopt (`unrecognized option '--x'`, `invalid option -- 'x'`), BSD (`illegal option`), find (`unknown
        // predicate`), BusyBox (`unrecognized option: x`, find's `unrecognized: -x`), each at the start of its own line.
        Regex::new(r"(?m)^([\w.-]+): (?:unrecognized option\b|unrecognized:|invalid option\b|illegal option\b|unknown option\b|unknown predicate\b)[^\n]*$")
            .unwrap()
    })
}

fn first_line(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .chars()
        .take(300)
        .collect()
}

/// Maps remote-side refusals and missing capabilities in stderr to typed errors. Applies whatever the exit status,
/// because a pipeline exits with its last command's status.
pub fn classify_remote(cmd: &RemoteCommand, out: &RunOutcome) -> Result<()> {
    if let Some(code) = classify_ssh_failure(&out.exit, &out.stderr) {
        // The client's own message names the address, port and user; keep it in the local log only.
        tracing::warn!(stderr = %first_line(&out.stderr), "ssh client failure");
        let msg = match code {
            ErrorCode::HostKeyChanged => "the host key does not match the key pinned for this host",
            ErrorCode::AuthenticationFailed => "authentication failed for the configured account",
            _ => "could not connect to the host",
        };
        return Err(SentinelError::new(code, msg));
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if out.exit == ExitKind::Code(SCOPE_ESCAPE_EXIT) && stderr.contains(SCOPE_ESCAPE) {
        return Err(SentinelError::new(
            ErrorCode::PolicyDenied,
            "path resolves outside the registered root (symlinked directory)",
        ));
    }
    if out.exit == ExitKind::Code(NESTED_EXCLUDED_EXIT) && stderr.contains(NESTED_EXCLUDED) {
        return Err(SentinelError::new(
            ErrorCode::PolicyDenied,
            "the directory contains a root this principal may not access; choose a path that does not contain it",
        ));
    }
    if out.exit == ExitKind::Code(MISSING_EXIT) && stderr.contains(MISSING) {
        return Err(SentinelError::new(ErrorCode::NotFound, "path not found"));
    }
    if out.exit == ExitKind::Code(NO_ACCESS_EXIT) && stderr.contains(NO_ACCESS) {
        return Err(SentinelError::new(
            ErrorCode::RemoteFailure,
            "the SSH account cannot read this path (permission denied)",
        ));
    }
    if out.exit == ExitKind::Code(HARDLINK_EXIT) && stderr.contains(HARDLINK) {
        return Err(SentinelError::new(
            ErrorCode::PolicyDenied,
            "hard-linked files are refused (the file has more than one name)",
        ));
    }
    if out.exit == ExitKind::Code(EXCLUDED_EXIT) && stderr.contains(EXCLUDED) {
        return Err(SentinelError::new(
            ErrorCode::PolicyDenied,
            "the path is inside a root this principal may not access",
        ));
    }
    if out.exit == ExitKind::Code(ROOT_MISSING_EXIT) && stderr.contains(ROOT_MISSING) {
        return Err(SentinelError::new(
            ErrorCode::RemoteFailure,
            "the registered root does not exist on the host",
        ));
    }
    if out.exit == ExitKind::Code(KIND_MISMATCH_EXIT) && stderr.contains(KIND_MISMATCH) {
        if stderr.contains("No such file or directory") {
            return Err(SentinelError::new(ErrorCode::NotFound, "path not found"));
        }
        return Err(SentinelError::new(
            ErrorCode::PolicyDenied,
            "target has an unexpected file type (symlinks and special files are refused)",
        ));
    }
    if out.exit == ExitKind::Code(TOO_LARGE_EXIT) && stderr.contains(TOO_LARGE) {
        return Err(SentinelError::new(
            ErrorCode::BudgetExceeded,
            "file exceeds the configured size limit",
        ));
    }
    // Only a program this command runs can be the missing or incompatible one.
    let ran = |name: &str| cmd.programs().contains(&name);
    if let Some(c) = missing_utility_re().captures_iter(&stderr).find(|c| ran(&c[1])) {
        return Err(
            SentinelError::new(ErrorCode::CapabilityUnsupported, format!("remote utility missing: {}", &c[1]))
                .with_detail("utility", c[1].to_string()),
        );
    }
    let systemctl = ran("systemctl");
    if systemctl && stderr.contains("has not been booted with systemd") {
        return Err(SentinelError::new(
            ErrorCode::CapabilityUnsupported,
            "remote host is not running systemd (systemctl unavailable)",
        ));
    }
    if systemctl && stderr.contains("Failed to connect to bus") {
        return Err(SentinelError::new(
            ErrorCode::CapabilityUnsupported,
            "systemd is not reachable for this account (no system manager, or no user session for user-scope units)",
        ));
    }
    if let Some(c) = unsupported_option_re().captures_iter(&stderr).find(|c| ran(&c[1])) {
        return Err(SentinelError::new(
            ErrorCode::CapabilityUnsupported,
            format!("remote {} does not support the required options (GNU utilities required)", &c[1]),
        )
        .with_detail("utility", c[1].to_string()));
    }
    if out.exit == ExitKind::Code(127) {
        let mut candidates: Vec<&str> = cmd
            .programs()
            .iter()
            .copied()
            .filter(|p| !matches!(*p, "realpath" | "stat" | "printf" | "true"))
            .collect();
        candidates.dedup();
        return Err(SentinelError::new(
            ErrorCode::CapabilityUnsupported,
            format!("a remote utility is missing (one of: {})", candidates.join(", ")),
        ));
    }
    Ok(())
}

impl ToolRun {
    /// Dispatches `cmd` and applies [`classify_remote`]. Non-zero exits that are not refusals are returned for the caller.
    pub async fn run(&self, cmd: &RemoteCommand) -> Result<RunOutcome> {
        let out = self.ctx.backend.run(&self.host, cmd, &self.budget, self.op.cancel.clone()).await?;
        classify_remote(cmd, &out)?;
        if out.stdout_truncated {
            self.warn(REMOTE_OUTPUT_TRUNCATED);
        }
        Ok(out)
    }

    /// Runs `main` behind [`contained`]: the target is pinned inside its root (and outside every root this `effect` may
    /// not reach) before `main` runs. A type mismatch becomes `POLICY_DENIED: target is not a <kind>`.
    pub async fn run_pinned(&self, pin: Pin, target: &ScopedPath, effect: Effect, main: RemoteCommand) -> Result<RunOutcome> {
        let excluded = self.excluded_roots(target, effect);
        let kind = match pin {
            Pin::Dir | Pin::Tree => Some("directory"),
            Pin::File => Some("regular file"),
            Pin::Entry => None,
        };
        self.run(&contained(&target.root_path, &target.absolute, pin, &excluded, main))
            .await
            .map_err(|e| match kind {
                Some(kind) if e.code == ErrorCode::PolicyDenied && e.message.starts_with("target has an unexpected file type") => {
                    SentinelError::new(
                        ErrorCode::PolicyDenied,
                        format!("target is not a {kind} (symlinks and special files are refused)"),
                    )
                }
                _ => e,
            })
    }

    pub fn excluded_for_export(&self, target: &ScopedPath) -> Vec<String> {
        self.excluded_roots(target, Effect::Export)
    }

    /// Paths of this host's roots that `effect` may not reach (red team: nested roots). A more restricted root nested
    /// inside, or reachable through, the requested root stays closed.
    fn excluded_roots(&self, target: &ScopedPath, effect: Effect) -> Vec<String> {
        // The host was authorised before the run began, so its policy exists.
        let hp = self.ctx.policy.host(&self.ctx.principal, &self.host.id).expect("authorised host");
        hp.roots
            .values()
            .filter(|r| r.path != target.root_path)
            .filter(|r| match effect {
                Effect::Export => !(r.read && r.export),
                _ => !r.read,
            })
            .map(|r| r.path.clone())
            .collect()
    }

    /// Lossy UTF-8; records the `non_utf8_replaced` warning once if any replacement happened.
    pub fn text_lossy(&self, bytes: &[u8]) -> String {
        match String::from_utf8(bytes.to_vec()) {
            Ok(s) => s,
            Err(_) => {
                self.warn(NON_UTF8_WARNING);
                String::from_utf8_lossy(bytes).into_owned()
            }
        }
    }

    pub fn warn(&self, w: &str) {
        let mut g = self.extras.lock().expect("extras");
        if !g.warnings.iter().any(|x| x == w) {
            g.warnings.push(w.to_owned());
        }
    }

    pub fn set_next_cursor(&self, c: String) {
        self.extras.lock().expect("extras").next_cursor = Some(c);
    }

    pub fn mark_partial(&self) {
        self.extras.lock().expect("extras").partial = true;
    }
}

fn finish_envelope<T>(mut env: ResultEnvelope<T>, extras: &Mutex<Extras>) -> ResultEnvelope<T> {
    let g = extras.lock().expect("extras");
    for w in &g.warnings {
        env = env.warn(w);
    }
    env.next_cursor = g.next_cursor.clone();
    if g.partial {
        env.outcome = Outcome::Partial;
    }
    env
}

/// While alive, a cancel from the caller (see [`crate::tools::cancelled_by`]) cancels this operation through the registry,
/// so its state moves to CancelRequested and then Cancelled exactly as with `ssh_operation_cancel`.
struct CancelLink(Option<tokio::task::JoinHandle<()>>);

impl Drop for CancelLink {
    fn drop(&mut self) {
        if let Some(h) = self.0.take() {
            h.abort();
        }
    }
}

fn link_caller_cancel(ctx: &AppContext, id: &OperationId) -> CancelLink {
    CancelLink(crate::tools::caller_cancel().map(|token| {
        let (ops, principal, id) = (ctx.operations.clone(), ctx.principal.clone(), id.clone());
        tokio::spawn(async move {
            token.cancelled().await;
            let _ = ops.cancel(&principal, &id);
        })
    }))
}

fn cancelled_while_queued() -> SentinelError {
    SentinelError::new(ErrorCode::Timeout, "cancelled while queued").with_detail("cancelled", true)
}

/// Host-scoped tools. `resource` is evaluated against `host_id` before anything else touches the host.
pub async fn read_tool<T, F, Fut>(
    ctx: &AppContext,
    tool: &'static str,
    host_id: &str,
    resource: ResourceRef<'_>,
    effect: Effect,
    body: F,
) -> Result<ResultEnvelope<T>>
where
    F: FnOnce(ToolRun) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let host_id = HostId::parse(host_id)?;
    if let Err(e) = ctx.policy.evaluate(&ctx.principal, Some(&host_id), &resource, effect).into_result() {
        let id = ctx.operations.begin_rejected(&ctx.principal, Some(&host_id), tool, effect, &e);
        return Err(e.with_operation(id.as_str()).with_detail("host_id", host_id.as_str()));
    }
    let host = ctx
        .config
        .host(&host_id)
        .cloned()
        .ok_or_else(|| SentinelError::new(ErrorCode::PolicyDenied, sentinel_core::policy::HOST_UNAVAILABLE))?;
    let op = ctx.operations.begin(&ctx.principal, Some(&host_id), tool, effect);
    let _link = link_caller_cancel(ctx, &op.id);
    let b = &ctx.config.gateway.budgets;
    let budget = RunBudget {
        timeout: Duration::from_secs(b.read_timeout_secs),
        max_stdout_bytes: b.max_result_bytes * 4,
        max_stderr_bytes: 16 * 1024,
    };
    let result = async {
        let acquire = async {
            if effect == Effect::Export {
                ctx.scheduler.acquire_transfer(&host_id).await
            } else {
                ctx.scheduler.acquire_read(&host_id).await
            }
        };
        // A cancel while waiting for a slot ends the operation before anything is dispatched.
        let _permit = tokio::select! {
            p = acquire => p?,
            _ = op.cancel.cancelled() => return Err(cancelled_while_queued()),
        };
        ctx.operations.mark_running(&op.id);
        let extras = Arc::new(Mutex::new(Extras::default()));
        let run = ToolRun {
            ctx: ctx.clone(),
            host,
            op: op.clone(),
            budget,
            extras: extras.clone(),
        };
        let data = body(run).await?;
        Ok(finish_envelope(
            ResultEnvelope::succeeded(op.id.clone(), Some(host_id.clone()), data).with_evidence(tool, EvidenceSource::Observer),
            &extras,
        ))
    }
    .await;
    match result {
        Ok(env) => {
            ctx.operations.finish_ok(&op.id, None);
            Ok(env)
        }
        Err(e) => {
            ctx.operations.finish_err(&op.id, &e);
            Err(e.with_operation(op.id.as_str()).with_detail("host_id", host_id.as_str()))
        }
    }
}

/// Tools that need no SSH (inventory, capabilities, artefact reads). Still recorded as operations, and each takes a
/// global slot, so a flood of them is bounded like any other work.
pub async fn local_tool<T, F, Fut>(ctx: &AppContext, tool: &'static str, body: F) -> Result<ResultEnvelope<T>>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(T, Option<String>)>>,
{
    local_tool_with(ctx, tool, true, body).await
}

/// For the batch tool only: it holds no slot itself, because every item takes its own and a batch holding one while its
/// items wait for one could deadlock a small pool.
pub async fn local_tool_unscheduled<T, F, Fut>(ctx: &AppContext, tool: &'static str, body: F) -> Result<ResultEnvelope<T>>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(T, Option<String>)>>,
{
    local_tool_with(ctx, tool, false, body).await
}

async fn local_tool_with<T, F, Fut>(ctx: &AppContext, tool: &'static str, scheduled: bool, body: F) -> Result<ResultEnvelope<T>>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(T, Option<String>)>>,
{
    let op = ctx.operations.begin(&ctx.principal, None, tool, Effect::Read);
    let _link = link_caller_cancel(ctx, &op.id);
    let result = async {
        let _slot = match scheduled {
            true => Some(tokio::select! {
                p = ctx.scheduler.acquire_local() => p?,
                _ = op.cancel.cancelled() => return Err(cancelled_while_queued()),
            }),
            false => None,
        };
        ctx.operations.mark_running(&op.id);
        // Work this tool starts (a batch's items) is cancelled with it.
        crate::tools::cancelled_by(op.cancel.clone(), body()).await
    }
    .await;
    match result {
        Ok((data, cursor)) => {
            ctx.operations.finish_ok(&op.id, None);
            let mut env = ResultEnvelope::succeeded(op.id.clone(), None, data).with_evidence(tool, EvidenceSource::Observer);
            env.next_cursor = cursor;
            Ok(env)
        }
        Err(e) => {
            ctx.operations.finish_err(&op.id, &e);
            Err(e.with_operation(op.id.as_str()))
        }
    }
}

/// Maps a remote I/O failure to a fixed message. Raw stderr (absolute paths, account details) goes to the local log only.
pub fn remote_failure(stderr: &[u8]) -> SentinelError {
    let s = String::from_utf8_lossy(stderr);
    if s.contains("No such file or directory") {
        SentinelError::new(ErrorCode::NotFound, "path not found")
    } else if s.contains("Permission denied") {
        SentinelError::new(
            ErrorCode::RemoteFailure,
            "the SSH account cannot read this path (permission denied)",
        )
    } else {
        tracing::warn!(stderr = %first_line(stderr), "remote command failed");
        SentinelError::new(ErrorCode::RemoteFailure, "remote command failed; details are in the gateway log")
    }
}

/// True when stderr reports that a file could not be opened or read, whatever the pipeline's exit status.
pub fn has_io_error(stderr: &[u8]) -> bool {
    let s = String::from_utf8_lossy(stderr);
    [
        "Permission denied",
        "cannot open",
        "No such file or directory",
        "Input/output error",
        "Is a directory",
    ]
    .iter()
    .any(|m| s.contains(m))
}
