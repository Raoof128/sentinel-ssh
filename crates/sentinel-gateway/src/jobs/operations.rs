//! In-memory operation registry (ADR-001 Decision 3). Operations are visible only to the principal that created them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use sentinel_core::effect::Effect;
use sentinel_core::error::{ErrorCode, Result, SentinelError};
use sentinel_core::identity::{ArtifactId, HostId, OperationId, Principal};
use sentinel_core::operation::{OperationRecord, OperationState, RemoteTermination};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub struct RunningOp {
    pub id: OperationId,
    pub cancel: CancellationToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancelOutcome {
    pub state: OperationState,
    pub remote_termination: RemoteTermination,
}

#[derive(Debug, Clone, Default)]
pub struct Operations {
    inner: Arc<Mutex<HashMap<OperationId, (OperationRecord, CancellationToken)>>>,
}

fn not_found() -> SentinelError {
    SentinelError::new(ErrorCode::NotFound, "operation not found")
}

impl Operations {
    pub fn new() -> Self {
        Self::default()
    }

    fn with<R>(&self, id: &OperationId, f: impl FnOnce(&mut OperationRecord, &CancellationToken) -> R) -> Option<R> {
        let mut m = self.inner.lock().expect("operations");
        m.get_mut(id).map(|(r, t)| f(r, t))
    }

    /// Records a new authorised operation: Received → Authorised → Queued.
    pub fn begin(&self, principal: &Principal, host: Option<&HostId>, tool: &str, effect: Effect) -> RunningOp {
        let mut rec = OperationRecord::new(principal.id.clone(), host.cloned(), tool, effect);
        rec.transition(OperationState::Authorised).expect("legal");
        rec.transition(OperationState::Queued).expect("legal");
        let token = CancellationToken::new();
        let id = rec.id.clone();
        self.inner.lock().expect("operations").insert(id.clone(), (rec, token.clone()));
        RunningOp { id, cancel: token }
    }

    /// Records a request refused by policy: Received → Rejected (spec §10.1: a rejection is distinct from a failure).
    pub fn begin_rejected(
        &self,
        principal: &Principal,
        host: Option<&HostId>,
        tool: &str,
        effect: Effect,
        err: &SentinelError,
    ) -> OperationId {
        let mut rec = OperationRecord::new(principal.id.clone(), host.cloned(), tool, effect);
        rec.transition(OperationState::Rejected).expect("legal");
        rec.error = Some(err.clone());
        let id = rec.id.clone();
        self.inner
            .lock()
            .expect("operations")
            .insert(id.clone(), (rec, CancellationToken::new()));
        id
    }

    pub fn mark_running(&self, id: &OperationId) {
        self.with(id, |r, _| {
            let _ = r.transition(OperationState::Running);
        });
    }

    pub fn finish_ok(&self, id: &OperationId, artifact: Option<ArtifactId>) {
        self.with(id, |r, _| {
            r.result_artifact = artifact;
            let _ = r.transition(OperationState::Succeeded);
        });
    }

    pub fn finish_err(&self, id: &OperationId, err: &SentinelError) {
        self.with(id, |r, _| {
            let cancelled = err.details.get("cancelled").and_then(|v| v.as_bool()) == Some(true);
            let to = if err.code == ErrorCode::OutcomeUnknown {
                OperationState::OutcomeUnknown
            } else if cancelled && r.state == OperationState::CancelRequested {
                OperationState::Cancelled
            } else {
                OperationState::Failed
            };
            r.remote_termination = if cancelled || err.code == ErrorCode::Timeout || err.details.get("remote_termination").is_some() {
                RemoteTermination::Unconfirmed
            } else {
                RemoteTermination::NotApplicable
            };
            r.error = Some(err.clone());
            if r.transition(to).is_err() {
                let _ = r.transition(OperationState::Failed);
            }
        });
    }

    pub fn get(&self, principal: &Principal, id: &OperationId) -> Result<OperationRecord> {
        let m = self.inner.lock().expect("operations");
        match m.get(id) {
            Some((r, _)) if r.principal == principal.id => Ok(r.clone()),
            _ => Err(not_found()),
        }
    }

    /// Owner-only. Queued or Running → CancelRequested and the token fires; terminal operations are returned unchanged.
    pub fn cancel(&self, principal: &Principal, id: &OperationId) -> Result<CancelOutcome> {
        let mut m = self.inner.lock().expect("operations");
        let Some((r, token)) = m.get_mut(id).filter(|(r, _)| r.principal == principal.id) else {
            return Err(not_found());
        };
        if matches!(r.state, OperationState::Queued | OperationState::Running) {
            r.transition(OperationState::CancelRequested)?;
            token.cancel();
        }
        Ok(CancelOutcome {
            state: r.state,
            remote_termination: r.remote_termination,
        })
    }

    /// Drops terminal operations that finished more than `older_than` ago. Returns how many were removed.
    pub fn sweep_finished(&self, older_than: Duration) -> usize {
        let cutoff = Utc::now() - chrono::Duration::from_std(older_than).unwrap_or(chrono::Duration::zero());
        let mut m = self.inner.lock().expect("operations");
        let before = m.len();
        m.retain(|_, (r, _)| !(r.is_terminal() && r.finished_at.is_some_and(|f| f <= cutoff)));
        before - m.len()
    }
}
