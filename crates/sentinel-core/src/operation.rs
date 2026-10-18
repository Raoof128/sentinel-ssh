//! Operation state machine (spec §10.1).

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::effect::Effect;
use crate::error::{ErrorCode, Result, SentinelError};
use crate::identity::{ArtifactId, HostId, OperationId, PrincipalId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Received,
    Authorised,
    Rejected,
    AwaitingApproval,
    Queued,
    Running,
    Verifying,
    Succeeded,
    Failed,
    CancelRequested,
    Cancelled,
    OutcomeUnknown,
}

impl OperationState {
    pub const ALL: [OperationState; 12] = [
        Self::Received,
        Self::Authorised,
        Self::Rejected,
        Self::AwaitingApproval,
        Self::Queued,
        Self::Running,
        Self::Verifying,
        Self::Succeeded,
        Self::Failed,
        Self::CancelRequested,
        Self::Cancelled,
        Self::OutcomeUnknown,
    ];

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Rejected | Self::Succeeded | Self::Failed | Self::Cancelled | Self::OutcomeUnknown
        )
    }
}

/// Whether a stopped operation is known to have stopped on the remote host (spec §10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RemoteTermination {
    Confirmed,
    Unconfirmed,
    Unknown,
    NotApplicable,
}

pub fn legal_transition(from: OperationState, to: OperationState) -> bool {
    use OperationState::*;
    matches!(
        (from, to),
        (Received, Authorised | Rejected)
            | (Authorised, Queued | AwaitingApproval | Rejected)
            | (AwaitingApproval, Queued | Rejected)
            | (Queued, Running | CancelRequested)
            | (Running, Verifying | Succeeded | Failed | OutcomeUnknown | CancelRequested)
            | (Verifying, Succeeded | Failed | OutcomeUnknown)
            | (CancelRequested, Cancelled | OutcomeUnknown | Succeeded | Failed)
    )
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OperationRecord {
    pub id: OperationId,
    pub principal: PrincipalId,
    pub host_id: Option<HostId>,
    pub tool: String,
    pub effect: Effect,
    pub state: OperationState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub remote_termination: RemoteTermination,
    pub error: Option<SentinelError>,
    pub result_artifact: Option<ArtifactId>,
}

impl OperationRecord {
    pub fn new(principal: PrincipalId, host_id: Option<HostId>, tool: &str, effect: Effect) -> Self {
        let now = Utc::now();
        Self {
            id: OperationId::generate(),
            principal,
            host_id,
            tool: tool.to_owned(),
            effect,
            state: OperationState::Received,
            created_at: now,
            updated_at: now,
            finished_at: None,
            remote_termination: RemoteTermination::NotApplicable,
            error: None,
            result_artifact: None,
        }
    }

    pub fn transition(&mut self, to: OperationState) -> Result<()> {
        if !legal_transition(self.state, to) {
            return Err(SentinelError::new(
                ErrorCode::Internal,
                format!("illegal operation transition {:?} -> {:?}", self.state, to),
            )
            .with_operation(self.id.as_str()));
        }
        let now = Utc::now();
        self.state = to;
        self.updated_at = now;
        if to.is_terminal() {
            self.finished_at = Some(now);
        }
        Ok(())
    }

    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }
}
