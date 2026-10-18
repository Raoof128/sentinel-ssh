//! `ssh_operation_get` and `ssh_operation_cancel` (spec §7.1 #13-14). Owner-only; another principal's operation is
//! indistinguishable from an unknown id. Neither call creates an operation record of its own.

use schemars::JsonSchema;
use sentinel_core::envelope::{EvidenceSource, ResultEnvelope};
use sentinel_core::error::Result;
use sentinel_core::identity::OperationId;
use sentinel_core::operation::{OperationRecord, OperationState, RemoteTermination};
use serde::{Deserialize, Serialize};

use crate::mcp::results::Detail;
use crate::tools::AppContext;

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationGetParams {
    pub operation_id: String,
    pub detail: Option<Detail>,
}

pub async fn ssh_operation_get(ctx: &AppContext, p: OperationGetParams) -> Result<ResultEnvelope<OperationRecord>> {
    let id = OperationId::parse(&p.operation_id)?;
    let rec = ctx.operations.get(&ctx.principal, &id)?;
    Ok(ResultEnvelope::succeeded(id, rec.host_id.clone(), rec).with_evidence("operation_record", EvidenceSource::Observer))
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationCancelParams {
    pub operation_id: String,
    pub detail: Option<Detail>,
}

pub const CANCEL_NOTE: &str = "observer mode: the local ssh process was signalled; remote termination is not confirmed";

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct CancelData {
    pub operation_id: String,
    /// `cancel_requested` when the request reached a queued or running operation; otherwise its current terminal state.
    pub state: OperationState,
    pub remote_termination: RemoteTermination,
    pub note: &'static str,
}

pub async fn ssh_operation_cancel(ctx: &AppContext, p: OperationCancelParams) -> Result<ResultEnvelope<CancelData>> {
    let id = OperationId::parse(&p.operation_id)?;
    let c = ctx.operations.cancel(&ctx.principal, &id)?;
    let data = CancelData {
        operation_id: id.to_string(),
        state: c.state,
        remote_termination: c.remote_termination,
        note: CANCEL_NOTE,
    };
    Ok(ResultEnvelope::succeeded(id, None, data).with_evidence("cancel_request", EvidenceSource::Observer))
}
