//! The wire form of every tool result (spec §6.3, §6.4, §11.3): bounded in size, with oversized data moved to a private
//! artefact, and failures carried as typed envelopes rather than protocol errors.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use sentinel_core::envelope::{Evidence, Outcome, ResultEnvelope, SCHEMA_VERSION};
use sentinel_core::error::{ErrorCode, Result, RetryStrategy, SentinelError};
use sentinel_core::identity::{ArtifactId, HostId, OperationId, PrincipalId};
use serde::{Deserialize, Serialize};

use crate::artifacts::{ArtifactOrigin, ArtifactStore, ContentKind};
use crate::config::Budgets;

/// Room left for the envelope's own fields when sizing a preview.
const ENVELOPE_OVERHEAD: usize = 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Detail {
    /// Up to 8 KiB inline (default).
    #[default]
    Concise,
    /// Up to 64 KiB inline.
    Full,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct BoundedEnvelope<T> {
    pub schema_version: String,
    pub host_id: Option<HostId>,
    pub operation_id: OperationId,
    pub outcome: Outcome,
    pub observed_at: DateTime<Utc>,
    /// `None` when the result was truncated to an artefact or the call failed.
    pub data: Option<T>,
    /// Start of the pretty-printed data when truncated.
    pub data_preview: Option<String>,
    /// Present when the outcome is failed, cancelled or outcome_unknown.
    pub error: Option<SentinelError>,
    pub truncated: bool,
    /// Holds the complete envelope when truncated; read it with `ssh_artifact_read`.
    pub artifact_id: Option<ArtifactId>,
    pub next_cursor: Option<String>,
    pub evidence: Vec<Evidence>,
    pub retry: RetryStrategy,
    pub warnings: Vec<String>,
}

fn from_parts<T>(env: ResultEnvelope<()>, data: Option<T>) -> BoundedEnvelope<T> {
    BoundedEnvelope {
        schema_version: env.schema_version,
        host_id: env.host_id,
        operation_id: env.operation_id,
        outcome: env.outcome,
        observed_at: env.observed_at,
        data,
        data_preview: None,
        error: None,
        truncated: env.truncated,
        artifact_id: env.artifact_id,
        next_cursor: env.next_cursor,
        evidence: env.evidence,
        retry: env.retry,
        warnings: env.warnings,
    }
}

fn split<T>(env: ResultEnvelope<T>) -> (ResultEnvelope<()>, T) {
    let ResultEnvelope {
        schema_version,
        host_id,
        operation_id,
        outcome,
        observed_at,
        data,
        truncated,
        artifact_id,
        next_cursor,
        evidence,
        retry,
        warnings,
    } = env;
    (
        ResultEnvelope {
            schema_version,
            host_id,
            operation_id,
            outcome,
            observed_at,
            data: (),
            truncated,
            artifact_id,
            next_cursor,
            evidence,
            retry,
            warnings,
        },
        data,
    )
}

/// Warnings are short fixed codes; more than this many means something is looping, and they must not break the bound.
pub const MAX_WARNINGS: usize = 16;

fn cap_warnings(w: &mut Vec<String>) {
    if w.len() > MAX_WARNINGS {
        w.truncate(MAX_WARNINGS);
        w.push("warnings_truncated".into());
    }
}

fn cut(s: &str, max: usize) -> &str {
    let mut i = max.min(s.len());
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    &s[..i]
}

pub async fn bound_envelope<T: Serialize>(
    store: &ArtifactStore,
    owner: &PrincipalId,
    env: ResultEnvelope<T>,
    detail: Detail,
    b: &Budgets,
) -> Result<BoundedEnvelope<T>> {
    let limit = match detail {
        Detail::Concise => b.default_result_bytes,
        Detail::Full => b.max_result_bytes,
    };
    let mut env = env;
    cap_warnings(&mut env.warnings);
    let full = serde_json::to_vec(&env).map_err(|e| SentinelError::new(ErrorCode::Internal, format!("serialising result: {e}")))?;
    let (head, data) = split(env);
    if full.len() <= limit {
        return Ok(from_parts(head, Some(data)));
    }
    let pretty_data = serde_json::to_string_pretty(&data).unwrap_or_default();
    let pretty_full = {
        let mut v = serde_json::to_value(&head).unwrap_or_default();
        v["data"] = serde_json::from_str(&pretty_data).unwrap_or_default();
        serde_json::to_vec_pretty(&v).unwrap_or_default()
    };
    let rec = store
        .put_bytes(
            owner,
            ArtifactOrigin::ToolResult {
                operation_id: head.operation_id.clone(),
            },
            ContentKind::Json,
            &pretty_full,
        )
        .await?;
    let mut out: BoundedEnvelope<T> = from_parts(head, None);
    out.truncated = true;
    out.artifact_id = Some(rec.id);
    if !out.warnings.iter().any(|w| w == "result_truncated_see_artifact") {
        out.warnings.push("result_truncated_see_artifact".into());
    }
    // JSON escaping can grow the preview, so shrink until the whole envelope fits.
    let mut budget = limit.saturating_sub(ENVELOPE_OVERHEAD);
    loop {
        out.data_preview = Some(cut(&pretty_data, budget).to_owned());
        let size = serde_json::to_vec(&out).map(|v| v.len()).unwrap_or(usize::MAX);
        if size <= limit || budget == 0 {
            break;
        }
        budget = budget.saturating_sub(size - limit + 64);
    }
    Ok(out)
}

/// Like [`bound_envelope`] but never creates an artefact: used by `ssh_artifact_read`, where spilling a page of an
/// artefact into a new artefact would repeat without end. Over the limit is `BUDGET_EXCEEDED`.
pub fn bound_envelope_inline<T: Serialize>(env: ResultEnvelope<T>, detail: Detail, b: &Budgets) -> Result<BoundedEnvelope<T>> {
    let limit = match detail {
        Detail::Concise => b.default_result_bytes,
        Detail::Full => b.max_result_bytes,
    };
    let size = serde_json::to_vec(&env).map(|v| v.len()).unwrap_or(usize::MAX);
    if size > limit {
        return Err(SentinelError::new(
            ErrorCode::BudgetExceeded,
            format!("this page is {size} bytes as JSON, over the {limit} byte result limit; request a smaller length or detail=full"),
        ));
    }
    let (head, data) = split(env);
    Ok(from_parts(head, Some(data)))
}

pub fn failed_envelope<T>(operation_id: OperationId, host_id: Option<HostId>, err: SentinelError) -> BoundedEnvelope<T> {
    let cancelled = err.details.get("cancelled").and_then(|v| v.as_bool()) == Some(true);
    let outcome = match err.code {
        ErrorCode::OutcomeUnknown => Outcome::OutcomeUnknown,
        _ if cancelled => Outcome::Cancelled,
        _ => Outcome::Failed,
    };
    BoundedEnvelope {
        schema_version: SCHEMA_VERSION.to_owned(),
        host_id,
        operation_id,
        outcome,
        observed_at: Utc::now(),
        data: None,
        data_preview: None,
        retry: err.retry.clone(),
        error: Some(err),
        truncated: false,
        artifact_id: None,
        next_cursor: None,
        evidence: Vec::new(),
        warnings: Vec::new(),
    }
}
