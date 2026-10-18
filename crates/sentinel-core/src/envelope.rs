//! The result envelope every tool returns (spec §6.3).

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::RetryStrategy;
use crate::identity::{ArtifactId, HostId, OperationId};

pub const SCHEMA_VERSION: &str = "1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Succeeded,
    Failed,
    Partial,
    Cancelled,
    OutcomeUnknown,
}

/// Who observed a fact. Observer-mode evidence comes from a gateway-issued command over the SSH account, not from a host-side broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Observer,
    Broker,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Evidence {
    pub kind: String,
    pub source: EvidenceSource,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResultEnvelope<T> {
    pub schema_version: String,
    pub host_id: Option<HostId>,
    pub operation_id: OperationId,
    pub outcome: Outcome,
    pub observed_at: DateTime<Utc>,
    pub data: T,
    pub truncated: bool,
    pub artifact_id: Option<ArtifactId>,
    pub next_cursor: Option<String>,
    pub evidence: Vec<Evidence>,
    pub retry: RetryStrategy,
    pub warnings: Vec<String>,
}

impl<T> ResultEnvelope<T> {
    pub fn succeeded(operation_id: OperationId, host_id: Option<HostId>, data: T) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            host_id,
            operation_id,
            outcome: Outcome::Succeeded,
            observed_at: Utc::now(),
            data,
            truncated: false,
            artifact_id: None,
            next_cursor: None,
            evidence: Vec::new(),
            retry: RetryStrategy::Never,
            warnings: Vec::new(),
        }
    }

    pub fn with_evidence(mut self, kind: &str, source: EvidenceSource) -> Self {
        self.evidence.push(Evidence {
            kind: kind.to_owned(),
            source,
            observed_at: Utc::now(),
        });
        self
    }

    pub fn warn(mut self, w: &str) -> Self {
        if !self.warnings.iter().any(|x| x == w) {
            self.warnings.push(w.to_owned());
        }
        self
    }
}
