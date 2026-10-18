//! The typed error contract (spec §6.5, §7.3.3). Every refusal or failure an agent can see is one of these codes.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    // §6.5
    HostKeyChanged,
    PolicyDenied,
    ApprovalRequired,
    StalePlan,
    CapabilityUnsupported,
    OutcomeUnknown,
    BudgetExceeded,
    ResumeUnverifiable,
    DestinationExists,
    DigestMismatch,
    SyncConflict,
    ArtifactExpired,
    // §7.3.3
    SourceChanged,
    DiskFull,
    TransferTimeoutIdle,
    TransferTimeoutTotal,
    TransferPartial,
    ExportNotAllowed,
    // gateway
    InvalidInput,
    NotFound,
    Timeout,
    ConnectionFailed,
    AuthenticationFailed,
    RemoteFailure,
    NotUtf8,
    ConfigInvalid,
    Internal,
}

impl ErrorCode {
    /// The "safe next step" column of spec §6.5, as a machine-readable strategy.
    pub fn default_retry(self) -> RetryStrategy {
        use ErrorCode::*;
        match self {
            OutcomeUnknown | TransferPartial => RetryStrategy::Reconcile,
            StalePlan | SyncConflict | SourceChanged | ResumeUnverifiable => RetryStrategy::Replan,
            BudgetExceeded | InvalidInput => RetryStrategy::NarrowRequest,
            ConnectionFailed | TransferTimeoutIdle => RetryStrategy::RetryAfter { seconds: 5 },
            _ => RetryStrategy::Never,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "strategy", rename_all = "snake_case")]
pub enum RetryStrategy {
    Never,
    Reconcile,
    Replan,
    NarrowRequest,
    RetryAfter { seconds: u32 },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct SentinelError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    pub retry: RetryStrategy,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub details: Map<String, Value>,
}

impl SentinelError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            operation_id: None,
            retry: code.default_retry(),
            details: Map::new(),
        }
    }

    pub fn with_operation(mut self, id: impl Into<String>) -> Self {
        self.operation_id = Some(id.into());
        self
    }

    pub fn with_detail(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.details.insert(key.to_owned(), value.into());
        self
    }

    pub fn with_retry(mut self, retry: RetryStrategy) -> Self {
        self.retry = retry;
        self
    }
}

pub type Result<T> = std::result::Result<T, SentinelError>;
