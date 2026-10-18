//! Effect labels (spec §7). An effect is what a tool call does to the world, independent of which tool performs it.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// No intended remote application mutation.
    Read,
    /// Moves confidential information to a new trust boundary.
    Export,
    /// Changes gateway or job state, or stops an owned operation.
    Control,
    /// Creates a proposal.
    Plan,
    /// Writes isolated staging storage.
    Stage,
    /// Can modify an approved remote resource.
    Change,
}
