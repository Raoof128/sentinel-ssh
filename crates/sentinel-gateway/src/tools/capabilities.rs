//! `ssh_capabilities_get` (spec §7.1 #16): what this gateway actually guarantees, including the weaker observer-mode limits.

use schemars::JsonSchema;
use sentinel_core::effect::Effect;
use sentinel_core::envelope::ResultEnvelope;
use sentinel_core::envelope::SCHEMA_VERSION;
use sentinel_core::error::Result;
use sentinel_core::identity::HostId;
use sentinel_core::operation::RemoteTermination;
use sentinel_core::policy::ResourceRef;
use serde::{Deserialize, Serialize};

use crate::config::Budgets;
use crate::mcp::results::Detail;
use crate::ssh::backend::BackendCapabilities;
use crate::tools::hosts::HostSummary;
use crate::tools::pipeline::local_tool;
use crate::tools::{AppContext, GUARANTEE_STATEMENT, SYMLINK_CONTAINMENT, TOOL_NAMES};

pub const PROTOCOL_VERSIONS: [&str; 2] = ["2026-07-28", "2025-11-25"];

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesParams {
    /// Also describe this host.
    pub host_id: Option<String>,
    pub detail: Option<Detail>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct Guarantees {
    /// False in observer mode: the SSH account itself is not restricted by the gateway.
    pub remote_enforcement: bool,
    pub remote_termination: RemoteTermination,
    pub statement: String,
    pub symlink_containment: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct CapabilitiesData {
    pub gateway_version: String,
    pub schema_version: String,
    pub protocol_versions: Vec<String>,
    pub mode: String,
    pub backend: BackendCapabilities,
    pub guarantees: Guarantees,
    pub tools: Vec<String>,
    pub limits: Budgets,
    pub host: Option<HostSummary>,
}

pub async fn ssh_capabilities_get(ctx: &AppContext, p: CapabilitiesParams) -> Result<ResultEnvelope<CapabilitiesData>> {
    let host = match &p.host_id {
        Some(id) => {
            let id = HostId::parse(id)?;
            ctx.policy
                .evaluate(&ctx.principal, Some(&id), &ResourceRef::Host, Effect::Read)
                .into_result()?;
            ctx.policy.host(&ctx.principal, &id).map(HostSummary::from_policy)
        }
        None => None,
    };
    local_tool(ctx, "ssh_capabilities_get", || async move {
        let backend = ctx.backend.capabilities();
        Ok((
            CapabilitiesData {
                gateway_version: env!("CARGO_PKG_VERSION").into(),
                schema_version: SCHEMA_VERSION.into(),
                protocol_versions: PROTOCOL_VERSIONS.iter().map(|s| s.to_string()).collect(),
                mode: "observer".into(),
                guarantees: Guarantees {
                    remote_enforcement: false,
                    remote_termination: backend.remote_termination,
                    statement: GUARANTEE_STATEMENT.into(),
                    symlink_containment: SYMLINK_CONTAINMENT.into(),
                },
                backend,
                tools: TOOL_NAMES.iter().map(|s| s.to_string()).collect(),
                limits: ctx.config.gateway.budgets.clone(),
                host,
            },
            None,
        ))
    })
    .await
}
