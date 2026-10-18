//! `ssh_service_status` (spec §7.1 #6): a registered service id, never an agent-chosen unit or systemctl flag.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use sentinel_core::effect::Effect;
use sentinel_core::envelope::ResultEnvelope;
use sentinel_core::error::{ErrorCode, Result, SentinelError};
use sentinel_core::policy::ResourceRef;
use serde::{Deserialize, Serialize};

use crate::config::{ServiceConfig, UnitScope};
use crate::mcp::results::Detail;
use crate::ssh::command::RemoteCommand;
use crate::tools::AppContext;
use crate::tools::pipeline::read_tool;

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceStatusParams {
    pub host_id: String,
    /// A service id from `ssh_hosts_list`.
    pub service_id: String,
    pub detail: Option<Detail>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct ServiceState {
    pub service_id: String,
    pub unit: String,
    pub scope: UnitScope,
    pub active_state: String,
    pub sub_state: String,
    pub load_state: String,
    pub result: String,
    pub main_pid: u32,
    pub n_restarts: u32,
    pub active_enter_timestamp: Option<String>,
}

/// `systemctl [--user] <verb> ...` for a registered unit.
pub(crate) fn systemctl(svc: &ServiceConfig) -> RemoteCommand {
    let c = RemoteCommand::new("systemctl");
    match svc.scope {
        UnitScope::System => c,
        UnitScope::User => c.flag("--user"),
    }
}

pub(crate) fn service_config<'a>(ctx: &'a AppContext, host_id: &str, service_id: &str) -> Result<&'a ServiceConfig> {
    ctx.config
        .hosts
        .iter()
        .find(|h| h.id.as_str() == host_id)
        .and_then(|h| h.services.get(service_id))
        .ok_or_else(|| SentinelError::new(ErrorCode::PolicyDenied, format!("unknown service '{service_id}'")))
}

/// `systemctl show -p …` prints properties in an arbitrary order, so parse as key=value.
pub fn parse_show(text: &str) -> BTreeMap<&str, &str> {
    text.lines().filter_map(|l| l.split_once('=')).collect()
}

pub async fn ssh_service_status(ctx: &AppContext, p: ServiceStatusParams) -> Result<ResultEnvelope<ServiceState>> {
    let (service_id, host_id) = (p.service_id.clone(), p.host_id.clone());
    read_tool(
        ctx,
        "ssh_service_status",
        &host_id,
        ResourceRef::Service(&service_id),
        Effect::Read,
        |run| async move {
            let svc = service_config(&run.ctx, run.host.id.as_str(), &p.service_id)?.clone();
            let cmd = systemctl(&svc)
                .flag("show")
                .flag("--no-pager")
                .flag("-p")
                .flag("Id,ActiveState,SubState,LoadState,Result,MainPID,NRestarts,ActiveEnterTimestamp")
                .flag("--")
                .arg(&svc.unit);
            let out = run.run(&cmd).await?;
            let text = run.text_lossy(&out.stdout);
            let m = parse_show(&text);
            if m.is_empty() {
                return Err(SentinelError::new(ErrorCode::RemoteFailure, "systemctl returned no properties"));
            }
            let get = |k: &str| m.get(k).copied().unwrap_or("").to_owned();
            Ok(ServiceState {
                service_id: p.service_id,
                unit: svc.unit,
                scope: svc.scope,
                active_state: get("ActiveState"),
                sub_state: get("SubState"),
                load_state: get("LoadState"),
                result: get("Result"),
                main_pid: get("MainPID").parse().unwrap_or(0),
                n_restarts: get("NRestarts").parse().unwrap_or(0),
                active_enter_timestamp: Some(get("ActiveEnterTimestamp")).filter(|s| !s.is_empty()),
            })
        },
    )
    .await
}
