//! `ssh_health_check` (spec §7.1 #3): runs an operator-registered check from the host. No agent-supplied URL or code.

use schemars::JsonSchema;
use sentinel_core::effect::Effect;
use sentinel_core::envelope::ResultEnvelope;
use sentinel_core::error::{ErrorCode, Result, SentinelError};
use sentinel_core::policy::ResourceRef;
use serde::{Deserialize, Serialize};

use crate::config::HealthCheckConfig;
use crate::mcp::results::Detail;
use crate::ssh::backend::ExitKind;
use crate::ssh::command::RemoteCommand;
use crate::tools::AppContext;
use crate::tools::pipeline::read_tool;
use crate::tools::services::{service_config, systemctl};

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckParams {
    pub host_id: String,
    /// A health check id from `ssh_hosts_list`.
    pub check_id: String,
    pub detail: Option<Detail>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct HealthResult {
    pub check_id: String,
    pub kind: String,
    pub passing: bool,
    pub observation: serde_json::Value,
    /// The registered definition, so another observer can repeat the check (spec §6.3).
    pub definition: HealthCheckConfig,
}

pub async fn ssh_health_check(ctx: &AppContext, p: HealthCheckParams) -> Result<ResultEnvelope<HealthResult>> {
    let check_id = p.check_id.clone();
    read_tool(
        ctx,
        "ssh_health_check",
        &p.host_id,
        ResourceRef::HealthCheck(&check_id),
        Effect::Read,
        |run| async move {
            let def = run
                .host
                .health_checks
                .get(&p.check_id)
                .cloned()
                .ok_or_else(|| SentinelError::new(ErrorCode::PolicyDenied, format!("unknown health check '{}'", p.check_id)))?;
            let (kind, passing, observation) = match &def {
                HealthCheckConfig::Http {
                    url,
                    expect_status,
                    timeout_secs,
                } => {
                    let cmd = RemoteCommand::new("curl")
                        // -q must come first: never read the remote account's ~/.curlrc.
                        .flag("-q")
                        .flag("-sS")
                        .flag("-o")
                        .arg("/dev/null")
                        .flag("-w")
                        .arg("%{http_code}")
                        .flag("--max-time")
                        .num(*timeout_secs)
                        .flag("--")
                        .arg(url);
                    let out = run.run(&cmd).await?;
                    let status: u16 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap_or(0);
                    let mut obs = serde_json::json!({ "status_code": status });
                    if let ExitKind::Code(c) = out.exit
                        && c != 0
                    {
                        obs["curl_exit"] = c.into();
                        obs["error"] = sentinel_core::scope::display_escape(
                            &String::from_utf8_lossy(&out.stderr).trim().chars().take(300).collect::<String>(),
                        )
                        .into();
                        obs["content_trust"] = crate::tools::UNTRUSTED.into();
                    }
                    ("http", status == *expect_status && out.exit == ExitKind::Code(0), obs)
                }
                HealthCheckConfig::ServiceActive { service } => {
                    let svc = service_config(&run.ctx, run.host.id.as_str(), service)?.clone();
                    let out = run.run(&systemctl(&svc).flag("is-active").flag("--").arg(&svc.unit)).await?;
                    let state = String::from_utf8_lossy(&out.stdout).trim().to_owned();
                    ("service_active", state == "active", serde_json::json!({ "active_state": state }))
                }
            };
            Ok(HealthResult {
                check_id: p.check_id,
                kind: kind.into(),
                passing,
                observation,
                definition: def,
            })
        },
    )
    .await
}
