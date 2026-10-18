//! `ssh_hosts_list` and `ssh_host_inspect` (spec §7.1 #1-2).

use schemars::JsonSchema;
use sentinel_core::effect::Effect;
use sentinel_core::envelope::ResultEnvelope;
use sentinel_core::error::{ErrorCode, Result, SentinelError};
use sentinel_core::policy::{HostPolicy, ResourceRef};
use sentinel_core::scope::display_escape;
use serde::{Deserialize, Serialize};

use crate::mcp::results::Detail;
use crate::ssh::command::{Marker, RemoteCommand};
use crate::tools::pipeline::{local_tool, read_tool};
use crate::tools::{AppContext, bounded};

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostsListParams {
    /// Return hosts after this host_id (from a previous `next_cursor`).
    pub cursor: Option<String>,
    /// 1-100, default 50.
    pub limit: Option<u32>,
    pub detail: Option<Detail>,
}

/// What an agent may know about a host: ids and registered resource names, never addresses, users or keys.
#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct HostSummary {
    pub host_id: String,
    pub environment: String,
    pub roots: Vec<String>,
    pub export_roots: Vec<String>,
    pub services: Vec<String>,
    pub log_sources: Vec<String>,
    pub health_checks: Vec<String>,
}

impl HostSummary {
    pub fn from_policy(h: &HostPolicy) -> Self {
        Self {
            host_id: h.host_id.to_string(),
            environment: h.environment.clone(),
            roots: h.roots.values().filter(|r| r.read).map(|r| r.alias.clone()).collect(),
            export_roots: h.roots.values().filter(|r| r.read && r.export).map(|r| r.alias.clone()).collect(),
            services: h.services.iter().cloned().collect(),
            log_sources: h.log_sources.iter().cloned().collect(),
            health_checks: h.health_checks.iter().cloned().collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct HostsListData {
    pub hosts: Vec<HostSummary>,
}

pub async fn ssh_hosts_list(ctx: &AppContext, p: HostsListParams) -> Result<ResultEnvelope<HostsListData>> {
    let limit = bounded(p.limit, 50, 100, "limit")? as usize;
    local_tool(ctx, "ssh_hosts_list", || async move {
        let visible = ctx.policy.visible_hosts(&ctx.principal);
        let after: Vec<&HostPolicy> = visible
            .into_iter()
            .filter(|h| p.cursor.as_deref().is_none_or(|c| h.host_id.as_str() > c))
            .collect();
        let more = after.len() > limit;
        let hosts: Vec<HostSummary> = after.into_iter().take(limit).map(HostSummary::from_policy).collect();
        let cursor = if more { hosts.last().map(|h| h.host_id.clone()) } else { None };
        Ok((HostsListData { hosts }, cursor))
    })
    .await
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostInspectParams {
    pub host_id: String,
    pub detail: Option<Detail>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct HostFacts {
    pub hostname: String,
    pub kernel: String,
    pub arch: String,
    pub cpus: u32,
    pub load_1m: f64,
    pub load_5m: f64,
    pub load_15m: f64,
    pub mem_total_bytes: u64,
    pub mem_available_bytes: u64,
    pub uptime_seconds: u64,
    pub os_pretty_name: Option<String>,
    /// Every string above came from the host.
    pub content_trust: &'static str,
}

fn command(mk: &Marker) -> RemoteCommand {
    RemoteCommand::new("uname")
        .flag("-srm")
        .then(mk.cmd())
        .then(RemoteCommand::new("nproc"))
        .then(mk.cmd())
        .then(RemoteCommand::new("cat").arg("/proc/loadavg"))
        .then(mk.cmd())
        .then(RemoteCommand::new("free").flag("-b"))
        .then(mk.cmd())
        .then(RemoteCommand::new("cat").arg("/proc/uptime"))
        .then(mk.cmd())
        .then(RemoteCommand::new("hostname"))
        .then(mk.cmd())
        .then(RemoteCommand::new("cat").arg("/etc/os-release"))
}

fn parse_err(what: &str) -> SentinelError {
    SentinelError::new(ErrorCode::RemoteFailure, format!("unexpected remote output: {what}"))
}

pub fn parse_host_facts(mk: &Marker, text: &str) -> Result<HostFacts> {
    let s = mk.sections(text);
    if s.len() < 6 {
        return Err(parse_err("host facts sections missing"));
    }
    let uname: Vec<&str> = s[0].split_whitespace().collect();
    let (kernel, arch) = match uname.as_slice() {
        [os, rel, arch, ..] => (display_escape(&format!("{os} {rel}")), display_escape(arch)),
        _ => return Err(parse_err("uname")),
    };
    let cpus = s[1].trim().parse().map_err(|_| parse_err("nproc"))?;
    let load: Vec<f64> = s[2].split_whitespace().take(3).filter_map(|x| x.parse().ok()).collect();
    let [load_1m, load_5m, load_15m] = load.as_slice() else {
        return Err(parse_err("loadavg"));
    };
    let mem: Vec<u64> = s[3]
        .lines()
        .find(|l| l.starts_with("Mem:"))
        .ok_or_else(|| parse_err("free"))?
        .split_whitespace()
        .skip(1)
        .filter_map(|x| x.parse().ok())
        .collect();
    let (mem_total_bytes, mem_available_bytes) = match mem.as_slice() {
        [total, _, _, _, _, available, ..] => (*total, *available),
        _ => return Err(parse_err("free columns")),
    };
    let uptime_seconds = s[4]
        .split_whitespace()
        .next()
        .and_then(|x| x.parse::<f64>().ok())
        .ok_or_else(|| parse_err("uptime"))? as u64;
    let os_pretty_name = s.get(6).and_then(|os| {
        os.lines()
            .find_map(|l| l.strip_prefix("PRETTY_NAME="))
            .map(|v| display_escape(v.trim_matches('"')))
    });
    Ok(HostFacts {
        hostname: display_escape(s[5].trim()),
        kernel,
        arch,
        cpus,
        load_1m: *load_1m,
        load_5m: *load_5m,
        load_15m: *load_15m,
        mem_total_bytes,
        mem_available_bytes,
        uptime_seconds,
        os_pretty_name,
        content_trust: crate::tools::UNTRUSTED,
    })
}

pub async fn ssh_host_inspect(ctx: &AppContext, p: HostInspectParams) -> Result<ResultEnvelope<HostFacts>> {
    read_tool(
        ctx,
        "ssh_host_inspect",
        &p.host_id,
        ResourceRef::Host,
        Effect::Read,
        |run| async move {
            let mk = Marker::new();
            let out = run.run(&command(&mk)).await?;
            parse_host_facts(&mk, &run.text_lossy(&out.stdout))
        },
    )
    .await
}
