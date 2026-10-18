//! `ssh_disk_usage` (spec §7.1 #4): filesystem capacity plus scoped directory usage with capped depth and entries.

use schemars::JsonSchema;
use sentinel_core::effect::Effect;
use sentinel_core::envelope::ResultEnvelope;
use sentinel_core::error::{ErrorCode, Result, SentinelError};
use sentinel_core::policy::ResourceRef;
use sentinel_core::scope::{display_escape, resolve_scoped};
use serde::{Deserialize, Serialize};

use crate::mcp::results::Detail;
use crate::ssh::command::RemoteCommand;
use crate::tools::pipeline::{read_tool, sections};
use crate::tools::{AppContext, bounded};

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiskUsageParams {
    pub host_id: String,
    /// A root alias from `ssh_hosts_list`.
    pub root: String,
    /// Path relative to the root; default the root itself.
    pub path: Option<String>,
    /// 1-3, default 1.
    pub depth: Option<u8>,
    /// 1-200, default 50.
    pub max_entries: Option<u32>,
    pub detail: Option<Detail>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct FilesystemUsage {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub mount: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct DiskEntry {
    /// Relative to the root alias.
    pub path: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct DiskUsageData {
    pub root: String,
    pub path: String,
    pub filesystem: FilesystemUsage,
    /// Usage of the requested path itself.
    pub total_bytes: u64,
    /// Largest first, excluding the requested path itself.
    pub entries: Vec<DiskEntry>,
    pub entries_truncated: bool,
}

fn bad(what: &str) -> SentinelError {
    SentinelError::new(ErrorCode::RemoteFailure, format!("unexpected remote output: {what}"))
}

pub fn parse_df(text: &str) -> Result<FilesystemUsage> {
    let line = text
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty() && !l.starts_with("Filesystem"))
        .ok_or_else(|| bad("df"))?;
    let c: Vec<&str> = line.split_whitespace().collect();
    if c.len() < 6 {
        return Err(bad("df columns"));
    }
    let n = |i: usize| c[i].parse::<u64>().map_err(|_| bad("df number"));
    Ok(FilesystemUsage {
        total_bytes: n(1)?,
        used_bytes: n(2)?,
        available_bytes: n(3)?,
        mount: c[5..].join(" "),
    })
}

pub async fn ssh_disk_usage(ctx: &AppContext, p: DiskUsageParams) -> Result<ResultEnvelope<DiskUsageData>> {
    let depth = p.depth.unwrap_or(1);
    if !(1..=3).contains(&depth) {
        return Err(SentinelError::new(ErrorCode::InvalidInput, "depth must be between 1 and 3").with_detail("field", "depth"));
    }
    let max_entries = bounded(p.max_entries, 50, 200, "max_entries")? as usize;
    let root_alias = p.root.clone();
    read_tool(
        ctx,
        "ssh_disk_usage",
        &p.host_id,
        ResourceRef::Root(&root_alias),
        Effect::Read,
        |run| async move {
            let root = run.ctx.policy.root(&run.ctx.principal, &run.host.id, &p.root)?.clone();
            let target = resolve_scoped(&root, p.path.as_deref().unwrap_or(""))?;
            let cmd = RemoteCommand::new("df")
                .flag("-B1")
                .flag("-P")
                .flag("--")
                .arg(&target.absolute)
                .then(RemoteCommand::marker())
                .then(
                    RemoteCommand::new("du")
                        .flag("-x")
                        .flag("-P")
                        // Without -a, `du -d N` lists directories only and files never appear.
                        .flag("-a")
                        .flag("-B1")
                        .flag("-d")
                        .num(depth as u64)
                        .flag("--")
                        .arg(&target.absolute)
                        .pipe(RemoteCommand::new("sort").flag("-rn"))
                        .pipe(RemoteCommand::new("head").flag("-n").num(max_entries as u64 + 2)),
                );
            let out = run.run_guarded("directory", &target.absolute, cmd).await?;
            if String::from_utf8_lossy(&out.stderr).contains("Permission denied") {
                run.warn("partial_permission_denied");
            }
            let text = run.text_lossy(&out.stdout);
            let s = sections(&text);
            let filesystem = parse_df(s.first().copied().unwrap_or(""))?;
            let root_prefix = format!("{}/", root.path);
            let target_prefix = format!("{}/", target.absolute.trim_end_matches('/'));
            let mut total_bytes = 0;
            let mut entries = Vec::new();
            for line in s.get(1).copied().unwrap_or("").lines() {
                let Some((bytes, path)) = line.split_once('\t') else { continue };
                let Ok(bytes) = bytes.trim().parse::<u64>() else { continue };
                if path == target.absolute {
                    total_bytes = bytes;
                    continue;
                }
                // Only paths inside the requested directory; anything else is dropped, never shown raw.
                if !path.starts_with(&target_prefix) {
                    continue;
                }
                let Some(rel) = path.strip_prefix(&root_prefix) else { continue };
                entries.push(DiskEntry {
                    path: display_escape(rel),
                    bytes,
                });
            }
            let entries_truncated = entries.len() > max_entries;
            entries.truncate(max_entries);
            Ok(DiskUsageData {
                root: p.root,
                path: target.relative,
                filesystem,
                total_bytes,
                entries,
                entries_truncated,
            })
        },
    )
    .await
}
