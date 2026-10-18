//! `ssh_batch_inspect` (spec §7.1 #12, §6.4): up to 16 typed read operations in one call. Each item goes through the
//! normal pipeline, so it is separately validated, authorised and recorded. Never an arbitrary command runner.

use std::collections::BTreeSet;
use std::sync::Arc;

use schemars::JsonSchema;
use sentinel_core::envelope::{Outcome, ResultEnvelope};
use sentinel_core::error::{ErrorCode, Result, SentinelError};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::mcp::results::Detail;
use crate::tools::pipeline::local_tool_unscheduled;
use crate::tools::{AppContext, capabilities, disk, files, health, hosts, logs, processes, services};

/// Tools a batch item may name. Control, export and batch itself are excluded.
pub const BATCHABLE: [&str; 11] = [
    "ssh_capabilities_get",
    "ssh_disk_usage",
    "ssh_file_hash",
    "ssh_file_read",
    "ssh_file_stat",
    "ssh_files_list",
    "ssh_health_check",
    "ssh_host_inspect",
    "ssh_logs_search",
    "ssh_process_list",
    "ssh_service_status",
];
const ITEM_CONCURRENCY: usize = 4;

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchItem {
    /// Caller-chosen id, unique in the batch: ^[A-Za-z0-9_-]{1,32}$.
    pub id: String,
    /// One of the batchable read tools.
    pub tool: String,
    /// That tool's parameters.
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchInspectParams {
    /// 1-16 items.
    pub items: Vec<BatchItem>,
    pub detail: Option<Detail>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BatchItemResult {
    Ok { id: String, result: serde_json::Value },
    Error { id: String, error: SentinelError },
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct BatchInspectData {
    pub items: Vec<BatchItemResult>,
    pub ok_count: u32,
    pub error_count: u32,
}

fn invalid(msg: impl Into<String>) -> SentinelError {
    SentinelError::new(ErrorCode::InvalidInput, msg).with_detail("field", "items")
}

fn valid_item_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn params<P: DeserializeOwned>(v: serde_json::Value) -> Result<P> {
    let v = if v.is_null() { serde_json::json!({}) } else { v };
    serde_json::from_value(v).map_err(|e| SentinelError::new(ErrorCode::InvalidInput, format!("invalid params: {e}")))
}

fn to_value<T: Serialize>(r: Result<ResultEnvelope<T>>) -> Result<serde_json::Value> {
    r.map(|env| serde_json::to_value(env).expect("envelope serialises"))
}

async fn dispatch(ctx: &AppContext, tool: &str, p: serde_json::Value) -> Result<serde_json::Value> {
    match tool {
        "ssh_capabilities_get" => to_value(capabilities::ssh_capabilities_get(ctx, params(p)?).await),
        "ssh_disk_usage" => to_value(disk::ssh_disk_usage(ctx, params(p)?).await),
        "ssh_file_hash" => to_value(files::ssh_file_hash(ctx, params(p)?).await),
        "ssh_file_read" => to_value(files::ssh_file_read(ctx, params(p)?).await),
        "ssh_file_stat" => to_value(files::ssh_file_stat(ctx, params(p)?).await),
        "ssh_files_list" => to_value(files::ssh_files_list(ctx, params(p)?).await),
        "ssh_health_check" => to_value(health::ssh_health_check(ctx, params(p)?).await),
        "ssh_host_inspect" => to_value(hosts::ssh_host_inspect(ctx, params(p)?).await),
        "ssh_logs_search" => to_value(logs::ssh_logs_search(ctx, params(p)?).await),
        "ssh_process_list" => to_value(processes::ssh_process_list(ctx, params(p)?).await),
        "ssh_service_status" => to_value(services::ssh_service_status(ctx, params(p)?).await),
        other => Err(SentinelError::new(
            ErrorCode::InvalidInput,
            format!("'{other}' cannot be used in a batch; batchable tools: {}", BATCHABLE.join(", ")),
        )),
    }
}

pub async fn ssh_batch_inspect(ctx: &AppContext, p: BatchInspectParams) -> Result<ResultEnvelope<BatchInspectData>> {
    let max = ctx.config.gateway.budgets.max_batch_items;
    if p.items.is_empty() || p.items.len() > max {
        return Err(invalid(format!("a batch holds 1-{max} items")));
    }
    let mut ids = BTreeSet::new();
    for it in &p.items {
        if !valid_item_id(&it.id) {
            return Err(invalid(format!("invalid item id '{}'", it.id)));
        }
        if !ids.insert(it.id.clone()) {
            return Err(invalid(format!("duplicate item id '{}'", it.id)));
        }
    }
    let mut env = local_tool_unscheduled(ctx, "ssh_batch_inspect", || async move {
        let gate = Arc::new(Semaphore::new(ITEM_CONCURRENCY));
        // The batch's own operation token: spawned items do not inherit task-locals, so each is re-scoped to it.
        let batch_cancel = crate::tools::caller_cancel().expect("local tools run under their operation's token");
        let mut tasks = Vec::with_capacity(p.items.len());
        for it in p.items {
            let (ctx, gate, cancel) = (ctx.clone(), gate.clone(), batch_cancel.clone());
            tasks.push(tokio::spawn(async move {
                let _slot = gate.acquire_owned().await.expect("semaphore never closed");
                match crate::tools::cancelled_by(cancel, dispatch(&ctx, &it.tool, it.params)).await {
                    Ok(result) => BatchItemResult::Ok { id: it.id, result },
                    Err(error) => BatchItemResult::Error { id: it.id, error },
                }
            }));
        }
        let mut items = Vec::with_capacity(tasks.len());
        for t in tasks {
            items.push(
                t.await
                    .map_err(|e| SentinelError::new(ErrorCode::Internal, format!("batch item task failed: {e}")))?,
            );
        }
        let ok_count = items.iter().filter(|i| matches!(i, BatchItemResult::Ok { .. })).count() as u32;
        let error_count = items.len() as u32 - ok_count;
        Ok((
            BatchInspectData {
                items,
                ok_count,
                error_count,
            },
            None,
        ))
    })
    .await?;
    if env.data.error_count > 0 {
        env.outcome = Outcome::Partial;
    }
    Ok(env)
}
