//! `ssh_transfer_download` (spec §7.3 #26, §7.3.3 steps 2, 4, 6): an authorised remote regular file into a principal-scoped
//! artefact, verified against the remote SHA-256. The bytes never enter model context; the result is a handle.

use std::time::Duration;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use sentinel_core::effect::Effect;
use sentinel_core::envelope::{EvidenceSource, ResultEnvelope};
use sentinel_core::error::{ErrorCode, Result, SentinelError};
use sentinel_core::identity::ArtifactId;
use sentinel_core::policy::ResourceRef;
use serde::{Deserialize, Serialize};

use crate::artifacts::{ArtifactOrigin, ContentKind};
use crate::mcp::results::Detail;
use crate::ssh::backend::{ExitKind, StreamBudget, classify_ssh_failure};
use crate::ssh::command::{RemoteCommand, scope_guard};
use crate::tools::files::{hash_command, parse_hash, scoped};
use crate::tools::pipeline::{has_io_error, read_tool, remote_failure};
use crate::tools::{AppContext, UNTRUSTED};

pub const NEXT_ACTION: &str =
    "read ranges with ssh_artifact_read or retrieve the artefact with the operator CLI; bytes were not placed in model context";

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransferDownloadParams {
    pub host_id: String,
    /// A root alias with export permission.
    pub root: String,
    pub path: String,
    /// Refuse unless the remote file currently has this SHA-256 (64 hex characters).
    pub expected_sha256: Option<String>,
    pub detail: Option<Detail>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct TransferDownloadData {
    pub artifact_id: ArtifactId,
    pub bytes: u64,
    /// Remote and local SHA-256 agree on this value.
    pub sha256: String,
    pub source: ArtifactOrigin,
    pub expires_at: DateTime<Utc>,
    pub next_action: &'static str,
    pub content_trust: &'static str,
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())
}

fn source_changed(msg: &str) -> SentinelError {
    SentinelError::new(ErrorCode::SourceChanged, msg)
}

pub async fn ssh_transfer_download(ctx: &AppContext, p: TransferDownloadParams) -> Result<ResultEnvelope<TransferDownloadData>> {
    if let Some(e) = &p.expected_sha256
        && !is_sha256_hex(e)
    {
        return Err(
            SentinelError::new(ErrorCode::InvalidInput, "expected_sha256 must be 64 hex characters")
                .with_detail("field", "expected_sha256"),
        );
    }
    let root = p.root.clone();
    let env = read_tool(
        ctx,
        "ssh_transfer_download",
        &p.host_id,
        ResourceRef::Root(&root),
        Effect::Export,
        |run| async move {
            let target = scoped(&run, &p.root, &p.path)?;
            let b = &run.ctx.config.gateway.budgets;
            let out = run
                .run_guarded(Some("regular file"), &target, hash_command(&target.absolute, b.max_transfer_bytes))
                .await?;
            if out.exit != ExitKind::Code(0) || has_io_error(&out.stderr) {
                return Err(remote_failure(&out.stderr));
            }
            let (size, remote_digest) = parse_hash(&out.stdout)?;
            if let Some(exp) = &p.expected_sha256
                && !exp.eq_ignore_ascii_case(&remote_digest)
            {
                return Err(source_changed("remote file does not have the expected SHA-256").with_detail("remote_sha256", remote_digest));
            }
            let origin = ArtifactOrigin::RemoteFile {
                host_id: run.host.id.clone(),
                root: p.root.clone(),
                path: target.relative.clone(),
            };
            let mut writer = run
                .ctx
                .artifacts
                .begin_write(&run.ctx.principal.id, origin.clone(), ContentKind::Binary)?;
            let budget = StreamBudget {
                idle_timeout: Duration::from_secs(b.transfer_idle_timeout_secs),
                total_timeout: Duration::from_secs(b.transfer_total_timeout_secs),
                max_bytes: size,
            };
            // Guarded again: the path could have been swapped for a symlink after hashing.
            let cat = scope_guard(
                &target.root_path,
                &target.absolute,
                Some("regular file"),
                RemoteCommand::new("cat").flag("--").arg(&target.absolute),
            );
            let streamed = run
                .ctx
                .backend
                .stream_stdout(&run.host, &cat, &budget, run.op.cancel.clone(), &mut writer)
                .await;
            let outcome = match streamed {
                Ok(o) => o,
                Err(e) => {
                    writer.abort().await;
                    return Err(if e.code == ErrorCode::BudgetExceeded {
                        source_changed("remote file grew after it was hashed")
                    } else {
                        e
                    });
                }
            };
            if outcome.exit != ExitKind::Code(0) {
                writer.abort().await;
                if let Some(code) = classify_ssh_failure(&outcome.exit, &outcome.stderr) {
                    tracing::warn!(stderr = %String::from_utf8_lossy(&outcome.stderr).lines().next().unwrap_or(""), "ssh client failure during transfer");
                return Err(SentinelError::new(code, "the SSH connection failed during the transfer"));
                }
                return Err(source_changed("remote file changed type or became unreadable during transfer"));
            }
            if writer.bytes_written() != size {
                writer.abort().await;
                return Err(
                    SentinelError::new(ErrorCode::TransferPartial, format!("received {} of {size} bytes", outcome.bytes))
                        .with_detail("bytes_received", outcome.bytes),
                );
            }
            let rec = writer.finish(Some(&remote_digest)).await?;
            Ok(TransferDownloadData {
                artifact_id: rec.id,
                bytes: rec.bytes,
                sha256: rec.sha256,
                source: origin,
                expires_at: rec.expires_at,
                next_action: NEXT_ACTION,
                content_trust: UNTRUSTED,
            })
        },
    )
    .await?;
    Ok(env
        .with_evidence("remote_digest", EvidenceSource::Observer)
        .with_evidence("local_digest", EvidenceSource::Observer))
}
