//! Principal-scoped local artefact store (spec §6.4, §7.3, §10.7). File bytes and oversized results live here, never in
//! model context. Each artefact is `<id>.bin` plus `<id>.json` metadata, both mode 0600, in a 0700 directory.

use std::io::{ErrorKind, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use sentinel_core::error::{ErrorCode, Result, SentinelError};
use sentinel_core::identity::{ArtifactId, HostId, OperationId, Principal, PrincipalId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

use crate::config::ensure_private_dir;

pub const MAX_RANGE_BYTES: u32 = 65536;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArtifactOrigin {
    RemoteFile { host_id: HostId, root: String, path: String },
    ToolResult { operation_id: OperationId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    Utf8Text,
    Binary,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactRecord {
    pub id: ArtifactId,
    pub owner: PrincipalId,
    pub origin: ArtifactOrigin,
    pub bytes: u64,
    /// Lowercase hex SHA-256 of the stored bytes.
    pub sha256: String,
    pub content_kind: ContentKind,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ArtifactStore {
    dir: PathBuf,
    retention: Duration,
}

fn io_err(what: &str, e: std::io::Error) -> SentinelError {
    let code = if e.kind() == ErrorKind::StorageFull {
        ErrorCode::DiskFull
    } else {
        ErrorCode::Internal
    };
    SentinelError::new(code, format!("artefact store: {what}: {e}"))
}

fn not_found() -> SentinelError {
    SentinelError::new(ErrorCode::NotFound, "artefact not found")
}

fn create_private(path: &Path) -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| io_err("create", e))
}

/// Streams bytes into `<id>.part`, hashing as it goes. Nothing is visible to readers until [`ArtifactWriter::finish`].
pub struct ArtifactWriter {
    file: tokio::fs::File,
    hasher: Sha256,
    bytes: u64,
    part: PathBuf,
    store: ArtifactStore,
    record: ArtifactRecord,
}

impl ArtifactWriter {
    /// Verifies the digest (when given), then publishes the artefact. On mismatch the partial bytes are deleted.
    pub async fn finish(mut self, expected_sha256: Option<&str>) -> Result<ArtifactRecord> {
        let flushed = async {
            self.file.flush().await?;
            self.file.sync_all().await
        }
        .await;
        if let Err(e) = flushed {
            let _ = tokio::fs::remove_file(&self.part).await;
            return Err(io_err("flush", e));
        }
        let digest = hex::encode(self.hasher.finalize_reset());
        if let Some(exp) = expected_sha256
            && !exp.eq_ignore_ascii_case(&digest)
        {
            let _ = tokio::fs::remove_file(&self.part).await;
            return Err(
                SentinelError::new(ErrorCode::DigestMismatch, "received bytes do not match the expected SHA-256")
                    .with_detail("expected_sha256", exp.to_ascii_lowercase())
                    .with_detail("received_sha256", digest)
                    .with_detail("bytes_received", self.bytes),
            );
        }
        let mut rec = self.record.clone();
        rec.bytes = self.bytes;
        rec.sha256 = digest;
        if let Err(e) = self.store.publish(&self.part, &rec) {
            let _ = tokio::fs::remove_file(&self.part).await;
            return Err(e);
        }
        Ok(rec)
    }

    pub async fn abort(self) {
        drop(self.file);
        let _ = tokio::fs::remove_file(&self.part).await;
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes
    }
}

impl AsyncWrite for ArtifactWriter {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        match Pin::new(&mut this.file).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                this.hasher.update(&buf[..n]);
                this.bytes += n as u64;
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.file).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.file).poll_shutdown(cx)
    }
}

impl ArtifactStore {
    pub fn open(dir: &Path, retention: Duration) -> Result<Self> {
        ensure_private_dir(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            retention,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path_of(&self, id: &ArtifactId) -> PathBuf {
        self.dir.join(format!("{id}.bin"))
    }

    fn meta_path(&self, id: &ArtifactId) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    pub fn begin_write(&self, owner: &PrincipalId, origin: ArtifactOrigin, kind: ContentKind) -> Result<ArtifactWriter> {
        let id = ArtifactId::generate();
        let part = self.dir.join(format!("{id}.part"));
        let file = tokio::fs::File::from_std(create_private(&part)?);
        let now = Utc::now();
        let expires_at = now + chrono::Duration::from_std(self.retention).unwrap_or(chrono::Duration::hours(24));
        let record = ArtifactRecord {
            id,
            owner: owner.clone(),
            origin,
            bytes: 0,
            sha256: String::new(),
            content_kind: kind,
            created_at: now,
            expires_at,
        };
        Ok(ArtifactWriter {
            file,
            hasher: Sha256::new(),
            bytes: 0,
            part,
            store: self.clone(),
            record,
        })
    }

    /// Metadata first, then the atomic rename: a `.bin` without `.json` is never served.
    fn publish(&self, part: &Path, rec: &ArtifactRecord) -> Result<()> {
        let meta_tmp = self.dir.join(format!("{}.json.part", rec.id));
        let mut f = create_private(&meta_tmp)?;
        f.write_all(&serde_json::to_vec(rec).expect("record serialises"))
            .map_err(|e| io_err("write metadata", e))?;
        f.sync_all().map_err(|e| io_err("sync metadata", e))?;
        std::fs::rename(&meta_tmp, self.meta_path(&rec.id)).map_err(|e| io_err("publish metadata", e))?;
        std::fs::rename(part, self.path_of(&rec.id)).map_err(|e| io_err("publish", e))
    }

    pub async fn put_bytes(&self, owner: &PrincipalId, origin: ArtifactOrigin, kind: ContentKind, bytes: &[u8]) -> Result<ArtifactRecord> {
        let mut w = self.begin_write(owner, origin, kind)?;
        if let Err(e) = w.write_all(bytes).await {
            w.abort().await;
            return Err(io_err("write", e));
        }
        w.finish(None).await
    }

    fn load(&self, id: &ArtifactId) -> Option<ArtifactRecord> {
        let text = std::fs::read(self.meta_path(id)).ok()?;
        let rec: ArtifactRecord = serde_json::from_slice(&text).ok()?;
        (rec.id == *id && self.path_of(id).is_file()).then_some(rec)
    }

    /// Another principal's artefact and an unknown id give the same `NOT_FOUND`.
    pub fn get(&self, principal: &Principal, id: &ArtifactId) -> Result<ArtifactRecord> {
        let rec = self.load(id).filter(|r| r.owner == principal.id).ok_or_else(not_found)?;
        if Utc::now() >= rec.expires_at {
            return Err(SentinelError::new(ErrorCode::ArtifactExpired, "artefact has expired")
                .with_detail("expired_at", rec.expires_at.to_rfc3339()));
        }
        Ok(rec)
    }

    pub async fn read_range(&self, principal: &Principal, id: &ArtifactId, offset: u64, length: u32) -> Result<(Vec<u8>, ArtifactRecord)> {
        if length > MAX_RANGE_BYTES {
            return Err(
                SentinelError::new(ErrorCode::InvalidInput, format!("length must be at most {MAX_RANGE_BYTES}"))
                    .with_detail("field", "length"),
            );
        }
        let rec = self.get(principal, id)?;
        if offset >= rec.bytes {
            return Ok((Vec::new(), rec));
        }
        let mut f = tokio::fs::File::open(self.path_of(id)).await.map_err(|e| io_err("open", e))?;
        f.seek(SeekFrom::Start(offset)).await.map_err(|e| io_err("seek", e))?;
        let want = (length as u64).min(rec.bytes - offset) as usize;
        let mut buf = vec![0u8; want];
        f.read_exact(&mut buf).await.map_err(|e| io_err("read", e))?;
        Ok((buf, rec))
    }

    /// Removes expired artefacts. Returns how many were removed.
    pub fn sweep_expired(&self) -> Result<usize> {
        let now = Utc::now();
        let mut n = 0;
        for entry in std::fs::read_dir(&self.dir).map_err(|e| io_err("list", e))?.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Some(rec) = std::fs::read(&p)
                .ok()
                .and_then(|b| serde_json::from_slice::<ArtifactRecord>(&b).ok())
            else {
                continue;
            };
            if now >= rec.expires_at {
                let _ = std::fs::remove_file(self.path_of(&rec.id));
                let _ = std::fs::remove_file(&p);
                n += 1;
            }
        }
        Ok(n)
    }
}
