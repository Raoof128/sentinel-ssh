//! Scoped file inspection (spec §7.1 #8-11): list, read a byte range, stat and hash, all relative to a registered root.

use base64::Engine;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use sentinel_core::effect::Effect;
use sentinel_core::envelope::ResultEnvelope;
use sentinel_core::error::{ErrorCode, Result, SentinelError};
use sentinel_core::policy::ResourceRef;
use sentinel_core::scope::{ScopedPath, display_escape, resolve_scoped};
use serde::{Deserialize, Serialize};

use crate::mcp::results::Detail;
use crate::ssh::command::{MARKER, RemoteCommand, size_guard};
use crate::tools::pipeline::{ToolRun, read_tool};
use crate::tools::{AppContext, UNTRUSTED, bounded};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    #[default]
    Utf8,
    Base64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithm {
    #[default]
    Sha256,
}

pub(crate) fn scoped(run: &ToolRun, root: &str, path: &str) -> Result<ScopedPath> {
    let r = run.ctx.policy.root(&run.ctx.principal, &run.host.id, root)?;
    resolve_scoped(r, path)
}

/// Splits `<header>\n--SENTINEL--\n<body>` at the first marker, leaving the body bytes exact.
pub(crate) fn split_header(out: &[u8]) -> Result<(String, &[u8])> {
    let marker = format!("\n{MARKER}\n");
    let pos = out
        .windows(marker.len())
        .position(|w| w == marker.as_bytes())
        .ok_or_else(|| SentinelError::new(ErrorCode::RemoteFailure, "unexpected remote output: missing section marker"))?;
    Ok((String::from_utf8_lossy(&out[..pos]).trim().to_owned(), &out[pos + marker.len()..]))
}

fn parse_size(s: &str) -> Result<u64> {
    s.trim()
        .parse()
        .map_err(|_| SentinelError::new(ErrorCode::RemoteFailure, "unexpected remote output: file size"))
}

fn kind_of(stat_type: &str) -> EntryKind {
    match stat_type {
        "regular file" | "regular empty file" | "f" => EntryKind::File,
        "directory" | "d" => EntryKind::Dir,
        "symbolic link" | "l" => EntryKind::Symlink,
        _ => EntryKind::Other,
    }
}

fn epoch(s: &str) -> DateTime<Utc> {
    let f: f64 = s.parse().unwrap_or(0.0);
    DateTime::from_timestamp(f.trunc() as i64, ((f.fract() * 1e9) as u32).min(999_999_999)).unwrap_or_default()
}

// ---------- ssh_files_list ----------

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesListParams {
    pub host_id: String,
    pub root: String,
    /// Directory relative to the root; "" for the root itself.
    #[serde(default)]
    pub path: String,
    /// 1-500, default 100.
    pub max_entries: Option<u32>,
    /// Continue after this entry name (from `next_cursor`).
    pub cursor: Option<String>,
    pub detail: Option<Detail>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct FileEntry {
    /// Control and bidirectional characters are shown escaped as `\u{XXXX}`.
    pub name: String,
    pub kind: EntryKind,
    pub bytes: u64,
    pub mtime: DateTime<Utc>,
    pub mode_octal: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct FilesListData {
    pub root: String,
    pub path: String,
    pub entries: Vec<FileEntry>,
    pub content_trust: &'static str,
}

/// Parses NUL-terminated `%y\t%s\t%T@\t%m\t%f` records. Names may contain any byte except NUL and '/'.
pub fn parse_find(run: &ToolRun, out: &[u8]) -> Vec<(String, FileEntry)> {
    out.split(|b| *b == 0)
        .filter(|r| !r.is_empty())
        .filter_map(|rec| {
            let text = run.text_lossy(rec);
            let mut f = text.splitn(5, '\t');
            let (y, s, t, m, name) = (f.next()?, f.next()?, f.next()?, f.next()?, f.next()?);
            Some((
                name.to_owned(),
                FileEntry {
                    name: display_escape(name),
                    kind: kind_of(y),
                    bytes: s.parse().unwrap_or(0),
                    mtime: epoch(t),
                    mode_octal: m.to_owned(),
                },
            ))
        })
        .collect()
}

pub async fn ssh_files_list(ctx: &AppContext, p: FilesListParams) -> Result<ResultEnvelope<FilesListData>> {
    let max = bounded(p.max_entries, 100, 500, "max_entries")? as usize;
    let root = p.root.clone();
    read_tool(
        ctx,
        "ssh_files_list",
        &p.host_id,
        ResourceRef::Root(&root),
        Effect::Read,
        |run| async move {
            let target = scoped(&run, &p.root, &p.path)?;
            let find = RemoteCommand::new("find")
                .arg(&target.absolute)
                .flag("-mindepth")
                .num(1)
                .flag("-maxdepth")
                .num(1)
                .flag("-printf")
                .arg("%y\t%s\t%T@\t%m\t%f\0");
            let out = run.run_guarded("directory", &target.absolute, find).await?;
            let mut all = parse_find(&run, &out.stdout);
            all.sort_by(|a, b| a.0.cmp(&b.0));
            let after: Vec<_> = all
                .into_iter()
                .filter(|(raw, _)| p.cursor.as_deref().is_none_or(|c| raw.as_str() > c))
                .collect();
            if after.len() > max {
                run.set_next_cursor(after[max - 1].0.clone());
            }
            let entries = after.into_iter().take(max).map(|(_, e)| e).collect();
            Ok(FilesListData {
                root: p.root,
                path: target.relative,
                entries,
                content_trust: UNTRUSTED,
            })
        },
    )
    .await
}

// ---------- ssh_file_read ----------

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileReadParams {
    pub host_id: String,
    pub root: String,
    pub path: String,
    /// Byte offset, default 0.
    pub offset: Option<u64>,
    /// 1-65536 bytes, default 8192.
    pub length: Option<u32>,
    /// utf8 (default; fails on invalid UTF-8) or base64.
    pub encoding: Option<Encoding>,
    pub detail: Option<Detail>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct FileReadData {
    pub offset: u64,
    pub bytes_returned: u32,
    pub total_bytes: u64,
    pub eof: bool,
    pub encoding: Encoding,
    pub content: String,
    pub content_trust: &'static str,
}

/// File bodies are never lossily converted: invalid UTF-8 is an error that names the alternative (Review Focus 2).
pub(crate) fn encode(bytes: &[u8], enc: Encoding) -> Result<String> {
    match enc {
        Encoding::Base64 => Ok(base64::engine::general_purpose::STANDARD.encode(bytes)),
        Encoding::Utf8 => String::from_utf8(bytes.to_vec())
            .map_err(|_| SentinelError::new(ErrorCode::NotUtf8, "content is not UTF-8; request encoding=base64")),
    }
}

pub async fn ssh_file_read(ctx: &AppContext, p: FileReadParams) -> Result<ResultEnvelope<FileReadData>> {
    let length = bounded(p.length, 8192, 65536, "length")?;
    let root = p.root.clone();
    read_tool(
        ctx,
        "ssh_file_read",
        &p.host_id,
        ResourceRef::Root(&root),
        Effect::Read,
        |run| async move {
            let target = scoped(&run, &p.root, &p.path)?;
            let offset = p.offset.unwrap_or(0);
            let main = RemoteCommand::new("stat")
                .flag("-c")
                .flag("%s")
                .flag("--")
                .arg(&target.absolute)
                .then(RemoteCommand::marker())
                .then(
                    RemoteCommand::new("tail")
                        .flag("-c")
                        .arg(&format!("+{}", offset + 1))
                        .flag("--")
                        .arg(&target.absolute)
                        .pipe(RemoteCommand::new("head").flag("-c").num(length as u64)),
                );
            let out = run.run_guarded("regular file", &target.absolute, main).await?;
            let (size, body) = split_header(&out.stdout)?;
            let total_bytes = parse_size(&size)?;
            let encoding = p.encoding.unwrap_or_default();
            Ok(FileReadData {
                offset,
                bytes_returned: body.len() as u32,
                total_bytes,
                eof: offset + body.len() as u64 >= total_bytes,
                encoding,
                content: encode(body, encoding)?,
                content_trust: UNTRUSTED,
            })
        },
    )
    .await
}

// ---------- ssh_file_stat ----------

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileStatParams {
    pub host_id: String,
    pub root: String,
    pub path: String,
    pub detail: Option<Detail>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct FileStatData {
    /// Of the path itself; a symlink is reported as `symlink` and its target is not followed or disclosed.
    pub kind: EntryKind,
    pub bytes: u64,
    pub mode_octal: String,
    pub owner: String,
    pub group: String,
    pub mtime: DateTime<Utc>,
    pub nlink: u32,
}

pub async fn ssh_file_stat(ctx: &AppContext, p: FileStatParams) -> Result<ResultEnvelope<FileStatData>> {
    let root = p.root.clone();
    read_tool(
        ctx,
        "ssh_file_stat",
        &p.host_id,
        ResourceRef::Root(&root),
        Effect::Read,
        |run| async move {
            let target = scoped(&run, &p.root, &p.path)?;
            let out = run
                .run(
                    &RemoteCommand::new("stat")
                        .flag("-c")
                        .arg("%F|%s|%a|%U|%G|%Y|%h")
                        .flag("--")
                        .arg(&target.absolute),
                )
                .await?;
            if out.exit != crate::ssh::backend::ExitKind::Code(0) {
                return Err(not_found_or_failure(&out.stderr));
            }
            let text = run.text_lossy(&out.stdout);
            let f: Vec<&str> = text.trim_end_matches('\n').split('|').collect();
            let [ty, size, mode, owner, group, mtime, nlink] = f.as_slice() else {
                return Err(SentinelError::new(ErrorCode::RemoteFailure, "unexpected remote output: stat"));
            };
            Ok(FileStatData {
                kind: kind_of(ty),
                bytes: size.parse().unwrap_or(0),
                mode_octal: (*mode).to_owned(),
                owner: display_escape(owner),
                group: display_escape(group),
                mtime: epoch(mtime),
                nlink: nlink.parse().unwrap_or(0),
            })
        },
    )
    .await
}

pub(crate) fn not_found_or_failure(stderr: &[u8]) -> SentinelError {
    let s = String::from_utf8_lossy(stderr);
    if s.contains("No such file or directory") {
        SentinelError::new(ErrorCode::NotFound, "path not found")
    } else if s.contains("Permission denied") {
        SentinelError::new(
            ErrorCode::RemoteFailure,
            "the SSH account cannot read this path (permission denied)",
        )
    } else {
        SentinelError::new(
            ErrorCode::RemoteFailure,
            s.lines()
                .next()
                .unwrap_or("remote command failed")
                .chars()
                .take(300)
                .collect::<String>(),
        )
    }
}

// ---------- ssh_file_hash ----------

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileHashParams {
    pub host_id: String,
    pub root: String,
    pub path: String,
    /// Only sha256.
    pub algorithm: Option<HashAlgorithm>,
    pub detail: Option<Detail>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct FileHashData {
    pub algorithm: HashAlgorithm,
    /// Lowercase hex.
    pub digest: String,
    pub bytes: u64,
}

/// `stat -c %s; marker; sha256sum` behind kind and size guards. Shared with the download tool.
pub(crate) fn hash_command(absolute: &str, max_bytes: u64) -> RemoteCommand {
    size_guard(
        absolute,
        max_bytes,
        RemoteCommand::new("stat")
            .flag("-c")
            .flag("%s")
            .flag("--")
            .arg(absolute)
            .then(RemoteCommand::marker())
            .then(RemoteCommand::new("sha256sum").flag("--").arg(absolute)),
    )
}

pub(crate) fn parse_hash(out: &[u8]) -> Result<(u64, String)> {
    let (size, rest) = split_header(out)?;
    let digest = String::from_utf8_lossy(rest)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if digest.len() != 64 || !digest.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(SentinelError::new(ErrorCode::RemoteFailure, "unexpected remote output: sha256sum"));
    }
    Ok((parse_size(&size)?, digest))
}

pub async fn ssh_file_hash(ctx: &AppContext, p: FileHashParams) -> Result<ResultEnvelope<FileHashData>> {
    let root = p.root.clone();
    read_tool(
        ctx,
        "ssh_file_hash",
        &p.host_id,
        ResourceRef::Root(&root),
        Effect::Read,
        |run| async move {
            let target = scoped(&run, &p.root, &p.path)?;
            let max = run.ctx.config.gateway.budgets.max_transfer_bytes;
            let out = run
                .run_guarded("regular file", &target.absolute, hash_command(&target.absolute, max))
                .await?;
            let (bytes, digest) = parse_hash(&out.stdout)?;
            Ok(FileHashData {
                algorithm: HashAlgorithm::Sha256,
                digest,
                bytes,
            })
        },
    )
    .await
}
