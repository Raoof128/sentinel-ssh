//! `ssh_artifact_read` (spec §7.1 #15): a bounded range of an artefact the caller owns. No filesystem paths or URLs.

use schemars::JsonSchema;
use sentinel_core::envelope::ResultEnvelope;
use sentinel_core::error::Result;
use sentinel_core::identity::ArtifactId;
use serde::{Deserialize, Serialize};

use crate::artifacts::ArtifactRecord;
use crate::mcp::results::Detail;
use crate::tools::files::{Encoding, encode};
use crate::tools::pipeline::local_tool;
use crate::tools::{AppContext, UNTRUSTED, bounded};

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReadParams {
    pub artifact_id: String,
    /// Byte offset, default 0.
    pub offset: Option<u64>,
    /// 1-65536 bytes, default 8192.
    pub length: Option<u32>,
    /// utf8 (default) or base64.
    pub encoding: Option<Encoding>,
    pub detail: Option<Detail>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct ArtifactReadData {
    pub artifact: ArtifactRecord,
    pub offset: u64,
    pub bytes_returned: u32,
    pub eof: bool,
    pub encoding: Encoding,
    pub content: String,
    pub content_trust: &'static str,
}

pub async fn ssh_artifact_read(ctx: &AppContext, p: ArtifactReadParams) -> Result<ResultEnvelope<ArtifactReadData>> {
    let id = ArtifactId::parse(&p.artifact_id)?;
    let length = bounded(p.length, 8192, 65536, "length")?;
    local_tool(ctx, "ssh_artifact_read", || async move {
        let offset = p.offset.unwrap_or(0);
        let (bytes, artifact) = ctx.artifacts.read_range(&ctx.principal, &id, offset, length).await?;
        let encoding = p.encoding.unwrap_or_default();
        let content = encode(&bytes, encoding)?;
        let eof = offset + bytes.len() as u64 >= artifact.bytes;
        Ok((
            ArtifactReadData {
                artifact,
                offset,
                bytes_returned: bytes.len() as u32,
                eof,
                encoding,
                content,
                content_trust: UNTRUSTED,
            },
            None,
        ))
    })
    .await
}
