//! rmcp adapter behaviour that the stdio transcripts do not reach directly.

use std::sync::Arc;

use rmcp::ServerHandler;
use rmcp::handler::server::router::tool::AsyncTool;
use sentinel_core::envelope::Outcome;
use sentinel_core::error::{ErrorCode, SentinelError};
use sentinel_core::identity::{HostId, PrincipalId};
use sentinel_gateway::artifacts::{ArtifactOrigin, ContentKind};
use sentinel_gateway::mcp::results::Detail;
use sentinel_gateway::mcp::server::{ArtifactReadTool, SentinelServer, ToolError};
use sentinel_gateway::tools::AppContext;
use sentinel_gateway::tools::artifacts::ArtifactReadParams;
use sentinel_testkit::configs::{TestDirs, load_minimal};
use sentinel_testkit::fake_backend::FakeBackend;

fn server() -> (TestDirs, SentinelServer) {
    let dirs = TestDirs::new();
    let (cfg, _) = load_minimal(&dirs);
    (
        dirs,
        SentinelServer::new(AppContext::new(cfg, Arc::new(FakeBackend::new())).unwrap()),
    )
}

#[test]
fn tool_errors_map_to_json_rpc_codes() {
    let code = |c| rmcp::ErrorData::from(ToolError(SentinelError::new(c, "m"))).code.0;
    assert_eq!(code(ErrorCode::InvalidInput), -32602);
    assert_eq!(code(ErrorCode::Internal), -32603);
    assert_eq!(code(ErrorCode::PolicyDenied), -32000);
}

#[test]
fn get_tool_finds_catalogue_entries_only() {
    let (_d, s) = server();
    assert_eq!(s.get_tool("ssh_hosts_list").unwrap().name, "ssh_hosts_list");
    assert!(s.get_tool("ssh_exec").is_none());
}

/// Artefact reads are bounded inline: a page that fits is returned, one that does not is a typed failure, never a new artefact.
#[tokio::test]
async fn artifact_reads_never_spill_into_new_artifacts() {
    let (_d, s) = server();
    let me = PrincipalId::parse("raouf").unwrap();
    let origin = ArtifactOrigin::RemoteFile {
        host_id: HostId::parse("h1").unwrap(),
        root: "app".into(),
        path: "x".into(),
    };
    let rec = s
        .ctx
        .artifacts
        .put_bytes(&me, origin, ContentKind::Utf8Text, "x".repeat(60_000).as_bytes())
        .await
        .unwrap();
    let before = std::fs::read_dir(s.ctx.artifacts.dir()).unwrap().count();
    let ok = ArtifactReadTool::invoke(
        &s,
        ArtifactReadParams {
            artifact_id: rec.id.to_string(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(ok.outcome, Outcome::Succeeded);
    assert_eq!(ok.data.unwrap().bytes_returned, 4096);
    let big = ArtifactReadParams {
        artifact_id: rec.id.to_string(),
        length: Some(65536),
        detail: Some(Detail::Concise),
        ..Default::default()
    };
    let refused = ArtifactReadTool::invoke(&s, big).await.unwrap();
    assert_eq!(refused.outcome, Outcome::Failed);
    assert_eq!(refused.error.unwrap().code, ErrorCode::BudgetExceeded);
    assert_eq!(
        std::fs::read_dir(s.ctx.artifacts.dir()).unwrap().count(),
        before,
        "no new artefact was created"
    );
}
