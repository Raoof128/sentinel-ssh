use std::time::Duration;

use sentinel_core::envelope::Outcome;
use sentinel_core::error::ErrorCode;
use sentinel_core::identity::{HostId, OperationId};
use sentinel_core::operation::{OperationState, RemoteTermination};
use sentinel_gateway::artifacts::{ArtifactOrigin, ContentKind};
use sentinel_gateway::tools::artifacts::{ArtifactReadParams, ssh_artifact_read};
use sentinel_gateway::tools::batch::{BatchInspectParams, BatchItem, BatchItemResult, ssh_batch_inspect};
use sentinel_gateway::tools::files::Encoding;
use sentinel_gateway::tools::hosts::{HostInspectParams, ssh_host_inspect};
use sentinel_gateway::tools::operations::{OperationCancelParams, OperationGetParams, ssh_operation_cancel, ssh_operation_get};
use sentinel_testkit::ctx::ctx_with;
use sentinel_testkit::fake_backend::{FakeBackend, Script};
use serde_json::json;

const SERVICE_OUT: &[u8] =
    b"Id=app-api.service\nActiveState=active\nSubState=running\nLoadState=loaded\nResult=success\nMainPID=1\nNRestarts=0\n";

fn item(id: &str, tool: &str, params: serde_json::Value) -> BatchItem {
    BatchItem {
        id: id.into(),
        tool: tool.into(),
        params,
    }
}
fn origin() -> ArtifactOrigin {
    ArtifactOrigin::RemoteFile {
        host_id: HostId::parse("h1").unwrap(),
        root: "app".into(),
        path: "x".into(),
    }
}

#[tokio::test]
async fn batch_runs_each_item_with_own_authorisation() {
    let fake = FakeBackend::new().on("systemctl show", SERVICE_OUT.to_vec());
    let ctx = ctx_with(fake.clone());
    let e = ssh_batch_inspect(
        &ctx,
        BatchInspectParams {
            items: vec![
                item("a", "ssh_service_status", json!({"host_id":"h1","service_id":"api"})),
                item("b", "ssh_file_hash", json!({"host_id":"h1","root":"secrets","path":"k"})),
                item("c", "ssh_transfer_download", json!({})),
                item("d", "ssh_service_status", json!({"host_id":"h1","service_id":"api","bogus":1})),
            ],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(e.outcome, Outcome::Partial);
    assert_eq!(e.data.ok_count, 1);
    assert_eq!(e.data.error_count, 3);
    assert!(matches!(&e.data.items[0], BatchItemResult::Ok { id, result } if id == "a" && result["data"]["active_state"] == "active"));
    assert!(matches!(&e.data.items[1], BatchItemResult::Error { error, .. } if error.code == ErrorCode::PolicyDenied));
    assert!(matches!(&e.data.items[2], BatchItemResult::Error { error, .. } if error.code == ErrorCode::InvalidInput));
    assert!(matches!(&e.data.items[3], BatchItemResult::Error { error, .. } if error.code == ErrorCode::InvalidInput));
    assert_eq!(fake.calls().len(), 1);
}

#[tokio::test]
async fn batch_all_ok_is_succeeded() {
    let ctx = ctx_with(FakeBackend::new());
    let e = ssh_batch_inspect(
        &ctx,
        BatchInspectParams {
            items: vec![item("x", "ssh_capabilities_get", json!({}))],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(e.outcome, Outcome::Succeeded);
}

#[tokio::test]
async fn batch_over_16_or_bad_ids_rejected_before_dispatch() {
    let fake = FakeBackend::new();
    let ctx = ctx_with(fake.clone());
    let items = (0..17).map(|i| item(&format!("i{i}"), "ssh_capabilities_get", json!({}))).collect();
    assert_eq!(
        ssh_batch_inspect(
            &ctx,
            BatchInspectParams {
                items,
                ..Default::default()
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::InvalidInput
    );
    let dup = vec![
        item("a", "ssh_capabilities_get", json!({})),
        item("a", "ssh_capabilities_get", json!({})),
    ];
    assert_eq!(
        ssh_batch_inspect(
            &ctx,
            BatchInspectParams {
                items: dup,
                ..Default::default()
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        ssh_batch_inspect(&ctx, BatchInspectParams::default()).await.unwrap_err().code,
        ErrorCode::InvalidInput
    );
    let bad = vec![item("a b", "ssh_capabilities_get", json!({}))];
    assert_eq!(
        ssh_batch_inspect(
            &ctx,
            BatchInspectParams {
                items: bad,
                ..Default::default()
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::InvalidInput
    );
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn operation_get_and_cancel_running_op() {
    let fake = FakeBackend::new().on_script(Script {
        matches: "uname".into(),
        stdout: vec![],
        stderr: vec![],
        exit: 0,
        delay: Duration::from_secs(5),
        error: None,
    });
    let ctx = ctx_with(fake);
    let c2 = ctx.ctx.clone();
    let h = tokio::spawn(async move {
        ssh_host_inspect(
            &c2,
            HostInspectParams {
                host_id: "h1".into(),
                ..Default::default()
            },
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let running = ctx
        .operations
        .list_for(&ctx.principal)
        .into_iter()
        .find(|r| r.state == OperationState::Running)
        .expect("a running op");
    let id = running.id.to_string();
    let c = ssh_operation_cancel(
        &ctx,
        OperationCancelParams {
            operation_id: id.clone(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(c.data.state, OperationState::CancelRequested);
    assert!(c.data.note.contains("not confirmed"));
    assert!(h.await.unwrap().is_err());
    let g = ssh_operation_get(
        &ctx,
        OperationGetParams {
            operation_id: id,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(g.data.state, OperationState::Cancelled);
    assert_eq!(g.data.remote_termination, RemoteTermination::Unconfirmed);
}

#[tokio::test]
async fn operation_get_unknown_and_malformed() {
    let ctx = ctx_with(FakeBackend::new());
    assert_eq!(
        ssh_operation_get(
            &ctx,
            OperationGetParams {
                operation_id: OperationId::generate().to_string(),
                ..Default::default()
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::NotFound
    );
    assert_eq!(
        ssh_operation_get(
            &ctx,
            OperationGetParams {
                operation_id: "op_../x".into(),
                ..Default::default()
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::InvalidInput
    );
}

#[tokio::test]
async fn artifact_read_ranges_and_base64() {
    let ctx = ctx_with(FakeBackend::new());
    let rec = ctx
        .artifacts
        .put_bytes(&ctx.principal.id, origin(), ContentKind::Binary, &[0, 255, 1])
        .await
        .unwrap();
    let e = ssh_artifact_read(
        &ctx,
        ArtifactReadParams {
            artifact_id: rec.id.to_string(),
            encoding: Some(Encoding::Base64),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(e.data.content, "AP8B");
    assert!(e.data.eof);
    assert_eq!(e.data.artifact.sha256, rec.sha256);
    assert_eq!(
        ssh_artifact_read(
            &ctx,
            ArtifactReadParams {
                artifact_id: rec.id.to_string(),
                ..Default::default()
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::NotUtf8
    );
    assert_eq!(
        ssh_artifact_read(
            &ctx,
            ArtifactReadParams {
                artifact_id: "../../etc/passwd".into(),
                ..Default::default()
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::InvalidInput
    );
    let part = ssh_artifact_read(
        &ctx,
        ArtifactReadParams {
            artifact_id: rec.id.to_string(),
            offset: Some(1),
            length: Some(1),
            encoding: Some(Encoding::Base64),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(part.data.content, "/w==");
    assert!(!part.data.eof);
}
