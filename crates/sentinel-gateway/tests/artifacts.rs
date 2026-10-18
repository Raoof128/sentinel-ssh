use std::collections::BTreeSet;
use std::time::Duration;

use sentinel_core::envelope::ResultEnvelope;
use sentinel_core::error::{ErrorCode, SentinelError};
use sentinel_core::identity::{ArtifactId, HostId, HostVisibility, OperationId, Principal, PrincipalId, Role};
use sentinel_gateway::artifacts::{ArtifactOrigin, ArtifactStore, ContentKind};
use sentinel_gateway::config::Budgets;
use sentinel_gateway::mcp::results::{BoundedEnvelope, Detail, bound_envelope, failed_envelope};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

fn me() -> Principal {
    Principal {
        id: PrincipalId::parse("me").unwrap(),
        role: Role::Observer,
        visible_hosts: HostVisibility::All,
    }
}
fn other() -> Principal {
    Principal {
        id: PrincipalId::parse("other").unwrap(),
        role: Role::Observer,
        visible_hosts: HostVisibility::Only(BTreeSet::new()),
    }
}
fn origin() -> ArtifactOrigin {
    ArtifactOrigin::RemoteFile {
        host_id: HostId::parse("h1").unwrap(),
        root: "app".into(),
        path: "data/blob.bin".into(),
    }
}
fn hex_sha256(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn mode(p: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode()
}
fn fresh() -> (tempfile::TempDir, ArtifactStore) {
    let d = tempfile::tempdir().unwrap();
    let store = ArtifactStore::open(&d.path().join("art"), Duration::from_secs(3600)).unwrap();
    (d, store)
}

#[tokio::test]
async fn round_trip_binary_with_zero_bytes() {
    let (_d, store) = fresh();
    let data: Vec<u8> = (0..70000u32).map(|i| (i % 251) as u8).collect();
    let rec = store.put_bytes(&me().id, origin(), ContentKind::Binary, &data).await.unwrap();
    assert_eq!(rec.bytes, 70000);
    assert_eq!(rec.sha256, hex_sha256(&data));
    let (chunk, _) = store.read_range(&me(), &rec.id, 65536, 65536).await.unwrap();
    assert_eq!(chunk, &data[65536..]);
    let (empty, _) = store.read_range(&me(), &rec.id, 70000, 10).await.unwrap();
    assert!(empty.is_empty());
    assert_eq!(mode(&store.path_of(&rec.id)) & 0o777, 0o600);
    assert_eq!(mode(store.dir()) & 0o777, 0o700);
}

#[tokio::test]
async fn writer_hashes_streamed_bytes() {
    let (_d, store) = fresh();
    let mut w = store.begin_write(&me().id, origin(), ContentKind::Binary).unwrap();
    w.write_all(b"abc").await.unwrap();
    w.write_all(b"def").await.unwrap();
    let rec = w.finish(Some(&hex_sha256(b"abcdef"))).await.unwrap();
    assert_eq!(rec.bytes, 6);
    assert_eq!(store.get(&me(), &rec.id).unwrap(), rec);
}

#[tokio::test]
async fn digest_mismatch_quarantines() {
    let (_d, store) = fresh();
    let mut w = store.begin_write(&me().id, origin(), ContentKind::Binary).unwrap();
    w.write_all(b"abc").await.unwrap();
    let e = w.finish(Some("00".repeat(32).as_str())).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::DigestMismatch);
    assert_eq!(std::fs::read_dir(store.dir()).unwrap().count(), 0);
}

#[tokio::test]
async fn abort_leaves_nothing() {
    let (_d, store) = fresh();
    let mut w = store.begin_write(&me().id, origin(), ContentKind::Binary).unwrap();
    w.write_all(b"abc").await.unwrap();
    w.abort().await;
    assert_eq!(std::fs::read_dir(store.dir()).unwrap().count(), 0);
}

#[tokio::test]
async fn other_principal_cannot_read_or_learn_existence() {
    let (_d, store) = fresh();
    let rec = store.put_bytes(&me().id, origin(), ContentKind::Utf8Text, b"x").await.unwrap();
    assert_eq!(store.get(&other(), &rec.id).unwrap_err().code, ErrorCode::NotFound);
    assert_eq!(
        store.read_range(&other(), &rec.id, 0, 1).await.unwrap_err().code,
        ErrorCode::NotFound
    );
    assert_eq!(store.get(&me(), &ArtifactId::generate()).unwrap_err().code, ErrorCode::NotFound);
}

#[tokio::test]
async fn expired_artifact_reports_expired_and_sweeps() {
    let d = tempfile::tempdir().unwrap();
    let store = ArtifactStore::open(&d.path().join("art"), Duration::ZERO).unwrap();
    let rec = store.put_bytes(&me().id, origin(), ContentKind::Binary, b"x").await.unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(store.get(&me(), &rec.id).unwrap_err().code, ErrorCode::ArtifactExpired);
    assert_eq!(store.sweep_expired().unwrap(), 1);
    assert_eq!(std::fs::read_dir(store.dir()).unwrap().count(), 0);
}

#[tokio::test]
async fn range_length_capped() {
    let (_d, store) = fresh();
    let rec = store.put_bytes(&me().id, origin(), ContentKind::Binary, b"x").await.unwrap();
    assert_eq!(
        store.read_range(&me(), &rec.id, 0, 65537).await.unwrap_err().code,
        ErrorCode::InvalidInput
    );
}

#[test]
fn store_dir_must_be_private() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("open");
    std::fs::create_dir(&p).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        ArtifactStore::open(&p, Duration::from_secs(60)).unwrap_err().code,
        ErrorCode::ConfigInvalid
    );
}

#[tokio::test]
async fn oversized_envelope_is_truncated_to_artifact() {
    let (_d, store) = fresh();
    let big = "x".repeat(20_000);
    let env = ResultEnvelope::succeeded(OperationId::generate(), None, serde_json::json!({ "text": big }));
    let b = bound_envelope(&store, &me().id, env, Detail::Concise, &Budgets::default())
        .await
        .unwrap();
    assert!(serde_json::to_vec(&b).unwrap().len() <= 8192);
    assert!(b.truncated);
    assert!(b.artifact_id.is_some());
    assert!(b.data.is_none());
    assert!(b.data_preview.as_deref().unwrap().len() > 1000);
    assert!(b.warnings.contains(&"result_truncated_see_artifact".to_string()));
    let (bytes, _) = store.read_range(&me(), b.artifact_id.as_ref().unwrap(), 0, 65536).await.unwrap();
    assert!(
        String::from_utf8(bytes).unwrap().contains("\"schema_version\""),
        "artefact holds the full envelope"
    );
}

#[tokio::test]
async fn preview_cut_on_char_boundary() {
    let (_d, store) = fresh();
    let big = "é".repeat(10_000);
    let env = ResultEnvelope::succeeded(OperationId::generate(), None, serde_json::json!({ "text": big }));
    let b = bound_envelope(&store, &me().id, env, Detail::Concise, &Budgets::default())
        .await
        .unwrap();
    assert!(b.truncated);
}

#[tokio::test]
async fn full_detail_allows_64k() {
    let (_d, store) = fresh();
    let env = ResultEnvelope::succeeded(OperationId::generate(), None, serde_json::json!({ "text": "x".repeat(20_000) }));
    let b = bound_envelope(&store, &me().id, env, Detail::Full, &Budgets::default())
        .await
        .unwrap();
    assert!(!b.truncated);
    assert!(b.data.is_some());
    assert!(b.artifact_id.is_none());
}

#[test]
fn failed_envelope_carries_typed_error() {
    let e: BoundedEnvelope<()> = failed_envelope(OperationId::generate(), None, SentinelError::new(ErrorCode::PolicyDenied, "x"));
    let v = serde_json::to_value(&e).unwrap();
    assert_eq!(v["outcome"], "failed");
    assert_eq!(v["error"]["code"], "POLICY_DENIED");
    assert_eq!(v["retry"]["strategy"], "never");
    assert!(v["data"].is_null());
    let c: BoundedEnvelope<()> = failed_envelope(
        OperationId::generate(),
        None,
        SentinelError::new(ErrorCode::Timeout, "c").with_detail("cancelled", true),
    );
    assert_eq!(serde_json::to_value(&c).unwrap()["outcome"], "cancelled");
    let u: BoundedEnvelope<()> = failed_envelope(OperationId::generate(), None, SentinelError::new(ErrorCode::OutcomeUnknown, "u"));
    assert_eq!(serde_json::to_value(&u).unwrap()["outcome"], "outcome_unknown");
}

/// Final review #5: a 4 KiB page as base64 fits the default result.
#[tokio::test]
async fn base64_default_page_fits_inline() {
    use base64::Engine;
    let (_d, store) = fresh();
    let content = base64::engine::general_purpose::STANDARD.encode(vec![0xffu8; 4096]);
    let env = ResultEnvelope::succeeded(
        OperationId::generate(),
        None,
        serde_json::json!({ "content": content, "artifact": { "id": "x".repeat(40) } }),
    );
    let b = bound_envelope(&store, &me().id, env, Detail::Concise, &Budgets::default())
        .await
        .unwrap();
    assert!(!b.truncated);
}

/// Final review #5: reading an artefact never spills into a new artefact.
#[tokio::test]
async fn inline_only_bound_refuses_instead_of_spilling() {
    let (_d, store) = fresh();
    let env = ResultEnvelope::succeeded(OperationId::generate(), None, serde_json::json!({ "text": "x".repeat(20_000) }));
    let e = sentinel_gateway::mcp::results::bound_envelope_inline(env, Detail::Concise, &Budgets::default()).unwrap_err();
    assert_eq!(e.code, ErrorCode::BudgetExceeded);
    assert!(
        e.message.contains("smaller length") || e.message.contains("detail"),
        "{}",
        e.message
    );
    assert_eq!(std::fs::read_dir(store.dir()).unwrap().count(), 0);
}
