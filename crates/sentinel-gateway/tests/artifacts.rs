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

#[tokio::test]
async fn a_failed_publish_leaves_no_partial_bytes() {
    use std::os::unix::fs::PermissionsExt;
    let (_d, store) = fresh();
    let mut w = store.begin_write(&me().id, origin(), ContentKind::Binary).unwrap();
    w.write_all(b"abc").await.unwrap();
    w.shutdown().await.unwrap();
    std::fs::set_permissions(store.dir(), std::fs::Permissions::from_mode(0o500)).unwrap();
    let r = w.finish(None).await;
    std::fs::set_permissions(store.dir(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(r.unwrap_err().code, ErrorCode::Internal);
    assert!(
        std::fs::read_dir(store.dir())
            .unwrap()
            .all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".bin"))
    );
}

#[tokio::test]
async fn sweep_skips_files_it_cannot_parse() {
    let d = tempfile::tempdir().unwrap();
    let store = ArtifactStore::open(&d.path().join("art"), Duration::ZERO).unwrap();
    std::fs::write(store.dir().join("junk.json"), b"not json").unwrap();
    std::fs::write(store.dir().join("note.txt"), b"x").unwrap();
    assert_eq!(store.sweep_expired().unwrap(), 0);
    assert!(store.dir().join("junk.json").exists());
}

/// Escaping can make a preview larger than its byte budget; the bound shrinks it until the whole envelope fits.
#[tokio::test]
async fn heavily_escaped_previews_still_fit_the_limit() {
    let (_d, store) = fresh();
    let env = ResultEnvelope::succeeded(OperationId::generate(), None, serde_json::json!({ "q": "\"\\".repeat(6000) }));
    let b = bound_envelope(&store, &me().id, env, Detail::Concise, &Budgets::default())
        .await
        .unwrap();
    assert!(b.truncated);
    assert!(serde_json::to_vec(&b).unwrap().len() <= 8192);
}

/// When the data itself is small but the envelope is large (many warnings), the preview is the whole data.
#[tokio::test]
async fn small_data_in_a_large_envelope_previews_whole() {
    let (_d, store) = fresh();
    let mut env = ResultEnvelope::succeeded(OperationId::generate(), None, serde_json::json!({ "a": 1 }));
    env.warnings = (0..600).map(|i| format!("warning-number-{i}")).collect();
    let b = bound_envelope(&store, &me().id, env, Detail::Concise, &Budgets::default())
        .await
        .unwrap();
    assert!(
        serde_json::to_vec(&b).unwrap().len() <= 8192,
        "the size bound holds whatever the warnings"
    );
    assert!(
        b.warnings.len() <= 17 && b.warnings.iter().any(|w| w == "warnings_truncated"),
        "{:?}",
        b.warnings.len()
    );
    assert_eq!(b.data.unwrap()["a"], 1, "once the warnings are capped the small data fits inline");
}

#[test]
fn inline_bound_accepts_small_results_at_either_detail() {
    for d in [Detail::Concise, Detail::Full] {
        let env = ResultEnvelope::succeeded(OperationId::generate(), None, serde_json::json!({ "a": 1 }));
        let b = sentinel_gateway::mcp::results::bound_envelope_inline(env, d, &Budgets::default()).unwrap();
        assert_eq!(b.data.unwrap()["a"], 1);
    }
}

/// Hardening (spec §9.3 "per-principal byte/disk quotas"): artefacts cannot grow without bound.
#[tokio::test]
async fn per_principal_quota_is_enforced() {
    let d = tempfile::tempdir().unwrap();
    let store = ArtifactStore::open(&d.path().join("art"), Duration::from_secs(3600))
        .unwrap()
        .with_quota(10);
    store.put_bytes(&me().id, origin(), ContentKind::Binary, &[1; 6]).await.unwrap();
    let e = store.put_bytes(&me().id, origin(), ContentKind::Binary, &[1; 6]).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::BudgetExceeded);
    assert!(e.message.contains("quota"), "{}", e.message);
    store.put_bytes(&other().id, origin(), ContentKind::Binary, &[1; 6]).await.unwrap();
    assert_eq!(store.ensure_quota(&me().id, 4).unwrap(), ());
    assert_eq!(store.ensure_quota(&me().id, 5).unwrap_err().code, ErrorCode::BudgetExceeded);
}

/// Hardening: partial files left by an interrupted write are swept once older than the retention period.
#[tokio::test]
async fn stale_partial_files_are_swept() {
    let d = tempfile::tempdir().unwrap();
    let store = ArtifactStore::open(&d.path().join("art"), Duration::ZERO).unwrap();
    std::fs::write(store.dir().join("art_x.part"), b"half").unwrap();
    std::fs::write(store.dir().join("art_x.json.part"), b"{").unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    store.sweep_expired().unwrap();
    assert_eq!(std::fs::read_dir(store.dir()).unwrap().count(), 0);
    let keep = ArtifactStore::open(&d.path().join("art2"), Duration::from_secs(3600)).unwrap();
    std::fs::write(keep.dir().join("art_y.part"), b"in progress").unwrap();
    keep.sweep_expired().unwrap();
    assert!(keep.dir().join("art_y.part").exists(), "a write in progress is not touched");
}

/// Security review: check-then-write let two concurrent downloads both pass the quota. Reservations are atomic and
/// shared by every clone of the store; they are released when dropped.
#[tokio::test]
async fn quota_reservations_are_atomic_across_clones() {
    let d = tempfile::tempdir().unwrap();
    let store = ArtifactStore::open(&d.path().join("art"), Duration::from_secs(3600))
        .unwrap()
        .with_quota(10);
    let clone = store.clone();
    let first = store.reserve(&me().id, 6).unwrap();
    assert_eq!(
        clone.reserve(&me().id, 6).unwrap_err().code,
        ErrorCode::BudgetExceeded,
        "the second reservation sees the first"
    );
    assert!(clone.reserve(&other().id, 6).is_ok(), "quotas are per principal");
    drop(first);
    assert!(clone.reserve(&me().id, 6).is_ok(), "dropping a reservation releases it");
}
