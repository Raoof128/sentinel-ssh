use std::time::Duration;

use sentinel_core::error::ErrorCode;
use sentinel_gateway::tools::transfers::{TransferDownloadParams, ssh_transfer_download};
use sentinel_testkit::ctx::ctx_with;
use sentinel_testkit::fake_backend::{FakeBackend, Script};
use sha2::{Digest, Sha256};

fn dl(h: &str, root: &str, path: &str, expected: Option<&str>) -> TransferDownloadParams {
    TransferDownloadParams {
        host_id: h.into(),
        root: root.into(),
        path: path.into(),
        expected_sha256: expected.map(Into::into),
        ..Default::default()
    }
}
fn hex_sha256(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn hash_out(size: usize, digest: &str) -> Vec<u8> {
    format!("{size}\n\n--SENTINEL--\n{digest}  /srv/app/data/blob.bin\n").into_bytes()
}
fn artefact_files(ctx: &sentinel_gateway::tools::AppContext) -> usize {
    std::fs::read_dir(ctx.artifacts.dir()).unwrap().count()
}

#[tokio::test]
async fn download_round_trips_binary_without_exposing_bytes() {
    let data: Vec<u8> = (0..1_048_576u32).map(|i| (i * 7 % 256) as u8).collect();
    let d = hex_sha256(&data);
    let fake = FakeBackend::new()
        .on("sha256sum", hash_out(data.len(), &d))
        .on("cat <&3", data.clone());
    let ctx = ctx_with(fake.clone());
    let e = ssh_transfer_download(&ctx, dl("h1", "app", "data/blob.bin", None)).await.unwrap();
    assert_eq!(e.data.bytes, 1_048_576);
    assert_eq!(e.data.sha256, d);
    let json = serde_json::to_string(&e).unwrap();
    assert!(json.len() < 4096, "bytes leaked into result ({} bytes)", json.len());
    let (bytes, rec) = ctx
        .artifacts
        .read_range(&ctx.principal, &e.data.artifact_id, 0, 65536)
        .await
        .unwrap();
    assert_eq!(bytes, &data[..65536]);
    assert_eq!(rec.sha256, d);
    assert!(e.evidence.iter().any(|x| x.kind == "remote_digest"));
    assert!(e.evidence.iter().any(|x| x.kind == "local_digest"));
    assert!(
        fake.calls()[1].contains("exec 3< 'blob.bin'") && fake.calls()[1].ends_with("cat <&3"),
        "{}",
        fake.calls()[1]
    );
}

#[tokio::test]
async fn zero_byte_file_downloads() {
    let empty = hex_sha256(b"");
    assert!(empty.starts_with("e3b0c442"));
    let fake = FakeBackend::new().on("sha256sum", hash_out(0, &empty)).on("cat <&3", Vec::new());
    let e = ssh_transfer_download(&ctx_with(fake), dl("h1", "app", "data/empty.bin", None))
        .await
        .unwrap();
    assert_eq!(e.data.bytes, 0);
    assert_eq!(e.data.sha256, empty);
}

#[tokio::test]
async fn digest_mismatch_leaves_no_artifact() {
    let fake = FakeBackend::new()
        .on("sha256sum", hash_out(3, &"00".repeat(32)))
        .on("cat <&3", b"abc".to_vec());
    let ctx = ctx_with(fake);
    assert_eq!(
        ssh_transfer_download(&ctx, dl("h1", "app", "x", None)).await.unwrap_err().code,
        ErrorCode::DigestMismatch
    );
    assert_eq!(artefact_files(&ctx), 0);
}

#[tokio::test]
async fn expected_digest_mismatch_is_source_changed() {
    let fake = FakeBackend::new()
        .on("sha256sum", hash_out(3, &hex_sha256(b"abc")))
        .on("cat <&3", b"abc".to_vec());
    let ctx = ctx_with(fake.clone());
    let e = ssh_transfer_download(&ctx, dl("h1", "app", "x", Some(&"11".repeat(32))))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::SourceChanged);
    assert_eq!(fake.calls().len(), 1, "no cat after a digest mismatch");
    assert_eq!(
        ssh_transfer_download(&ctx, dl("h1", "app", "x", Some("zz")))
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
}

#[tokio::test]
async fn export_denied_root_never_reads() {
    let fake = FakeBackend::new();
    let ctx = ctx_with(fake.clone());
    assert_eq!(
        ssh_transfer_download(&ctx, dl("h1", "logs", "api.log", None))
            .await
            .unwrap_err()
            .code,
        ErrorCode::PolicyDenied
    );
    assert_eq!(
        ssh_transfer_download(&ctx, dl("h1", "secrets", "key", None))
            .await
            .unwrap_err()
            .code,
        ErrorCode::PolicyDenied
    );
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn symlink_and_oversize_refused() {
    let sym = FakeBackend::new().on_script(Script {
        matches: "sha256sum".into(),
        stderr: b"SENTINEL_KIND_MISMATCH\n".to_vec(),
        exit: 97,
        ..Default::default()
    });
    assert_eq!(
        ssh_transfer_download(&ctx_with(sym), dl("h1", "app", "escape", None))
            .await
            .unwrap_err()
            .code,
        ErrorCode::PolicyDenied
    );
    let big = FakeBackend::new().on_script(Script {
        matches: "sha256sum".into(),
        stderr: b"SENTINEL_TOO_LARGE\n".to_vec(),
        exit: 98,
        ..Default::default()
    });
    assert_eq!(
        ssh_transfer_download(&ctx_with(big), dl("h1", "app", "big", None))
            .await
            .unwrap_err()
            .code,
        ErrorCode::BudgetExceeded
    );
}

#[tokio::test]
async fn short_stream_is_transfer_partial() {
    let fake = FakeBackend::new()
        .on("sha256sum", hash_out(10, &"ab".repeat(32)))
        .on("cat <&3", b"12345".to_vec());
    let ctx = ctx_with(fake);
    assert_eq!(
        ssh_transfer_download(&ctx, dl("h1", "app", "x", None)).await.unwrap_err().code,
        ErrorCode::TransferPartial
    );
    assert_eq!(artefact_files(&ctx), 0);
}

#[tokio::test]
async fn grown_file_is_source_changed() {
    let fake = FakeBackend::new()
        .on("sha256sum", hash_out(3, &hex_sha256(b"abc")))
        .on("cat <&3", b"abcdef".to_vec());
    let ctx = ctx_with(fake);
    assert_eq!(
        ssh_transfer_download(&ctx, dl("h1", "app", "x", None)).await.unwrap_err().code,
        ErrorCode::SourceChanged
    );
    assert_eq!(artefact_files(&ctx), 0);
}

#[tokio::test]
async fn type_swap_during_stream_is_source_changed() {
    let fake = FakeBackend::new()
        .on("sha256sum", hash_out(3, &hex_sha256(b"abc")))
        .on_script(Script {
            matches: "cat <&3".into(),
            stderr: b"SENTINEL_KIND_MISMATCH\n".to_vec(),
            exit: 97,
            delay: Duration::ZERO,
            ..Default::default()
        });
    let ctx = ctx_with(fake);
    assert_eq!(
        ssh_transfer_download(&ctx, dl("h1", "app", "x", None)).await.unwrap_err().code,
        ErrorCode::SourceChanged
    );
    assert_eq!(artefact_files(&ctx), 0);
}
