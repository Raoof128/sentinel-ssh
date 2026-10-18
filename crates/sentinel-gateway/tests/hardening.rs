//! Hardening from the final review's minor findings and the red-team pass. Each test names the attack it pins.

use std::time::Duration;

use sentinel_core::error::ErrorCode;
use sentinel_core::operation::OperationState;
use sentinel_gateway::config::HostKey;
use sentinel_gateway::tools::artifacts::{ArtifactReadParams, ssh_artifact_read};
use sentinel_gateway::tools::disk::{DiskUsageParams, ssh_disk_usage};
use sentinel_gateway::tools::files::{FileReadParams, ssh_file_read};
use sentinel_gateway::tools::health::{HealthCheckParams, ssh_health_check};
use sentinel_gateway::tools::hosts::{HostInspectParams, ssh_host_inspect};
use sentinel_gateway::tools::logs::{LogsSearchParams, ssh_logs_search};
use sentinel_gateway::tools::services::{ServiceStatusParams, ssh_service_status};
use sentinel_testkit::ctx::ctx_with;
use sentinel_testkit::fake_backend::{FakeBackend, Script};

fn script(matches: &str, stdout: &[u8], stderr: &[u8], exit: i32) -> Script {
    Script {
        matches: matches.into(),
        stdout: stdout.to_vec(),
        stderr: stderr.to_vec(),
        exit,
        ..Default::default()
    }
}

/// A filename with a newline must not split into a fake du entry.
#[tokio::test]
async fn du_output_is_nul_separated() {
    let fake = FakeBackend::new().on("df -B1", b"/dev/x 100 50 50 50% /\n\n--SENTINEL--\n9\t.\x005\t./a\nb\x00".to_vec());
    let ctx = ctx_with(fake.clone());
    let e = ssh_disk_usage(
        &ctx,
        DiskUsageParams {
            host_id: "h1".into(),
            root: "app".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(e.data.entries.iter().map(|x| x.path.as_str()).collect::<Vec<_>>(), ["a\\u{A}b"]);
    assert!(fake.calls()[0].contains("du -x -P -a -0 -B1"), "{}", fake.calls()[0]);
    assert!(
        fake.calls()[0].contains("sort -z -rn") && fake.calls()[0].contains("head -z -n"),
        "{}",
        fake.calls()[0]
    );
}

/// Offsets near u64::MAX overflowed `offset + 1` (debug panic, release wrap to byte 0).
#[tokio::test]
async fn huge_offsets_are_rejected_before_dispatch() {
    let fake = FakeBackend::new();
    let ctx = ctx_with(fake.clone());
    let p = FileReadParams {
        host_id: "h1".into(),
        root: "app".into(),
        path: "x".into(),
        offset: Some(u64::MAX),
        ..Default::default()
    };
    assert_eq!(ssh_file_read(&ctx, p).await.unwrap_err().code, ErrorCode::InvalidInput);
    let a = ArtifactReadParams {
        artifact_id: sentinel_core::identity::ArtifactId::generate().to_string(),
        offset: Some(u64::MAX),
        ..Default::default()
    };
    assert_eq!(ssh_artifact_read(&ctx, a).await.unwrap_err().code, ErrorCode::InvalidInput);
    assert!(fake.calls().is_empty());
}

/// Remote hostname and OS name are untrusted text: escaped like every other remote string.
#[tokio::test]
async fn host_facts_strings_are_escaped() {
    let out = "Linux 6.1 x86_64\n\n--SENTINEL--\n2\n\n--SENTINEL--\n0 0 0 1/1 1\n\n--SENTINEL--\nMem: 1 1 1 1 1 1\n\n--SENTINEL--\n5 5\n\n--SENTINEL--\nhost\x1b[31mred\n\n--SENTINEL--\nPRETTY_NAME=\"Deb\u{202e}ian\"\n";
    let e = ssh_host_inspect(
        &ctx_with(FakeBackend::new().on("uname", out.as_bytes().to_vec())),
        HostInspectParams {
            host_id: "h1".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(e.data.hostname, "host\\u{1B}[31mred");
    assert_eq!(e.data.os_pretty_name.as_deref(), Some("Deb\\u{202E}ian"));
}

/// curl must not read the remote account's ~/.curlrc (which could redirect the check or send data elsewhere).
#[tokio::test]
async fn health_check_curl_ignores_curlrc() {
    let fake = FakeBackend::new().on("curl", b"200".to_vec());
    ssh_health_check(
        &ctx_with(fake.clone()),
        HealthCheckParams {
            host_id: "h1".into(),
            check_id: "api_http".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(fake.calls()[0].starts_with("curl -q -sS "), "{}", fake.calls()[0]);
}

/// A pinned key whose blob encodes a different algorithm is a config error, not a runtime HOST_KEY_CHANGED.
#[test]
fn host_key_type_must_match_its_blob() {
    // TEST_HOST_KEY's blob starts with the string "ssh-ed25519".
    let e = "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIExample".parse::<HostKey>().unwrap_err();
    assert!(e.message.contains("does not match"), "{}", e.message);
    assert!(sentinel_testkit::configs::TEST_HOST_KEY.parse::<HostKey>().is_ok());
}

/// Newer GNU grep reports binary matches on stderr.
#[tokio::test]
async fn grep_binary_notice_on_stderr_is_a_warning() {
    let fake = FakeBackend::new().on_script(script("grep -a -F", b"", b"grep: /var/log/app/api.log: binary file matches\n", 0));
    let e = ssh_logs_search(
        &ctx_with(fake),
        LogsSearchParams {
            host_id: "h1".into(),
            source_id: "api".into(),
            pattern: "x".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(e.warnings.iter().any(|w| w == "binary_content_skipped"), "{:?}", e.warnings);
}

/// "Failed to connect to bus" for a user-scope unit means no user session, not "host is not running systemd".
#[tokio::test]
async fn missing_user_session_bus_is_described_accurately() {
    let fake = FakeBackend::new().on_script(script("systemctl --user", b"", b"Failed to connect to bus: No medium found\n", 1));
    let e = ssh_service_status(
        &ctx_with(fake),
        ServiceStatusParams {
            host_id: "h1".into(),
            service_id: "worker".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::CapabilityUnsupported);
    assert!(e.message.contains("user session"), "{}", e.message);
}

/// Cancelling an operation that is still waiting for a slot stops it before anything is dispatched.
#[tokio::test]
async fn cancelling_a_queued_operation_never_dispatches_it() {
    let fake = FakeBackend::new().on_script(Script {
        matches: "uname".into(),
        delay: Duration::from_secs(3),
        ..Default::default()
    });
    let ctx = ctx_with(fake.clone());
    let mut busy = Vec::new();
    for _ in 0..4 {
        let c = ctx.ctx.clone();
        busy.push(tokio::spawn(async move {
            ssh_host_inspect(
                &c,
                HostInspectParams {
                    host_id: "h1".into(),
                    ..Default::default()
                },
            )
            .await
        }));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let c = ctx.ctx.clone();
    let queued = tokio::spawn(async move {
        ssh_host_inspect(
            &c,
            HostInspectParams {
                host_id: "h1".into(),
                ..Default::default()
            },
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let rec = ctx
        .operations
        .list_for(&ctx.principal)
        .into_iter()
        .find(|r| r.state == OperationState::Queued)
        .expect("one op is queued");
    ctx.operations.cancel(&ctx.principal, &rec.id).unwrap();
    let r = tokio::time::timeout(Duration::from_millis(500), queued)
        .await
        .expect("queued op ends promptly")
        .unwrap();
    assert!(r.unwrap_err().details.get("cancelled").is_some());
    assert_eq!(
        ctx.operations.get(&ctx.principal, &rec.id).unwrap().state,
        OperationState::Cancelled
    );
    assert_eq!(fake.calls().len(), 4, "the cancelled operation was never dispatched");
    for b in busy {
        let _ = b.await;
    }
}

/// A download larger than the remaining artefact quota is refused before any bytes move.
#[tokio::test]
async fn download_over_quota_is_refused_before_streaming() {
    use sentinel_gateway::tools::transfers::{TransferDownloadParams, ssh_transfer_download};
    let hash = format!("2000000000\n\n--SENTINEL--\n{}  x\n", "ab".repeat(32)).into_bytes();
    let fake = FakeBackend::new().on("sha256sum", hash);
    let ctx = ctx_with(fake.clone());
    let e = ssh_transfer_download(
        &ctx,
        TransferDownloadParams {
            host_id: "h1".into(),
            root: "app".into(),
            path: "x".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::BudgetExceeded);
    assert_eq!(fake.calls().len(), 1, "no cat after the quota check");
}
