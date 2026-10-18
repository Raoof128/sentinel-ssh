//! End-to-end enforcement against the disposable Docker sshd fixture with the real OpenSSH backend.
//! Run: `bash scripts/fixture-up.sh && set -a && . target/fixture/fixture.env && set +a && cargo test --test e2e_fixture`.
//! Without the fixture every test prints `skipped: no ssh fixture` and passes.

use std::sync::Arc;

use sentinel_core::error::{ErrorCode, RetryStrategy};
use sentinel_gateway::config::load_config;
use sentinel_gateway::doctor::run_doctor;
use sentinel_gateway::ssh::openssh::OpenSshBackend;
use sentinel_gateway::tools::AppContext;
use sentinel_gateway::tools::disk::{DiskUsageParams, ssh_disk_usage};
use sentinel_gateway::tools::files::{
    EntryKind, FileHashParams, FileReadParams, FileStatParams, FilesListParams, ssh_file_hash, ssh_file_read, ssh_file_stat, ssh_files_list,
};
use sentinel_gateway::tools::health::{HealthCheckParams, ssh_health_check};
use sentinel_gateway::tools::hosts::{HostInspectParams, ssh_host_inspect};
use sentinel_gateway::tools::logs::{LogsSearchParams, ssh_logs_search};
use sentinel_gateway::tools::processes::{ProcessListParams, ssh_process_list};
use sentinel_gateway::tools::services::{ServiceStatusParams, ssh_service_status};
use sentinel_gateway::tools::transfers::{TransferDownloadParams, ssh_transfer_download};
use sentinel_testkit::configs::TestDirs;
use sentinel_testkit::fixture::SshFixture;

macro_rules! fixture_or_skip {
    () => {
        match SshFixture::from_env() {
            Some(fx) => fx,
            None => {
                eprintln!("skipped: no ssh fixture");
                return;
            }
        }
    };
}

struct E2e {
    ctx: AppContext,
    _dirs: TestDirs,
    config: std::path::PathBuf,
}

fn ctx(fx: &SshFixture, wrong_key: bool) -> E2e {
    let dirs = TestDirs::new();
    let config = fx.write_config(&dirs, wrong_key);
    let cfg = load_config(&config).expect("fixture config loads");
    let backend = OpenSshBackend::new(&cfg.gateway).expect("backend");
    E2e {
        ctx: AppContext::new(cfg, Arc::new(backend)).expect("context"),
        _dirs: dirs,
        config,
    }
}

fn read(root: &str, path: &str) -> FileReadParams {
    FileReadParams {
        host_id: "fx".into(),
        root: root.into(),
        path: path.into(),
        ..Default::default()
    }
}
fn list(root: &str, path: &str) -> FilesListParams {
    FilesListParams {
        host_id: "fx".into(),
        root: root.into(),
        path: path.into(),
        ..Default::default()
    }
}
fn dl(root: &str, path: &str) -> TransferDownloadParams {
    TransferDownloadParams {
        host_id: "fx".into(),
        root: root.into(),
        path: path.into(),
        ..Default::default()
    }
}
fn search(pattern: &str) -> LogsSearchParams {
    LogsSearchParams {
        host_id: "fx".into(),
        source_id: "api".into(),
        pattern: pattern.into(),
        ..Default::default()
    }
}

/// Spec §3.2 outcomes 1-2: diagnose and inspect with typed tools only.
#[tokio::test]
async fn e2e_legitimate_inspection_tasks() {
    let fx = fixture_or_skip!();
    let e = ctx(&fx, false);
    let c = &e.ctx;
    let h = ssh_host_inspect(
        c,
        HostInspectParams {
            host_id: "fx".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(h.data.cpus >= 1);
    assert!(h.data.kernel.starts_with("Linux"));
    assert!(h.data.os_pretty_name.unwrap_or_default().contains("Debian"));
    let d = ssh_disk_usage(
        c,
        DiskUsageParams {
            host_id: "fx".into(),
            root: "app".into(),
            path: Some("data".into()),
            depth: Some(1),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(d.data.entries.iter().any(|x| x.path == "data/blob.bin"), "{:?}", d.data.entries);
    let l = ssh_logs_search(c, search("ERROR db timeout")).await.unwrap();
    assert_eq!(l.data.matches.len(), 3);
    assert_eq!(l.data.matches[0].line_no, 50);
    let f = ssh_files_list(c, list("app", "data")).await.unwrap();
    assert!(f.data.entries.iter().any(|x| x.name == "new\\u{A}line.txt"), "{:?}", f.data.entries);
    assert!(f.data.entries.iter().any(|x| x.name == "données ünï.txt"), "{:?}", f.data.entries);
    let r = ssh_file_read(c, read("app", "config/app.toml")).await.unwrap();
    assert!(r.data.content.contains("[app]"));
    assert!(r.data.eof);
    let hc = ssh_health_check(
        c,
        HealthCheckParams {
            host_id: "fx".into(),
            check_id: "api_http".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(hc.data.passing, "{:?}", hc.data.observation);
    let ps = ssh_process_list(
        c,
        ProcessListParams {
            host_id: "fx".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(ps.data.processes.iter().any(|p| p.command == "sshd"), "{:?}", ps.data.processes);
}

#[tokio::test]
async fn e2e_service_status_without_systemd_is_unsupported() {
    let fx = fixture_or_skip!();
    let e = ctx(&fx, false);
    let err = ssh_service_status(
        &e.ctx,
        ServiceStatusParams {
            host_id: "fx".into(),
            service_id: "api".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::CapabilityUnsupported, "{err:?}");
}

#[tokio::test]
async fn e2e_download_matches_remote_hash_exactly() {
    let fx = fixture_or_skip!();
    let e = ctx(&fx, false);
    let hsh = ssh_file_hash(
        &e.ctx,
        FileHashParams {
            host_id: "fx".into(),
            root: "app".into(),
            path: "data/blob.bin".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let got = ssh_transfer_download(&e.ctx, dl("app", "data/blob.bin")).await.unwrap();
    assert_eq!(got.data.sha256, hsh.data.digest);
    assert_eq!(got.data.bytes, 1_048_576);
    let (first, _) = e
        .ctx
        .artifacts
        .read_range(&e.ctx.principal, &got.data.artifact_id, 0, 16)
        .await
        .unwrap();
    assert_eq!(first.len(), 16);
    let empty = ssh_transfer_download(&e.ctx, dl("app", "data/empty.bin")).await.unwrap();
    assert_eq!(empty.data.bytes, 0);
    assert!(empty.data.sha256.starts_with("e3b0c442"));
}

#[tokio::test]
async fn e2e_scope_and_export_enforcement() {
    let fx = fixture_or_skip!();
    let e = ctx(&fx, false);
    let c = &e.ctx;
    assert_eq!(
        ssh_file_read(c, read("app", "../secrets/key")).await.unwrap_err().code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        ssh_file_read(c, read("secrets", "key")).await.unwrap_err().code,
        ErrorCode::PolicyDenied
    );
    assert_eq!(
        ssh_files_list(c, list("app", "escape")).await.unwrap_err().code,
        ErrorCode::PolicyDenied,
        "symlink to /etc refused"
    );
    assert_eq!(
        ssh_file_read(c, read("app", "escape")).await.unwrap_err().code,
        ErrorCode::PolicyDenied
    );
    // Final review #3: a regular file reached through a symlinked parent (escape -> /etc) is outside the root.
    for (name, code) in [
        (
            "file_read",
            ssh_file_read(c, read("app", "escape/hostname")).await.map(|_| ()).unwrap_err().code,
        ),
        (
            "download",
            ssh_transfer_download(c, dl("app", "escape/hostname"))
                .await
                .map(|_| ())
                .unwrap_err()
                .code,
        ),
        (
            "files_list",
            ssh_files_list(c, list("app", "escape/apt")).await.map(|_| ()).unwrap_err().code,
        ),
        (
            "file_stat",
            ssh_file_stat(
                c,
                FileStatParams {
                    host_id: "fx".into(),
                    root: "app".into(),
                    path: "escape/passwd".into(),
                    ..Default::default()
                },
            )
            .await
            .map(|_| ())
            .unwrap_err()
            .code,
        ),
        (
            "file_hash",
            ssh_file_hash(
                c,
                FileHashParams {
                    host_id: "fx".into(),
                    root: "app".into(),
                    path: "escape/hostname".into(),
                    ..Default::default()
                },
            )
            .await
            .map(|_| ())
            .unwrap_err()
            .code,
        ),
    ] {
        assert_eq!(code, ErrorCode::PolicyDenied, "{name}");
    }
    assert_eq!(
        ssh_transfer_download(c, dl("logs", "api.log")).await.unwrap_err().code,
        ErrorCode::PolicyDenied
    );
    let st = ssh_file_stat(
        c,
        FileStatParams {
            host_id: "fx".into(),
            root: "app".into(),
            path: "escape".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(st.data.kind, EntryKind::Symlink);
    assert_eq!(
        ssh_file_read(c, read("app", "data/nope")).await.unwrap_err().code,
        ErrorCode::NotFound
    );
}

#[tokio::test]
async fn e2e_changed_host_key_never_dispatches() {
    let fx = fixture_or_skip!();
    let e = ctx(&fx, true);
    let err = ssh_host_inspect(
        &e.ctx,
        HostInspectParams {
            host_id: "fx".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::HostKeyChanged, "{err:?}");
    assert_eq!(err.retry, RetryStrategy::Never);
}

/// Spec §17 step 10: an instruction planted in a log cannot widen policy.
#[tokio::test]
async fn e2e_injected_log_line_changes_nothing() {
    let fx = fixture_or_skip!();
    let e = ctx(&fx, false);
    let l = ssh_logs_search(&e.ctx, search("SYSTEM:")).await.unwrap();
    assert_eq!(l.data.matches.len(), 1);
    assert_eq!(l.data.content_trust, "untrusted");
    assert_eq!(
        ssh_transfer_download(&e.ctx, dl("secrets", "key")).await.unwrap_err().code,
        ErrorCode::PolicyDenied
    );
}

/// `doctor` is the synchronous CLI path and builds its own runtime, so this is a plain test.
#[test]
fn e2e_doctor_connect_passes() {
    let fx = fixture_or_skip!();
    let e = ctx(&fx, false);
    let r = run_doctor(&e.config, true);
    assert!(r.checks.iter().any(|c| c.name == "host.fx.connect" && c.ok), "{}", r.render());
    assert!(r.ok(), "{}", r.render());
}

/// 256 MiB download with bounded gateway memory. Needs the fixture built with LARGE=1.
#[tokio::test]
#[ignore = "build the fixture with LARGE=1, then run with --ignored"]
async fn e2e_256mib_download_bounded_memory() {
    let fx = fixture_or_skip!();
    let e = ctx(&fx, false);
    let rss = || -> u64 {
        let out = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().parse::<u64>().unwrap_or(0) * 1024
    };
    let before = rss();
    let hsh = ssh_file_hash(
        &e.ctx,
        FileHashParams {
            host_id: "fx".into(),
            root: "app".into(),
            path: "data/large.bin".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let got = ssh_transfer_download(&e.ctx, dl("app", "data/large.bin")).await.unwrap();
    let after = rss();
    assert_eq!(got.data.bytes, 268_435_456);
    assert_eq!(got.data.sha256, hsh.data.digest);
    assert!(
        after.saturating_sub(before) < 64 * 1024 * 1024,
        "RSS grew by {} bytes",
        after.saturating_sub(before)
    );
}
