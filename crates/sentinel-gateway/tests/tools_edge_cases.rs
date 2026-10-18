//! Edge and failure paths across the tools: malformed remote output, optional parameters, transport failures.

use sentinel_core::error::ErrorCode;
use sentinel_gateway::ssh::command::Marker;
use sentinel_gateway::tools::AppContext;
use sentinel_gateway::tools::disk::{DiskUsageParams, ssh_disk_usage};
use sentinel_gateway::tools::files::{
    EntryKind, FileHashParams, FileStatParams, FilesListParams, ssh_file_hash, ssh_file_stat, ssh_files_list,
};
use sentinel_gateway::tools::health::{HealthCheckParams, ssh_health_check};
use sentinel_gateway::tools::hosts::parse_host_facts;
use sentinel_gateway::tools::logs::{LogsSearchParams, ssh_logs_search};
use sentinel_gateway::tools::processes::{ProcessListParams, ProcessSort, redact_args, ssh_process_list};
use sentinel_gateway::tools::services::{ServiceStatusParams, ssh_service_status};
use sentinel_gateway::tools::transfers::{TransferDownloadParams, ssh_transfer_download};
use sentinel_testkit::configs::{TestDirs, load_minimal};
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

const FACTS: [&str; 7] = [
    "Linux 6.1.0 x86_64",
    "4",
    "0.1 0.2 0.3 1/2 3",
    "Mem: 10 1 1 1 1 9",
    "100.5 1",
    "h",
    "PRETTY_NAME=\"Debian\"",
];

fn sep(mk: &Marker) -> String {
    format!("\n\n{}\n", mk.as_str())
}

fn facts_with(mk: &Marker, i: usize, value: &str) -> String {
    let mut f = FACTS.map(String::from);
    f[i] = value.into();
    f.join(&sep(mk))
}

#[test]
fn host_facts_reject_malformed_sections() {
    let mk = Marker::new();
    assert!(parse_host_facts(&mk, &FACTS.join(&sep(&mk))).is_ok());
    for (i, bad, what) in [
        (0, "Linux", "uname"),
        (1, "many", "nproc"),
        (2, "x y", "loadavg"),
        (3, "Mem: 1 2", "free columns"),
        (3, "Swap: 0", "free"),
        (4, "soon", "uptime"),
    ] {
        let e = parse_host_facts(&mk, &facts_with(&mk, i, bad)).unwrap_err();
        assert_eq!(e.code, ErrorCode::RemoteFailure);
        assert!(e.message.contains(what), "{what}: {}", e.message);
    }
    assert!(
        parse_host_facts(&mk, "only one section")
            .unwrap_err()
            .message
            .contains("sections missing")
    );
    let no_os = FACTS[..6].join(&sep(&mk));
    assert_eq!(parse_host_facts(&mk, &no_os).unwrap().os_pretty_name, None);
}

#[tokio::test]
async fn disk_usage_rejects_malformed_df_and_warns_on_unreadable_subdirs() {
    let bad = FakeBackend::new().on("df -B1", b"weird line\n\n--SENTINEL--\n".to_vec());
    let e = ssh_disk_usage(
        &ctx_with(bad),
        DiskUsageParams {
            host_id: "h1".into(),
            root: "app".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert!(e.message.contains("df columns"), "{}", e.message);
    let denied = FakeBackend::new().on_script(script(
        "df -B1",
        b"/dev/x 100 50 50 50% /\n\n--SENTINEL--\n8\t.\x00",
        b"du: cannot read directory '/srv/app/private': Permission denied\n",
        0,
    ));
    let e = ssh_disk_usage(
        &ctx_with(denied),
        DiskUsageParams {
            host_id: "h1".into(),
            root: "app".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(e.warnings.iter().any(|w| w == "partial_permission_denied"), "{:?}", e.warnings);
}

#[tokio::test]
async fn files_report_special_kinds_and_reject_malformed_output() {
    let ctx = ctx_with(FakeBackend::new().on("find", b"p\t0\t1\t644\tfifo\0s\t0\t1\t755\tsock\0".to_vec()));
    let e = ssh_files_list(
        &ctx,
        FilesListParams {
            host_id: "h1".into(),
            root: "app".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(e.data.entries.iter().all(|x| x.kind == EntryKind::Other));
    let stat = |stdout: &[u8], stderr: &[u8], exit: i32| ctx_with(FakeBackend::new().on_script(script("stat -c", stdout, stderr, exit)));
    let p = || FileStatParams {
        host_id: "h1".into(),
        root: "app".into(),
        path: "x".into(),
        ..Default::default()
    };
    assert_eq!(
        ssh_file_stat(&stat(b"", b"stat: cannot statx 'x': No such file or directory\n", 1), p())
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    assert!(
        ssh_file_stat(&stat(b"garbage\n", b"", 0), p())
            .await
            .unwrap_err()
            .message
            .contains("stat")
    );
    let hash = ctx_with(FakeBackend::new().on("sha256sum", b"5\n\n--SENTINEL--\nnot-a-digest  x\n".to_vec()));
    let e = ssh_file_hash(
        &hash,
        FileHashParams {
            host_id: "h1".into(),
            root: "app".into(),
            path: "x".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert!(e.message.contains("sha256sum"), "{}", e.message);
}

#[tokio::test]
async fn service_active_check_and_user_scope_services() {
    let fake = FakeBackend::new()
        .on("is-active", b"active\n".to_vec())
        .on("systemctl --user show", b"Id=worker.service\nActiveState=inactive\n".to_vec());
    let ctx = ctx_with(fake.clone());
    let e = ssh_health_check(
        &ctx,
        HealthCheckParams {
            host_id: "h1".into(),
            check_id: "api_active".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(e.data.passing);
    assert_eq!(e.data.observation["active_state"], "active");
    let s = ssh_service_status(
        &ctx,
        ServiceStatusParams {
            host_id: "h1".into(),
            service_id: "worker".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(s.data.active_state, "inactive");
    assert!(
        fake.calls().iter().any(|c| c.starts_with("systemctl --user show")),
        "{:?}",
        fake.calls()
    );
    let empty = ctx_with(FakeBackend::new().on("systemctl show", b"\n".to_vec()));
    let e = ssh_service_status(
        &empty,
        ServiceStatusParams {
            host_id: "h1".into(),
            service_id: "api".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert!(e.message.contains("no properties"), "{}", e.message);
}

#[tokio::test]
async fn logs_validate_windows_and_flag_binary_files() {
    let ctx = ctx_with(FakeBackend::new().on("grep -a -F", b"Binary file /var/log/app/api.log matches\n".to_vec()));
    let p = || LogsSearchParams {
        host_id: "h1".into(),
        source_id: "api".into(),
        pattern: "x".into(),
        ..Default::default()
    };
    assert_eq!(
        ssh_logs_search(
            &ctx,
            LogsSearchParams {
                last_bytes: Some(0),
                ..p()
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::InvalidInput
    );
    let e = ssh_logs_search(&ctx, p()).await.unwrap();
    assert!(e.data.matches.is_empty());
    assert!(e.warnings.iter().any(|w| w == "binary_content_skipped"), "{:?}", e.warnings);
}

#[tokio::test]
async fn process_list_filters_sorts_and_skips_malformed_rows() {
    let fake = FakeBackend::new().on("ps -", b"9999\n--SENTINEL--\n1 2 3\n 5 1 app 0.0 0.0 1 x x\n".to_vec());
    let ctx = ctx_with(fake.clone());
    let e = ssh_process_list(
        &ctx,
        ProcessListParams {
            host_id: "h1".into(),
            user: Some("app".into()),
            sort: Some(ProcessSort::Mem),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(e.data.processes.len(), 1, "short rows are skipped");
    ssh_process_list(
        &ctx,
        ProcessListParams {
            host_id: "h1".into(),
            sort: Some(ProcessSort::Pid),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let calls = fake.calls();
    assert!(
        calls[0].contains("ps -u 'app' -o ") && calls[0].contains("--sort=-pmem"),
        "{}",
        calls[0]
    );
    assert!(calls[1].contains("--sort=pid"), "{}", calls[1]);
    assert_eq!(redact_args("app --token "), "app --token ");
}

#[tokio::test]
async fn transport_failures_during_a_download_are_typed() {
    let digest = "ab".repeat(32);
    let hash = format!("3\n\n--SENTINEL--\n{digest}  x\n").into_bytes();
    let p = || TransferDownloadParams {
        host_id: "h1".into(),
        root: "app".into(),
        path: "x".into(),
        ..Default::default()
    };
    let idle = FakeBackend::new().on("sha256sum", hash.clone()).on_script(Script {
        matches: "cat <&3".into(),
        error: Some(ErrorCode::TransferTimeoutIdle),
        ..Default::default()
    });
    assert_eq!(
        ssh_transfer_download(&ctx_with(idle), p()).await.unwrap_err().code,
        ErrorCode::TransferTimeoutIdle
    );
    let dropped = FakeBackend::new().on("sha256sum", hash).on_script(script(
        "cat <&3",
        b"",
        b"Connection to 203.0.113.10 closed by remote host.\n",
        255,
    ));
    let e = ssh_transfer_download(&ctx_with(dropped), p()).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::ConnectionFailed);
    assert!(!e.message.contains("203.0.113.10"), "{}", e.message);
}

#[test]
fn context_refuses_an_open_artifact_directory() {
    use std::os::unix::fs::PermissionsExt;
    let dirs = TestDirs::new();
    let (cfg, _) = load_minimal(&dirs);
    std::fs::create_dir_all(&cfg.gateway.artifact_dir).unwrap();
    std::fs::set_permissions(&cfg.gateway.artifact_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let e = AppContext::new(cfg, std::sync::Arc::new(FakeBackend::new())).err().unwrap();
    assert_eq!(e.code, ErrorCode::ConfigInvalid);
}

#[tokio::test]
async fn unenterable_directories_are_typed_by_cause() {
    let list = |p: &str| FilesListParams {
        host_id: "h1".into(),
        root: "app".into(),
        path: p.into(),
        ..Default::default()
    };
    let cases = [
        (b"SENTINEL_MISSING\n".as_slice(), 91, ErrorCode::NotFound, "not found"),
        (
            b"SENTINEL_NO_ACCESS\n".as_slice(),
            92,
            ErrorCode::RemoteFailure,
            "permission denied",
        ),
        (b"SENTINEL_KIND_MISMATCH\n".as_slice(), 97, ErrorCode::PolicyDenied, "are refused"),
    ];
    for (stderr, exit, code, msg) in cases {
        let ctx = ctx_with(FakeBackend::new().on_script(script("find", b"", stderr, exit)));
        let e = ssh_files_list(&ctx, list("d")).await.unwrap_err();
        assert_eq!(e.code, code, "exit {exit}");
        assert!(e.message.contains(msg), "exit {exit}: {}", e.message);
    }
    // The marker without its exit status is ordinary remote output, not a refusal.
    let ctx = ctx_with(FakeBackend::new().on_script(script("find", b"", b"SENTINEL_NO_ACCESS\n", 1)));
    assert!(
        !ssh_files_list(&ctx, list("d"))
            .await
            .unwrap_err()
            .message
            .contains("permission denied")
    );
}

#[tokio::test]
async fn excluded_roots_are_skipped_refused_or_checked_by_pin() {
    // Root `secrets` (read = false) is excluded for every read below.
    let fake = FakeBackend::new();
    let ctx = ctx_with(fake.clone());
    let _ = ssh_files_list(
        &ctx,
        FilesListParams {
            host_id: "h1".into(),
            root: "app".into(),
            ..Default::default()
        },
    )
    .await;
    let _ = ssh_file_stat(
        &ctx,
        FileStatParams {
            host_id: "h1".into(),
            root: "app".into(),
            path: "data".into(),
            ..Default::default()
        },
    )
    .await;
    let _ = ssh_disk_usage(
        &ctx,
        DiskUsageParams {
            host_id: "h1".into(),
            root: "app".into(),
            ..Default::default()
        },
    )
    .await;
    let calls = fake.calls();
    let [list, stat, du] = &calls[..] else { panic!("{calls:?}") };
    assert!(
        list.contains("set --; if x=$(rp '/srv/secrets'); then set -- \"$@\" ! -samefile \"$x\"; fi;"),
        "{list}"
    );
    assert!(list.contains("-maxdepth 1 \"$@\" -printf"), "{list}");
    assert!(
        stat.contains("e=\"$w\"/'data'; if x=$(rp '/srv/secrets'); then if inside \"$e\" \"$x\"; then deny SENTINEL_EXCLUDED 93"),
        "{stat}"
    );
    assert!(
        du.contains("if inside \"$x\" \"$w\"; then deny SENTINEL_NESTED_EXCLUDED 90; fi;"),
        "{du}"
    );
    assert!(!du.contains("\"$@\""), "{du}");

    let refused = ctx_with(FakeBackend::new().on_script(script("du", b"", b"SENTINEL_NESTED_EXCLUDED\n", 90)));
    let e = ssh_disk_usage(
        &refused,
        DiskUsageParams {
            host_id: "h1".into(),
            root: "app".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::PolicyDenied);
    assert!(e.message.contains("contains a root"), "{}", e.message);
}

/// Red team M3: stderr is partly remote-controlled (file names in error messages). Capability errors are recognised
/// only in the exact formats the shell and GNU tools print, for programs the command actually ran.
#[tokio::test]
async fn spoofed_capability_messages_in_stderr_are_not_trusted() {
    let list = || FilesListParams {
        host_id: "h1".into(),
        root: "app".into(),
        ..Default::default()
    };
    for stderr in [
        // A file name that embeds a fake shell message on its own line.
        b"find: './x\nsh: 1: grep: not found': Permission denied\n".as_slice(),
        b"find: './x\ngrep: unrecognized option '--evil'\n".as_slice(),
        b"find: 'System has not been booted with systemd as init system (PID 1). Can't operate.'\n".as_slice(),
        b"find: './Failed to connect to bus': Permission denied\n".as_slice(),
        b"find: './x: not found trailing'\n".as_slice(),
    ] {
        let ctx = ctx_with(FakeBackend::new().on_script(script("find", b"", stderr, 1)));
        let e = ssh_files_list(&ctx, list()).await.unwrap_err();
        assert_ne!(
            e.code,
            ErrorCode::CapabilityUnsupported,
            "{}: {e:?}",
            String::from_utf8_lossy(stderr)
        );
    }
    // The genuine formats, for a program the command ran, are still recognised.
    for stderr in [
        b"sh: 1: find: not found\n".as_slice(),
        b"find: unrecognized option '-printf'\n".as_slice(),
    ] {
        let ctx = ctx_with(FakeBackend::new().on_script(script("find", b"", stderr, 127)));
        let e = ssh_files_list(&ctx, list()).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::CapabilityUnsupported, "{e:?}");
    }
}

/// Red team L1: every remote-sourced string is display-escaped and every result that carries one says so.
#[test]
fn host_facts_escape_every_remote_string() {
    let mk = Marker::new();
    let f = parse_host_facts(&mk, &facts_with(&mk, 0, "Linux 6.1\u{202E}x x86\u{200B}64")).unwrap();
    assert_eq!(f.kernel, "Linux 6.1\\u{202E}x");
    assert_eq!(f.arch, "x86\\u{200B}64");
    assert_eq!(f.content_trust, "untrusted");
}

#[tokio::test]
async fn service_disk_and_stat_results_are_escaped_and_marked_untrusted() {
    let svc_out = b"Id=app-api.service\nActiveState=act\xe2\x80\xaeive\nSubState=run\x1bning\nLoadState=loaded\nResult=success\nMainPID=1\nNRestarts=0\nActiveEnterTimestamp=Sat\xe2\x80\x8b\n".to_vec();
    let ctx = ctx_with(FakeBackend::new().on("systemctl show", svc_out));
    let s = ssh_service_status(
        &ctx,
        ServiceStatusParams {
            host_id: "h1".into(),
            service_id: "api".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(s.data.active_state, "act\\u{202E}ive");
    assert_eq!(s.data.sub_state, "run\\u{1B}ning");
    assert_eq!(s.data.active_enter_timestamp.as_deref(), Some("Sat\\u{200B}"));
    assert_eq!(s.data.content_trust, "untrusted");

    let stat = ctx_with(FakeBackend::new().on("stat -c", b"regular file|3|644|u|g|1700000000|1\n".to_vec()));
    let st = ssh_file_stat(
        &stat,
        FileStatParams {
            host_id: "h1".into(),
            root: "app".into(),
            path: "x".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(st.data.content_trust, "untrusted");
}

/// Red team L7: a usage figure that skipped unreadable subtrees is an undercount, so the result says partial.
#[tokio::test]
async fn disk_usage_with_unreadable_subtrees_is_partial() {
    use sentinel_core::envelope::Outcome;
    let mk_df = "Filesystem 1-blocks Used Available Capacity Mounted on\n/dev/x 100 50 50 50% /srv\n";
    let fake = FakeBackend::new().on_script(Script {
        matches: "du ".into(),
        stdout: format!("{mk_df}\n--SENTINEL--\n10\t.\x005\t./a\x00").into_bytes(),
        stderr: b"du: cannot read directory './private': Permission denied\n".to_vec(),
        exit: 1,
        ..Default::default()
    });
    let e = ssh_disk_usage(
        &ctx_with(fake),
        DiskUsageParams {
            host_id: "h1".into(),
            root: "app".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(e.outcome, Outcome::Partial);
    assert!(
        e.warnings.iter().any(|w| w.contains("partial_permission_denied")),
        "{:?}",
        e.warnings
    );
    assert_eq!(e.data.content_trust, "untrusted");
}
