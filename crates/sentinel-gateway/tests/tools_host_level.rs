use std::time::Duration;

use sentinel_core::error::{ErrorCode, RetryStrategy};
use sentinel_core::identity::OperationId;
use sentinel_core::operation::OperationState;
use sentinel_gateway::tools::TOOL_NAMES;
use sentinel_gateway::tools::capabilities::{CapabilitiesParams, ssh_capabilities_get};
use sentinel_gateway::tools::disk::{DiskUsageParams, ssh_disk_usage};
use sentinel_gateway::tools::health::{HealthCheckParams, ssh_health_check};
use sentinel_gateway::tools::hosts::{HostInspectParams, HostsListParams, ssh_host_inspect, ssh_hosts_list};
use sentinel_gateway::tools::processes::{ProcessListParams, redact_args, ssh_process_list};
use sentinel_gateway::tools::services::{ServiceStatusParams, ssh_service_status};
use sentinel_testkit::ctx::ctx_with;
use sentinel_testkit::fake_backend::{FakeBackend, Script};

const SERVICE_OUT: &[u8] = b"MainPID=1234\nId=app-api.service\nActiveState=active\nSubState=running\nLoadState=loaded\nResult=success\nNRestarts=0\nActiveEnterTimestamp=Sat 2026-10-18 01:00:00 UTC\n";

fn inspect(h: &str) -> HostInspectParams {
    HostInspectParams {
        host_id: h.into(),
        ..Default::default()
    }
}
fn svc(h: &str, s: &str) -> ServiceStatusParams {
    ServiceStatusParams {
        host_id: h.into(),
        service_id: s.into(),
        ..Default::default()
    }
}
fn ps(h: &str) -> ProcessListParams {
    ProcessListParams {
        host_id: h.into(),
        ..Default::default()
    }
}
fn du(h: &str, root: &str, path: Option<&str>) -> DiskUsageParams {
    DiskUsageParams {
        host_id: h.into(),
        root: root.into(),
        path: path.map(Into::into),
        ..Default::default()
    }
}
fn exit_script(matches: &str, stderr: &[u8], exit: i32) -> Script {
    Script {
        matches: matches.into(),
        stdout: vec![],
        stderr: stderr.to_vec(),
        exit,
        delay: Duration::ZERO,
        error: None,
    }
}

#[test]
fn tool_names_are_the_seventeen_sorted() {
    assert_eq!(TOOL_NAMES.len(), 17);
    let mut sorted = TOOL_NAMES.to_vec();
    sorted.sort();
    assert_eq!(sorted, TOOL_NAMES);
    assert!(TOOL_NAMES.contains(&"ssh_transfer_download"));
}

#[tokio::test]
async fn hosts_list_hides_credentials() {
    let ctx = ctx_with(FakeBackend::new());
    let e = ssh_hosts_list(&ctx, HostsListParams::default()).await.unwrap();
    let v = serde_json::to_value(&e).unwrap();
    assert_eq!(v["data"]["hosts"][0]["host_id"], "h1");
    assert_eq!(v["data"]["hosts"][0]["export_roots"], serde_json::json!(["app"]));
    let s = v.to_string();
    assert!(!s.contains("203.0.113.10"));
    assert!(!s.contains("sentinel-observer"));
    assert!(!s.contains("AAAAC3"));
    assert!(!s.contains("id_test"));
}

#[tokio::test]
async fn hosts_list_paginates() {
    let ctx = ctx_with(FakeBackend::new());
    let e = ssh_hosts_list(
        &ctx,
        HostsListParams {
            cursor: Some("h1".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(e.data.hosts.is_empty());
    assert_eq!(
        ssh_hosts_list(
            &ctx,
            HostsListParams {
                limit: Some(101),
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
async fn host_inspect_parses_fixture_output() {
    let fake = FakeBackend::new().on("uname -srm", include_bytes!("fixtures/host_inspect.txt").to_vec());
    let e = ssh_host_inspect(&ctx_with(fake), inspect("h1")).await.unwrap();
    assert_eq!(e.data.cpus, 4);
    assert_eq!(e.data.kernel, "Linux 6.1.0-28-amd64");
    assert_eq!(e.data.arch, "x86_64");
    assert_eq!(e.data.hostname, "staging-api-1");
    assert_eq!(e.data.mem_total_bytes, 8_323_567_616);
    assert_eq!(e.data.mem_available_bytes, 6_012_342_272);
    assert_eq!(e.data.uptime_seconds, 86400);
    assert!((e.data.load_1m - 0.42).abs() < 1e-9);
    assert_eq!(e.data.os_pretty_name.as_deref(), Some("Debian GNU/Linux 12 (bookworm)"));
    assert_eq!(e.evidence[0].kind, "ssh_host_inspect");
}

#[tokio::test]
async fn unknown_host_never_connects() {
    let fake = FakeBackend::new();
    let ctx = ctx_with(fake.clone());
    let e = ssh_host_inspect(&ctx, inspect("ghost")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::PolicyDenied);
    assert!(fake.calls().is_empty());
    let rec = ctx
        .operations
        .get(&ctx.principal, &OperationId::parse(e.operation_id.as_deref().unwrap()).unwrap())
        .unwrap();
    assert_eq!(rec.state, OperationState::Rejected);
}

#[tokio::test]
async fn invalid_host_id_is_invalid_input() {
    let fake = FakeBackend::new();
    assert_eq!(
        ssh_host_inspect(&ctx_with(fake.clone()), inspect("../h1")).await.unwrap_err().code,
        ErrorCode::InvalidInput
    );
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn service_status_uses_registered_unit_only() {
    let fake = FakeBackend::new().on("systemctl show", SERVICE_OUT.to_vec());
    let ctx = ctx_with(fake.clone());
    let e = ssh_service_status(&ctx, svc("h1", "api")).await.unwrap();
    assert_eq!(e.data.active_state, "active");
    assert_eq!(e.data.main_pid, 1234);
    assert_eq!(e.data.unit, "app-api.service");
    assert!(fake.calls()[0].ends_with("-- 'app-api.service'"), "{}", fake.calls()[0]);
    assert!(!fake.calls()[0].contains("--user"));
    assert_eq!(
        ssh_service_status(&ctx, svc("h1", "sshd")).await.unwrap_err().code,
        ErrorCode::PolicyDenied
    );
    assert_eq!(fake.calls().len(), 1);
}

#[tokio::test]
async fn service_status_without_systemd_is_capability_unsupported() {
    let fake = FakeBackend::new().on_script(exit_script("systemctl", b"sh: 1: systemctl: not found\n", 127));
    let e = ssh_service_status(&ctx_with(fake), svc("h1", "api")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::CapabilityUnsupported);
    assert!(e.message.contains("systemctl"), "{}", e.message);
}

#[tokio::test]
async fn systemctl_in_container_without_systemd_init_is_unsupported() {
    let fake = FakeBackend::new().on_script(exit_script(
        "systemctl",
        b"System has not been booted with systemd as init system (PID 1). Can't operate.\n",
        1,
    ));
    assert_eq!(
        ssh_service_status(&ctx_with(fake), svc("h1", "api")).await.unwrap_err().code,
        ErrorCode::CapabilityUnsupported
    );
}

#[tokio::test]
async fn process_list_redacts_and_paginates() {
    let fake = FakeBackend::new().on(
        "ps -eo",
        b"  1 0 root 0.0 0.1 5000 systemd /sbin/init\n 42 1 app 3.5 1.2 300 node node server.js --token=abc123SECRET\n".to_vec(),
    );
    let ctx = ctx_with(fake.clone());
    let e = ssh_process_list(
        &ctx,
        ProcessListParams {
            limit: Some(10),
            ..ps("h1")
        },
    )
    .await
    .unwrap();
    assert_eq!(e.data.processes.len(), 2);
    assert_eq!(e.data.processes[1].pid, 42);
    assert_eq!(e.data.processes[1].command, "node");
    assert_eq!(e.data.processes[1].args_redacted, "node server.js --token=[REDACTED]");
    assert_eq!(e.data.content_trust, "untrusted");
    assert!(fake.calls()[0].contains("head -n 10"));
    assert_eq!(
        ssh_process_list(
            &ctx,
            ProcessListParams {
                limit: Some(201),
                ..ps("h1")
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        ssh_process_list(
            &ctx,
            ProcessListParams {
                user: Some("root; reboot".into()),
                ..ps("h1")
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::InvalidInput
    );
}

#[test]
fn redaction_examples() {
    assert_eq!(
        redact_args("app --password=hunter2 --port 80"),
        "app --password=[REDACTED] --port 80"
    );
    assert_eq!(redact_args("app --token abc"), "app --token [REDACTED]");
    assert_eq!(
        redact_args("curl https://bob:pw123@example.com/x"),
        "curl https://bob:[REDACTED]@example.com/x"
    );
    assert_eq!(redact_args("mysql -uroot -psecretpw db"), "mysql -uroot -p[REDACTED] db");
    assert_eq!(redact_args("nginx -c /etc/nginx.conf -p /srv"), "nginx -c /etc/nginx.conf -p /srv");
    assert_eq!(redact_args("svc API_KEY=abcdefghijklmnopqrstuvwxyz"), "svc API_KEY=[REDACTED]");
    assert_eq!(redact_args("svc --license-key=0123456789abcdef"), "svc --license-key=[REDACTED]");
}

#[tokio::test]
async fn process_list_non_utf8_args_do_not_fail() {
    let fake = FakeBackend::new().on("ps -eo", b" 7 1 app 0.0 0.0 1 x caf\xe9\n".to_vec());
    let e = ssh_process_list(&ctx_with(fake), ps("h1")).await.unwrap();
    assert!(e.warnings.contains(&"non_utf8_replaced".to_string()));
    assert_eq!(e.data.processes[0].args_redacted, "caf\u{FFFD}");
}

#[tokio::test]
async fn disk_usage_is_root_scoped() {
    let fake = FakeBackend::new().on("df -B1", include_bytes!("fixtures/du.txt").to_vec());
    let ctx = ctx_with(fake.clone());
    let e = ssh_disk_usage(&ctx, du("h1", "app", Some("data"))).await.unwrap();
    assert!(
        fake.calls()[0].contains("enter '/srv/app/data'") && fake.calls()[0].contains("du -x -P -a -0 -B1 -d 1 -- '.'"),
        "{}",
        fake.calls()[0]
    );
    // e2e finding: `du -d N` lists only directories; -a is needed for files.
    assert!(fake.calls()[0].contains("du -x -P -a -0 -B1"), "{}", fake.calls()[0]);
    assert_eq!(e.data.entries[0].path, "data/blob.bin");
    assert_eq!(e.data.entries[0].bytes, 1_048_576);
    assert_eq!(e.data.total_bytes, 1_052_672);
    assert_eq!(e.data.filesystem.total_bytes, 123_690_532_864);
    assert_eq!(e.data.filesystem.mount, "/");
    assert_eq!(
        ssh_disk_usage(&ctx, du("h1", "app", Some("../etc"))).await.unwrap_err().code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        ssh_disk_usage(&ctx, du("h1", "secrets", None)).await.unwrap_err().code,
        ErrorCode::PolicyDenied
    );
    assert_eq!(
        ssh_disk_usage(
            &ctx,
            DiskUsageParams {
                depth: Some(4),
                ..du("h1", "app", None)
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::InvalidInput
    );
    assert_eq!(fake.calls().len(), 1);
}

#[tokio::test]
async fn disk_usage_missing_du_in_pipeline_is_unsupported() {
    // `du | sort | head` exits 0 when du is missing; the stderr line is the only signal.
    let fake = FakeBackend::new().on_script(Script {
        matches: "df -B1".into(),
        stdout: b"/dev/x 1 1 1 1% /\n\n--SENTINEL--\n".to_vec(),
        stderr: b"sh: 1: du: not found\n".to_vec(),
        exit: 0,
        delay: Duration::ZERO,
        error: None,
    });
    let e = ssh_disk_usage(&ctx_with(fake), du("h1", "app", None)).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::CapabilityUnsupported);
    assert!(e.message.contains("du"));
}

#[tokio::test]
async fn health_check_uses_registered_url_only() {
    let fake = FakeBackend::new().on("curl", b"200".to_vec());
    let ctx = ctx_with(fake.clone());
    let e = ssh_health_check(
        &ctx,
        HealthCheckParams {
            host_id: "h1".into(),
            check_id: "api_http".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(e.data.passing);
    assert_eq!(e.data.observation["status_code"], 200);
    assert!(fake.calls()[0].contains("'http://127.0.0.1:8080/health'"));
    let e = ssh_health_check(
        &ctx,
        HealthCheckParams {
            host_id: "h1".into(),
            check_id: "nope".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::PolicyDenied);
}

#[tokio::test]
async fn health_check_failure_is_a_result_not_an_error() {
    let fake = FakeBackend::new().on_script(Script {
        matches: "curl".into(),
        stdout: b"000".to_vec(),
        stderr: b"curl: (7) Failed to connect\n".to_vec(),
        exit: 7,
        delay: Duration::ZERO,
        error: None,
    });
    let e = ssh_health_check(
        &ctx_with(fake),
        HealthCheckParams {
            host_id: "h1".into(),
            check_id: "api_http".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(!e.data.passing);
    assert_eq!(e.data.observation["curl_exit"], 7);
}

#[tokio::test]
async fn capabilities_state_weaker_guarantee() {
    let e = ssh_capabilities_get(&ctx_with(FakeBackend::new()), CapabilitiesParams::default())
        .await
        .unwrap();
    assert!(!e.data.guarantees.remote_enforcement);
    assert!(e.data.guarantees.statement.contains("not a remote sandbox"));
    assert!(e.data.guarantees.symlink_containment.contains("realpath"));
    assert_eq!(e.data.tools.len(), 17);
    assert_eq!(e.data.protocol_versions, ["2026-07-28", "2025-11-25"]);
    assert_eq!(e.data.mode, "observer");
    let h = ssh_capabilities_get(
        &ctx_with(FakeBackend::new()),
        CapabilitiesParams {
            host_id: Some("h1".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(h.data.host.unwrap().host_id, "h1");
}

#[tokio::test]
async fn ssh_failure_classified() {
    let ctx = ctx_with(FakeBackend::new().fail_connect(ErrorCode::HostKeyChanged));
    let e = ssh_host_inspect(&ctx, inspect("h1")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::HostKeyChanged);
    assert_eq!(e.retry, RetryStrategy::Never);
    let rec = ctx
        .operations
        .get(&ctx.principal, &OperationId::parse(e.operation_id.as_deref().unwrap()).unwrap())
        .unwrap();
    assert_eq!(rec.state, OperationState::Failed);
}

#[tokio::test]
async fn exit_255_from_ssh_is_classified() {
    let fake = FakeBackend::new().on_script(exit_script("uname", b"Host key verification failed.\n", 255));
    assert_eq!(
        ssh_host_inspect(&ctx_with(fake), inspect("h1")).await.unwrap_err().code,
        ErrorCode::HostKeyChanged
    );
}

/// Security review 2026-10-18: keywords embedded in env-var or flag names were not redacted.
#[test]
fn redaction_catches_embedded_keywords() {
    assert_eq!(redact_args("env DB_PASSWORD=hunter2 app"), "env DB_PASSWORD=[REDACTED] app");
    assert_eq!(redact_args("app --db-password hunter2"), "app --db-password [REDACTED]");
    assert_eq!(redact_args("app MYSQL_PWD=x1"), "app MYSQL_PWD=[REDACTED]");
    assert_eq!(
        redact_args("curl http://h/x?token=abc&secret=def"),
        "curl http://h/x?token=[REDACTED]&secret=[REDACTED]"
    );
    assert_eq!(
        redact_args("curl -H Authorization: Bearer abc.def"),
        "curl -H Authorization: [REDACTED]"
    );
    assert_eq!(
        redact_args("app --aws-access-key-id=AKIA123 --github-token=ghp_x"),
        "app --aws-access-key-id=[REDACTED] --github-token=[REDACTED]"
    );
    assert_eq!(redact_args("app --credentials-file=/run/c"), "app --credentials-file=[REDACTED]");
    assert_eq!(redact_args("nginx -g daemon off;"), "nginx -g daemon off;");
}

/// Security review 2026-10-18: disk_usage must refuse a symlinked target and drop du lines outside the root.
#[tokio::test]
async fn disk_usage_refuses_symlink_target() {
    let fake = FakeBackend::new().on_script(exit_script("df -B1", b"SENTINEL_KIND_MISMATCH\n", 97));
    let ctx = ctx_with(fake.clone());
    let e = ssh_disk_usage(&ctx, du("h1", "app", Some("escape"))).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::PolicyDenied);
    assert!(e.message.contains("not a directory"), "{}", e.message);
    assert!(fake.calls()[0].contains("= directory ]"), "{}", fake.calls()[0]);
    assert!(fake.calls()[0].contains("du -x -P"), "{}", fake.calls()[0]);
}

#[tokio::test]
async fn disk_usage_drops_paths_outside_root() {
    let out =
        b"/dev/vda1 100 50 50 50% /\n\n--SENTINEL--\n9000\t.\x005000\t/etc/shadow\x004000\t./data\x00/srv/application\t1\x00".to_vec();
    let fake = FakeBackend::new().on("df -B1", out);
    let e = ssh_disk_usage(&ctx_with(fake), du("h1", "app", None)).await.unwrap();
    assert_eq!(e.data.entries.iter().map(|x| x.path.as_str()).collect::<Vec<_>>(), ["data"]);
    assert!(!serde_json::to_string(&e).unwrap().contains("shadow"));
}

/// Security review 2026-10-18 (second pass): header values with a scheme word, credential flag values starting with '-',
/// and bare keywords followed by a value.
#[test]
fn redaction_covers_header_schemes_dash_values_and_bare_keywords() {
    assert_eq!(
        redact_args("curl -H Authorization: token ghp_abc"),
        "curl -H Authorization: [REDACTED]"
    );
    assert_eq!(redact_args("curl -H X-Api-Key: k123"), "curl -H X-Api-Key: [REDACTED]");
    assert_eq!(redact_args("app --password -abc"), "app --password [REDACTED]");
    assert_eq!(redact_args("expect-login password hunter2"), "expect-login password [REDACTED]");
    assert_eq!(redact_args("nginx -g daemon off;"), "nginx -g daemon off;");
}

/// Security review 2026-10-18 (third and fourth pass): the token after a keyword is always redacted (even a `--x` token,
/// which could be a password), chaining when that token is itself a keyword; bare keywords include env-style names and
/// trailing punctuation, but not paths or file names.
#[test]
fn redaction_does_not_let_flags_swallow_flags() {
    assert_eq!(redact_args("app --auth --password hunter2"), "app --auth [REDACTED] [REDACTED]");
    assert_eq!(
        redact_args("python3 auth_server.py --token abc"),
        "python3 auth_server.py --token [REDACTED]"
    );
    assert_eq!(redact_args("app --password --hunter2"), "app --password [REDACTED]");
    assert_eq!(redact_args("app token abc"), "app token [REDACTED]");
    assert_eq!(redact_args("app tokenizer abc"), "app tokenizer abc");
    assert_eq!(redact_args("env DB_PASSWORD hunter2"), "env DB_PASSWORD [REDACTED]");
    assert_eq!(redact_args("login password: hunter2"), "login password: [REDACTED]");
    assert_eq!(redact_args("cat /etc/token.d/readme x"), "cat /etc/token.d/readme x");
}

/// Final review #2: BusyBox ash prints `sh: ps: not found` and the pipeline exits 0.
#[tokio::test]
async fn busybox_missing_utility_in_pipeline_is_unsupported() {
    let fake = FakeBackend::new().on_script(Script {
        matches: "ps -eo".into(),
        stdout: vec![],
        stderr: b"sh: ps: not found\n".to_vec(),
        exit: 0,
        delay: Duration::ZERO,
        error: None,
    });
    let e = ssh_process_list(&ctx_with(fake), ps("h1")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::CapabilityUnsupported);
    assert!(e.message.contains(": ps"), "{}", e.message);
}

#[tokio::test]
async fn exit_127_without_a_parsable_name_lists_the_candidates() {
    let fake = FakeBackend::new().on_script(exit_script("df -B1", b"", 127));
    let e = ssh_disk_usage(&ctx_with(fake), du("h1", "app", None)).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::CapabilityUnsupported);
    assert!(e.message.contains("du") && e.message.contains("df"), "{}", e.message);
}

/// Final review #7: SSH client failures must not expose the host address, port or user.
#[tokio::test]
async fn ssh_client_failures_do_not_leak_inventory() {
    let fake = FakeBackend::new().on_script(exit_script(
        "uname",
        b"ssh: connect to host 203.0.113.10 port 22: Connection refused\n",
        255,
    ));
    let e = ssh_host_inspect(&ctx_with(fake), inspect("h1")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::ConnectionFailed);
    let s = serde_json::to_string(&e).unwrap();
    assert!(!s.contains("203.0.113.10") && !s.contains("port 22"), "{s}");
    let fake = FakeBackend::new().on_script(exit_script(
        "uname",
        b"sentinel-observer@203.0.113.10: Permission denied (publickey).\n",
        255,
    ));
    let s = serde_json::to_string(&ssh_host_inspect(&ctx_with(fake), inspect("h1")).await.unwrap_err()).unwrap();
    assert!(!s.contains("203.0.113.10") && !s.contains("sentinel-observer"), "{s}");
}
