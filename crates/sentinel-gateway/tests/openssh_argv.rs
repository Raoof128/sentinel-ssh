use std::time::{Duration, Instant};

use sentinel_core::error::ErrorCode;
use sentinel_gateway::config::{Config, HostConfig};
use sentinel_gateway::ssh::backend::{ExitKind, RunBudget, SshBackend, StreamBudget, classify_ssh_failure};
use sentinel_gateway::ssh::command::RemoteCommand;
use sentinel_gateway::ssh::openssh::OpenSshBackend;
use sentinel_testkit::configs::{TestDirs, fake_ssh_script, load_minimal};
use tokio_util::sync::CancellationToken;

fn setup() -> (TestDirs, Config) {
    let dirs = TestDirs::new();
    let (cfg, _) = load_minimal(&dirs);
    (dirs, cfg)
}

fn host(cfg: &Config) -> HostConfig {
    cfg.hosts[0].clone()
}

fn with_script(dirs: &TestDirs, cfg: &mut Config, body: &str) {
    cfg.gateway.ssh_binary = fake_ssh_script(dirs.state.path(), "fake-ssh", body);
}

fn budget(ms: u64) -> RunBudget {
    RunBudget {
        timeout: Duration::from_millis(ms),
        max_stdout_bytes: 4096,
        max_stderr_bytes: 4096,
    }
}

fn mode(p: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode()
}

#[test]
fn argv_is_fully_controlled() {
    let (dirs, cfg) = setup();
    let b = OpenSshBackend::new(&cfg.gateway).unwrap();
    let argv = b.build_argv(&host(&cfg), &RemoteCommand::new("true"));
    let run = dirs.run.path().display().to_string();
    let id = cfg.hosts[0].auth_identity().unwrap().display().to_string();
    let hash = regex::Regex::new("c-[0-9a-f]{40}").unwrap();
    let s: Vec<String> = argv
        .iter()
        .map(|a| {
            hash.replace_all(&a.to_string_lossy().replace(&run, "<RUN>").replace(&id, "<ID>"), "c-<HASH>")
                .into_owned()
        })
        .collect();
    let joined = s.join(" ");
    assert_eq!(&s[0..2], ["-F", "/dev/null"]);
    for req in [
        "StrictHostKeyChecking=yes",
        "HostKeyAlias=h1",
        "ClearAllForwardings=yes",
        "ProxyCommand=none",
        "IdentitiesOnly=yes",
        "IdentityAgent=none",
        "ControlMaster=auto",
        "BatchMode=yes",
        "ForwardAgent=no",
    ] {
        assert!(joined.contains(req), "{req}");
    }
    assert_eq!(s[s.len() - 3..], ["--", "203.0.113.10", "true"]);
    insta::assert_debug_snapshot!(s);
}

#[test]
fn known_hosts_uses_alias() {
    let (_dirs, cfg) = setup();
    let b = OpenSshBackend::new(&cfg.gateway).unwrap();
    let p = b.write_known_hosts(&host(&cfg)).unwrap();
    assert_eq!(
        std::fs::read_to_string(&p).unwrap(),
        "h1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample\n"
    );
    assert_eq!(mode(&p) & 0o777, 0o600);
}

#[test]
fn runtime_dir_must_be_private() {
    let (dirs, cfg) = setup();
    let open = dirs.run.path().join("open");
    std::fs::create_dir(&open).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut g = cfg.gateway.clone();
    g.runtime_dir = open;
    assert_eq!(OpenSshBackend::new(&g).unwrap_err().code, ErrorCode::ConfigInvalid);
}

#[test]
fn classify() {
    assert_eq!(
        classify_ssh_failure(&ExitKind::Code(255), b"... REMOTE HOST IDENTIFICATION HAS CHANGED! ..."),
        Some(ErrorCode::HostKeyChanged)
    );
    assert_eq!(
        classify_ssh_failure(&ExitKind::Code(255), b"Host key verification failed."),
        Some(ErrorCode::HostKeyChanged)
    );
    assert_eq!(
        classify_ssh_failure(&ExitKind::Code(255), b"Permission denied (publickey)."),
        Some(ErrorCode::AuthenticationFailed)
    );
    assert_eq!(
        classify_ssh_failure(&ExitKind::Code(255), b"ssh: connect to host x port 22: Connection refused"),
        Some(ErrorCode::ConnectionFailed)
    );
    assert_eq!(classify_ssh_failure(&ExitKind::Code(97), b"SENTINEL_KIND_MISMATCH"), None);
    assert_eq!(classify_ssh_failure(&ExitKind::Code(0), b""), None);
}

/// Replaces the plan's `untrusted_ssh_config_not_executed`: OpenSSH reads ~/.ssh/config from the passwd home, not $HOME,
/// so planting a config in a temp $HOME proves nothing. Instead ask the real ssh binary what configuration it would use.
#[test]
fn effective_config_is_locked_down() {
    let (_dirs, cfg) = setup();
    let b = OpenSshBackend::new(&cfg.gateway).unwrap();
    let eff = b.effective_config(&host(&cfg)).unwrap();
    assert_eq!(eff["stricthostkeychecking"], ["true"]);
    assert_eq!(eff["globalknownhostsfile"], ["/dev/null"]);
    assert_eq!(eff["forwardagent"], ["no"]);
    assert_eq!(eff["identitiesonly"], ["yes"]);
    assert_eq!(eff["hostkeyalias"], ["h1"]);
    assert_eq!(
        eff["identityfile"].len(),
        1,
        "only the configured identity: {:?}",
        eff["identityfile"]
    );
    assert!(eff.get("proxycommand").is_none_or(|v| v == &["none"]));
    b.check_effective_config(&host(&cfg)).unwrap();
}

#[tokio::test]
async fn missing_identity_never_dispatches() {
    let (dirs, mut cfg) = setup();
    let marker = dirs.state.path().join("RAN");
    with_script(&dirs, &mut cfg, &format!("touch '{}'", marker.display()));
    std::fs::remove_file(cfg.hosts[0].auth_identity().unwrap()).unwrap();
    let b = OpenSshBackend::new(&cfg.gateway).unwrap();
    let e = b
        .run(&host(&cfg), &RemoteCommand::new("true"), &budget(2000), CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::ConfigInvalid);
    assert!(
        !marker.exists(),
        "ssh was spawned without the configured identity (would fall back to ~/.ssh defaults)"
    );
}

#[tokio::test]
async fn run_collects_output_and_exit() {
    let (dirs, mut cfg) = setup();
    with_script(&dirs, &mut cfg, "echo out; echo err >&2; exit 3");
    let b = OpenSshBackend::new(&cfg.gateway).unwrap();
    let r = b
        .run(&host(&cfg), &RemoteCommand::new("true"), &budget(5000), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(r.stdout, b"out\n");
    assert_eq!(r.stderr, b"err\n");
    assert!(matches!(r.exit, ExitKind::Code(3)));
}

#[tokio::test]
async fn silent_child_is_killed_at_read_timeout() {
    let (dirs, mut cfg) = setup();
    with_script(&dirs, &mut cfg, "sleep 30");
    let b = OpenSshBackend::new(&cfg.gateway).unwrap();
    let t = Instant::now();
    let e = b
        .run(&host(&cfg), &RemoteCommand::new("true"), &budget(300), CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Timeout);
    assert_eq!(e.details["remote_termination"], "unconfirmed");
    assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
}

#[tokio::test]
async fn stdout_cap_truncates_without_blocking() {
    let (dirs, mut cfg) = setup();
    with_script(&dirs, &mut cfg, "head -c 1048576 /dev/zero");
    let b = OpenSshBackend::new(&cfg.gateway).unwrap();
    let t = Instant::now();
    let r = b
        .run(&host(&cfg), &RemoteCommand::new("true"), &budget(5000), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(r.stdout.len(), 4096);
    assert!(r.stdout_truncated);
    assert!(t.elapsed() < Duration::from_secs(3));
}

/// An OpenSSH ControlPersist master backgrounds itself and can keep the stderr pipe open after the client exits.
#[tokio::test]
async fn stderr_held_open_by_background_process_does_not_hang() {
    let (dirs, mut cfg) = setup();
    with_script(&dirs, &mut cfg, "(sleep 30 >&2 &) ; echo hi");
    let b = OpenSshBackend::new(&cfg.gateway).unwrap();
    let t = Instant::now();
    let r = b
        .run(&host(&cfg), &RemoteCommand::new("true"), &budget(10_000), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(r.stdout, b"hi\n");
    assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
}

#[tokio::test]
async fn cancel_token_kills_child() {
    let (dirs, mut cfg) = setup();
    with_script(&dirs, &mut cfg, "sleep 30");
    let b = OpenSshBackend::new(&cfg.gateway).unwrap();
    let cancel = CancellationToken::new();
    let c2 = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        c2.cancel();
    });
    let t = Instant::now();
    let e = b
        .run(&host(&cfg), &RemoteCommand::new("true"), &budget(10_000), cancel)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Timeout);
    assert_eq!(e.details["cancelled"], true);
    assert!(t.elapsed() < Duration::from_secs(3));
}

fn stream_budget(idle_ms: u64, max: u64) -> StreamBudget {
    StreamBudget {
        idle_timeout: Duration::from_millis(idle_ms),
        total_timeout: Duration::from_secs(10),
        max_bytes: max,
    }
}

#[tokio::test]
async fn stream_copies_exact_bytes() {
    let (dirs, mut cfg) = setup();
    with_script(&dirs, &mut cfg, "head -c 200000 /dev/zero");
    let b = OpenSshBackend::new(&cfg.gateway).unwrap();
    let mut sink: Vec<u8> = Vec::new();
    let r = b
        .stream_stdout(
            &host(&cfg),
            &RemoteCommand::new("cat"),
            &stream_budget(2000, 200_000),
            CancellationToken::new(),
            &mut sink,
        )
        .await
        .unwrap();
    assert_eq!(r.bytes, 200_000);
    assert_eq!(sink.len(), 200_000);
    assert!(matches!(r.exit, ExitKind::Code(0)));
}

#[tokio::test]
async fn stream_over_max_bytes_is_budget_exceeded() {
    let (dirs, mut cfg) = setup();
    with_script(&dirs, &mut cfg, "head -c 200000 /dev/zero");
    let b = OpenSshBackend::new(&cfg.gateway).unwrap();
    let mut sink: Vec<u8> = Vec::new();
    let e = b
        .stream_stdout(
            &host(&cfg),
            &RemoteCommand::new("cat"),
            &stream_budget(2000, 1000),
            CancellationToken::new(),
            &mut sink,
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::BudgetExceeded);
}

#[tokio::test]
async fn stream_idle_timeout() {
    let (dirs, mut cfg) = setup();
    with_script(&dirs, &mut cfg, "sleep 30");
    let b = OpenSshBackend::new(&cfg.gateway).unwrap();
    let mut sink: Vec<u8> = Vec::new();
    let t = Instant::now();
    let e = b
        .stream_stdout(
            &host(&cfg),
            &RemoteCommand::new("cat"),
            &stream_budget(300, 1000),
            CancellationToken::new(),
            &mut sink,
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::TransferTimeoutIdle);
    assert!(t.elapsed() < Duration::from_secs(3));
}

/// Security review 2026-10-18: `%C` hashes only host/port/user, so a master authenticated under one pinned key or identity
/// could be reused after either changed, or by a second inventory entry for the same address (spec §9.2).
#[test]
fn control_path_binds_trust_identity() {
    let (_dirs, cfg) = setup();
    let b = OpenSshBackend::new(&cfg.gateway).unwrap();
    let base = host(&cfg);
    let p0 = b.control_path(&base);
    assert!(!p0.to_string_lossy().contains('%'), "no OpenSSH tokens: {}", p0.display());
    assert!(p0.as_os_str().len() <= sentinel_gateway::config::MAX_CONTROL_PATH);
    let mut other_key = base.clone();
    other_key.host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOther00".parse().unwrap();
    let mut other_id = base.clone();
    other_id.id = sentinel_core::identity::HostId::parse("h2").unwrap();
    let mut other_identity = base.clone();
    other_identity.auth = sentinel_gateway::config::AuthConfig::IdentityFile {
        path: "/tmp/other-id".into(),
    };
    for h in [&other_key, &other_id, &other_identity] {
        assert_ne!(b.control_path(h), p0);
    }
    assert_eq!(b.control_path(&base.clone()), p0, "stable for the same trust identity");
    let argv: Vec<String> = b
        .build_argv(&base, &RemoteCommand::new("true"))
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    assert!(argv.contains(&format!("ControlPath={}", p0.display())));
}
