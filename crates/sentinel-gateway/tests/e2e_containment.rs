//! Red-team containment attacks against the disposable Docker sshd fixture (seeded by `docker/seed.sh`).
//! Run: `bash scripts/fixture-up.sh && set -a && . target/fixture/fixture.env && set +a && cargo test --test e2e_containment`.
//! Without the fixture every test prints `skipped: no ssh fixture` and passes. The attacker loops run inside the
//! container as the observer account through `docker exec`; nothing here touches a real host.

use std::process::{Command, Output};
use std::sync::Arc;
use std::time::Duration;

use sentinel_core::error::ErrorCode;
use sentinel_gateway::config::load_config;
use sentinel_gateway::ssh::openssh::OpenSshBackend;
use sentinel_gateway::tools::AppContext;
use sentinel_gateway::tools::disk::{DiskUsageParams, ssh_disk_usage};
use sentinel_gateway::tools::files::{
    FileHashParams, FileReadParams, FileStatParams, FilesListParams, ssh_file_hash, ssh_file_read, ssh_file_stat, ssh_files_list,
};
use sentinel_gateway::tools::health::{HealthCheckParams, ssh_health_check};
use sentinel_gateway::tools::logs::{LogsSearchParams, ssh_logs_search};
use sentinel_gateway::tools::transfers::{TransferDownloadParams, ssh_transfer_download};
use sentinel_testkit::configs::{TestDirs, write_private};
use sentinel_testkit::fixture::SshFixture;

const SECRET: &str = "FAKE-PRIVATE-KEY-FOR-TESTS";
const CONTAINER: &str = "sentinel-fixture";

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
}

/// The fixture config, optionally with a short read timeout and a health check against a port that never answers.
fn ctx_with_toml(fx: &SshFixture, edit: impl Fn(String) -> String) -> E2e {
    let dirs = TestDirs::new();
    let p = dirs.state.path().join("fixture.toml");
    write_private(&p, &edit(fx.config_toml(&dirs, &fx.host_key)));
    let cfg = load_config(&p).expect("fixture config loads");
    let backend = OpenSshBackend::new(&cfg.gateway).expect("backend");
    E2e {
        ctx: AppContext::new(cfg, Arc::new(backend)).expect("context"),
        _dirs: dirs,
    }
}
fn ctx(fx: &SshFixture) -> E2e {
    ctx_with_toml(fx, |t| t)
}

fn docker(args: &[&str]) -> Output {
    Command::new("docker").args(args).output().expect("docker CLI")
}
/// A shell command inside the fixture container, as the observer account.
fn in_container(script: &str) -> Output {
    docker(&["exec", "-u", "sentinel", CONTAINER, "sh", "-c", script])
}

fn read(root: &str, path: &str) -> FileReadParams {
    FileReadParams {
        host_id: "fx".into(),
        root: root.into(),
        path: path.into(),
        ..Default::default()
    }
}
fn hash(root: &str, path: &str) -> FileHashParams {
    FileHashParams {
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

async fn artefact_text(c: &AppContext, id: &sentinel_core::identity::ArtifactId) -> String {
    let (bytes, _) = c.artifacts.read_range(&c.principal, id, 0, 65536).await.unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn e2e_symlinked_log_source_is_refused() {
    let fx = fixture_or_skip!();
    let e = ctx(&fx);
    let p = LogsSearchParams {
        host_id: "fx".into(),
        source_id: "linked".into(),
        pattern: "FAKE".into(),
        ..Default::default()
    };
    let err = ssh_logs_search(&e.ctx, p).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::PolicyDenied, "{err:?}");
    assert!(!err.message.contains(SECRET));
}

#[tokio::test]
async fn e2e_hardlink_to_secret_is_refused_by_every_reader() {
    let fx = fixture_or_skip!();
    let e = ctx(&fx);
    let c = &e.ctx;
    let p = "data/hardlink-to-secret";
    for err in [
        ssh_file_read(c, read("app", p)).await.unwrap_err(),
        ssh_file_hash(c, hash("app", p)).await.unwrap_err(),
        ssh_transfer_download(c, dl("app", p)).await.unwrap_err(),
    ] {
        assert_eq!(err.code, ErrorCode::PolicyDenied, "{err:?}");
        assert!(err.message.contains("hard-linked"), "{}", err.message);
    }
}

#[tokio::test]
async fn e2e_newline_sibling_of_the_root_is_outside_it() {
    let fx = fixture_or_skip!();
    let e = ctx(&fx);
    let c = &e.ctx;
    // `/srv/app/nl` -> "/srv/app\n", a sibling whose name begins with the root's path.
    let err = ssh_file_read(c, read("app", "nl/out")).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::PolicyDenied, "{err:?}");
    let err = ssh_files_list(
        c,
        FilesListParams {
            host_id: "fx".into(),
            root: "app".into(),
            path: "nl".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::PolicyDenied, "{err:?}");
}

#[tokio::test]
async fn e2e_nested_root_without_export_cannot_be_downloaded_through_its_parent() {
    let fx = fixture_or_skip!();
    let e = ctx(&fx);
    let c = &e.ctx;
    // Root `logs` (/srv/app/logs, export = false) sits inside root `app` (export = true).
    let err = ssh_transfer_download(c, dl("app", "logs/api.log")).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::PolicyDenied, "{err:?}");
    assert!(err.message.contains("may not access"), "{}", err.message);
    // Reading is allowed by both roots, so the same file is readable through the parent.
    let r = ssh_file_read(c, read("app", "logs/api.log")).await.unwrap();
    assert!(r.data.content.contains("INFO request 1 ok"));
}

#[tokio::test]
async fn e2e_backslash_name_hashes_and_downloads() {
    let fx = fixture_or_skip!();
    let e = ctx(&fx);
    let c = &e.ctx;
    let p = "data/back\\slash.txt";
    let h = ssh_file_hash(c, hash("app", p)).await.unwrap();
    let d = ssh_transfer_download(c, dl("app", p)).await.unwrap();
    assert_eq!(h.data.digest, d.data.sha256);
    assert_eq!(artefact_text(c, &d.data.artifact_id).await, "back\n");
}

#[tokio::test]
async fn e2e_names_that_are_not_utf8_page_without_collapsing() {
    let fx = fixture_or_skip!();
    let e = ctx(&fx);
    let c = &e.ctx;
    // "n-\xff" and "n-\xfe" display identically after lossy decoding; the cursor must still tell them apart.
    let page = |cursor: Option<String>| FilesListParams {
        host_id: "fx".into(),
        root: "app".into(),
        path: "utf8".into(),
        max_entries: Some(1),
        cursor,
        ..Default::default()
    };
    let first = ssh_files_list(c, page(None)).await.unwrap();
    assert_eq!(first.data.entries.len(), 1);
    let cursor = first.next_cursor.clone().expect("a second page");
    let second = ssh_files_list(c, page(Some(cursor))).await.unwrap();
    assert_eq!(second.data.entries.len(), 1, "{:?}", second.data.entries);
    assert!(second.next_cursor.is_none(), "exactly two entries");
}

#[tokio::test]
async fn e2e_fifo_is_refused_without_blocking() {
    let fx = fixture_or_skip!();
    let e = ctx(&fx);
    let c = &e.ctx;
    let started = std::time::Instant::now();
    for err in [
        ssh_file_read(c, read("app", "data/a-fifo")).await.unwrap_err(),
        ssh_file_hash(c, hash("app", "data/a-fifo")).await.unwrap_err(),
        ssh_transfer_download(c, dl("app", "data/a-fifo")).await.unwrap_err(),
    ] {
        assert_eq!(err.code, ErrorCode::PolicyDenied, "{err:?}");
    }
    assert!(started.elapsed() < Duration::from_secs(10), "a FIFO open blocked");
}

/// An attacker with the observer account's own write access swaps `data/race` between a decoy, a symlink to the
/// secret and a hard link to it, as fast as it can, while the gateway reads, hashes and downloads it.
#[tokio::test]
async fn e2e_swap_race_never_returns_the_secret() {
    let fx = fixture_or_skip!();
    let e = ctx(&fx);
    let c = &e.ctx;
    let attacker = r#"
import os
d = "/srv/app/data"
while True:
    for kind in ("decoy", "symlink", "hardlink"):
        tmp = d + "/.race-tmp"
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        if kind == "decoy":
            with open(tmp, "w") as f:
                f.write("decoy content for the swap race\n")
        elif kind == "symlink":
            os.symlink("/srv/secrets/key", tmp)
        else:
            os.link("/srv/secrets/key", tmp)
        os.rename(tmp, d + "/race")
"#;
    std::fs::write(std::env::temp_dir().join("sentinel-race.py"), attacker).unwrap();
    let cp = docker(&[
        "cp",
        std::env::temp_dir().join("sentinel-race.py").to_str().unwrap(),
        &format!("{CONTAINER}:/tmp/race.py"),
    ]);
    assert!(cp.status.success(), "{cp:?}");
    let start = docker(&["exec", "-d", "-u", "sentinel", CONTAINER, "python3", "/tmp/race.py"]);
    assert!(start.status.success(), "{start:?}");

    let mut outcomes = (0usize, 0usize); // (succeeded, refused)
    for _ in 0..40 {
        if let Ok(r) = ssh_file_read(c, read("app", "data/race")).await {
            assert!(!r.data.content.contains(SECRET), "file_read leaked the secret");
            outcomes.0 += 1;
        } else {
            outcomes.1 += 1;
        }
        match ssh_transfer_download(c, dl("app", "data/race")).await {
            Ok(d) => {
                assert!(
                    !artefact_text(c, &d.data.artifact_id).await.contains(SECRET),
                    "download leaked the secret"
                );
                outcomes.0 += 1;
            }
            Err(_) => outcomes.1 += 1,
        }
        if let Ok(h) = ssh_file_hash(c, hash("app", "data/race")).await {
            // The secret's digest would prove the hash was taken through the swapped link.
            let secret = in_container("sha256sum /srv/secrets/key");
            assert!(
                !String::from_utf8_lossy(&secret.stdout).starts_with(&h.data.digest),
                "hash read the secret"
            );
            outcomes.0 += 1;
        } else {
            outcomes.1 += 1;
        }
    }
    in_container(
        "pkill -f /tmp/race.py; printf 'decoy content for the swap race\\n' > /srv/app/data/.race-tmp; mv /srv/app/data/.race-tmp /srv/app/data/race",
    );
    eprintln!("swap race: {} succeeded on the decoy, {} refused", outcomes.0, outcomes.1);
    assert_eq!(outcomes.0 + outcomes.1, 120);
}

/// A remote command that outlives the read timeout is killed on the host, not just abandoned by the client.
#[tokio::test]
async fn e2e_timed_out_command_leaves_no_remote_process() {
    let fx = fixture_or_skip!();
    let e = ctx_with_toml(&fx, |t| {
        t.replace("\n[principal]", "\n[gateway.budgets]\nread_timeout_secs = 2\n\n[principal]")
            + "\n[hosts.health_checks.hang]\nkind = \"http\"\nurl = \"http://127.0.0.1:8099/\"\nexpect_status = 200\ntimeout_secs = 60\n"
    });
    // Accepts connections and never answers.
    let listener = docker(&[
        "exec",
        "-d",
        "-u",
        "sentinel",
        CONTAINER,
        "python3",
        "-c",
        "import socket,time\ns=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',8099));s.listen(8)\nc=[]\nwhile True: c.append(s.accept())",
    ]);
    assert!(listener.status.success(), "{listener:?}");
    std::thread::sleep(Duration::from_millis(500));
    let started = std::time::Instant::now();
    let err = ssh_health_check(
        &e.ctx,
        HealthCheckParams {
            host_id: "fx".into(),
            check_id: "hang".into(),
            ..Default::default()
        },
    )
    .await;
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "the gateway waited {:?}",
        started.elapsed()
    );
    let mut leftover = String::new();
    for _ in 0..20 {
        std::thread::sleep(Duration::from_millis(500));
        leftover = String::from_utf8_lossy(&in_container("pgrep -a -u sentinel curl || true").stdout).into_owned();
        if leftover.trim().is_empty() {
            break;
        }
    }
    in_container("pkill -f 8099 || true");
    assert!(
        leftover.trim().is_empty(),
        "remote curl survived the timeout: {leftover} (result {err:?})"
    );
    let err = err.expect_err("a hung health check is not a success");
    assert!(matches!(err.code, ErrorCode::Timeout | ErrorCode::OutcomeUnknown), "{err:?}");
}

/// Root `vault` (/srv/app/vault, read = false) sits inside root `app`: nothing about its contents, and not even its
/// own metadata, may come back through the parent.
#[tokio::test]
async fn e2e_nested_unreadable_root_is_invisible_through_its_parent() {
    let fx = fixture_or_skip!();
    let e = ctx(&fx);
    let c = &e.ctx;
    let listing = ssh_files_list(
        c,
        FilesListParams {
            host_id: "fx".into(),
            root: "app".into(),
            path: "".into(),
            max_entries: Some(500),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let names: Vec<&str> = listing.data.entries.iter().map(|x| x.name.as_str()).collect();
    assert!(names.contains(&"data") && names.contains(&"logs"), "{names:?}");
    assert!(!names.contains(&"vault"), "the excluded root is listed: {names:?}");
    let stat = ssh_file_stat(
        c,
        FileStatParams {
            host_id: "fx".into(),
            root: "app".into(),
            path: "vault".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(stat.code, ErrorCode::PolicyDenied, "{stat:?}");
    for (path, depth) in [("", 2u8), ("", 1)] {
        let du = ssh_disk_usage(
            c,
            DiskUsageParams {
                host_id: "fx".into(),
                root: "app".into(),
                path: Some(path.into()),
                depth: Some(depth),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(du.code, ErrorCode::PolicyDenied, "{du:?}");
        assert!(du.message.contains("contains a root"), "{}", du.message);
    }
    // A sibling subtree that does not contain the vault is still measurable.
    ssh_disk_usage(
        c,
        DiskUsageParams {
            host_id: "fx".into(),
            root: "app".into(),
            path: Some("data".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let read = ssh_file_read(c, read("app", "vault/inner.txt")).await.unwrap_err();
    assert_eq!(read.code, ErrorCode::PolicyDenied, "{read:?}");
}

#[tokio::test]
async fn e2e_process_list_shows_the_host_not_the_gateway() {
    use sentinel_gateway::tools::processes::{ProcessListParams, ssh_process_list};
    let fx = fixture_or_skip!();
    let e = ctx(&fx);
    let p = ssh_process_list(
        &e.ctx,
        ProcessListParams {
            host_id: "fx".into(),
            limit: Some(200),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(p.data.processes.iter().any(|x| x.command == "sshd"), "{:?}", p.data.processes);
    // Other sessions' sshd processes (earlier tests' persistent masters) are legitimately listed; this call's own
    // shell, its children and its timeout wrapper are not.
    for x in &p.data.processes {
        assert!(
            !x.args_redacted.contains("SENTINEL") && !matches!(x.command.as_str(), "ps" | "head" | "timeout"),
            "the gateway's own process is listed: {x:?}"
        );
    }
}
