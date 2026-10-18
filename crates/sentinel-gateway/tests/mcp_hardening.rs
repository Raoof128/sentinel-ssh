//! Red-team MCP and resource findings: bounded registries and queues, cancellation that reaches the work, cleanup on
//! drop, and failure envelopes that stay bounded and traceable.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sentinel_core::effect::Effect;
use sentinel_core::envelope::ResultEnvelope;
use sentinel_core::error::{ErrorCode, SentinelError};
use sentinel_core::identity::{HostId, HostVisibility, OperationId, Principal, PrincipalId, Role};
use sentinel_core::operation::OperationState;
use sentinel_gateway::artifacts::{ArtifactOrigin, ArtifactStore, ContentKind};
use sentinel_gateway::config::Budgets;
use sentinel_gateway::jobs::operations::Operations;
use sentinel_gateway::jobs::scheduler::Scheduler;
use sentinel_gateway::mcp::results::{Detail, bound_envelope, failed_envelope};
use sentinel_gateway::tools::batch::{BatchInspectParams, BatchItem, BatchItemResult, ssh_batch_inspect};
use sentinel_gateway::tools::files::{FileReadParams, FilesListParams, ssh_file_read, ssh_files_list};
use sentinel_gateway::tools::hosts::{HostsListParams, ssh_hosts_list};
use sentinel_gateway::tools::{AppContext, cancelled_by};
use sentinel_testkit::configs::{TestDirs, load_minimal};
use sentinel_testkit::ctx::ctx_with;
use sentinel_testkit::fake_backend::{FakeBackend, Script};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

fn h(s: &str) -> HostId {
    HostId::parse(s).unwrap()
}

fn me() -> Principal {
    Principal {
        id: PrincipalId::parse("me").unwrap(),
        role: Role::Observer,
        visible_hosts: HostVisibility::All,
    }
}

fn slow(matches: &str) -> FakeBackend {
    FakeBackend::new().on_script(Script {
        matches: matches.into(),
        stdout: b"x".to_vec(),
        delay: Duration::from_secs(20),
        ..Default::default()
    })
}

fn read(path: &str) -> FileReadParams {
    FileReadParams {
        host_id: "h1".into(),
        root: "app".into(),
        path: path.into(),
        ..Default::default()
    }
}

/// An AppContext over the minimal config with edited budgets.
fn ctx_budgets(fake: FakeBackend, edit: impl FnOnce(&mut Budgets)) -> (AppContext, TestDirs) {
    let dirs = TestDirs::new();
    let (mut cfg, _) = load_minimal(&dirs);
    edit(&mut cfg.gateway.budgets);
    (AppContext::new(cfg, Arc::new(fake)).unwrap(), dirs)
}

#[test]
fn operation_registry_is_capped_and_never_drops_live_operations() {
    let ops = Operations::with_capacity(3);
    let denied = SentinelError::new(ErrorCode::PolicyDenied, "no");
    let mut last = None;
    for _ in 0..10 {
        last = Some(ops.begin_rejected(&me(), Some(&h("h1")), "ssh_file_read", Effect::Read, &denied));
    }
    assert_eq!(ops.list_for(&me()).len(), 3, "terminal records beyond the cap are evicted");
    assert!(ops.get(&me(), &last.unwrap()).is_ok(), "the newest record is kept");
    // Live operations are never evicted, even past the cap.
    let live: Vec<OperationId> = (0..4).map(|_| ops.begin(&me(), Some(&h("h1")), "t", Effect::Read).id).collect();
    ops.begin_rejected(&me(), Some(&h("h1")), "t", Effect::Read, &denied);
    for id in &live {
        assert_eq!(ops.get(&me(), id).unwrap().state, OperationState::Queued);
    }
}

#[tokio::test]
async fn one_host_cannot_fill_the_whole_pending_queue() {
    let b = Budgets {
        per_host_reads: 1,
        max_pending_per_host: 1,
        queue_wait_secs: 5,
        ..Budgets::default()
    };
    let s = Scheduler::new(&b);
    let _held = s.acquire_read(&h("h1")).await.unwrap();
    let waiter = {
        let s = s.clone();
        tokio::spawn(async move { s.acquire_read(&h("h1")).await.map(|_| ()) })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let e = s.acquire_read(&h("h1")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::BudgetExceeded);
    assert_eq!(e.details["reason"], "host_pending_limit");
    // Other hosts still get through.
    s.acquire_read(&h("h2")).await.unwrap();
    waiter.abort();
}

#[tokio::test]
async fn a_client_cancel_reaches_the_running_remote_command() {
    let ctx = ctx_with(slow("tail -c"));
    let token = CancellationToken::new();
    let t = token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        t.cancel();
    });
    let started = Instant::now();
    let e = cancelled_by(token, ssh_file_read(&ctx, read("x"))).await.unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    let op = OperationId::parse(e.operation_id.as_deref().unwrap()).unwrap();
    assert_eq!(ctx.operations.get(&ctx.principal, &op).unwrap().state, OperationState::Cancelled);
}

#[tokio::test]
async fn cancelling_a_batch_cancels_its_items() {
    let ctx = ctx_with(slow("tail -c"));
    let canceller = {
        let ctx = ctx.ctx.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let batch = ctx
                    .operations
                    .list_for(&ctx.principal)
                    .into_iter()
                    .find(|r| r.tool == "ssh_batch_inspect" && r.state == OperationState::Running);
                if let Some(b) = batch {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    ctx.operations.cancel(&ctx.principal, &b.id).unwrap();
                    return;
                }
            }
        })
    };
    let started = Instant::now();
    let r = ssh_batch_inspect(
        &ctx,
        BatchInspectParams {
            items: vec![BatchItem {
                id: "a".into(),
                tool: "ssh_file_read".into(),
                params: serde_json::json!({"host_id": "h1", "root": "app", "path": "x"}),
            }],
            ..Default::default()
        },
    )
    .await;
    canceller.await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    let items = match r {
        Ok(env) => env.data.items,
        Err(e) => panic!("{e:?}"),
    };
    assert!(
        matches!(&items[0], BatchItemResult::Error { error, .. } if error.details.get("cancelled").is_some()),
        "{items:?}"
    );
}

#[tokio::test]
async fn local_tools_take_a_bounded_slot() {
    let (ctx, _dirs) = ctx_budgets(FakeBackend::new(), |b| {
        b.max_active_operations = 1;
        b.queue_wait_secs = 1;
    });
    let held = ctx.scheduler.acquire_local().await.unwrap();
    let e = ssh_hosts_list(&ctx, HostsListParams::default()).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::BudgetExceeded, "{e:?}");
    drop(held);
    ssh_hosts_list(&ctx, HostsListParams::default()).await.unwrap();
}

#[tokio::test]
async fn a_dropped_artifact_writer_leaves_no_partial_file() {
    let dirs = TestDirs::new();
    let store = ArtifactStore::open(&dirs.state.path().join("a"), Duration::from_secs(60)).unwrap();
    let mut w = store
        .begin_write(
            &me().id,
            ArtifactOrigin::RemoteFile {
                host_id: h("h1"),
                root: "app".into(),
                path: "x".into(),
            },
            ContentKind::Binary,
        )
        .unwrap();
    w.write_all(b"partial bytes").await.unwrap();
    drop(w);
    let left: Vec<_> = std::fs::read_dir(store.dir()).unwrap().collect();
    assert!(left.is_empty(), "{left:?}");
}

#[tokio::test]
async fn a_result_that_cannot_be_spilled_keeps_its_operation_id() {
    let dirs = TestDirs::new();
    let store = ArtifactStore::open(&dirs.state.path().join("a"), Duration::from_secs(60))
        .unwrap()
        .with_quota(16);
    let id = OperationId::generate();
    let env = ResultEnvelope::succeeded(id.clone(), Some(h("h1")), "y".repeat(50_000));
    let e = bound_envelope(&store, &me().id, env, Detail::Concise, &Budgets::default())
        .await
        .unwrap_err();
    assert_eq!(e.operation_id.as_deref(), Some(id.as_str()), "{e:?}");
}

#[test]
fn failure_envelopes_stay_bounded_whatever_they_echo() {
    let err = SentinelError::new(ErrorCode::PolicyDenied, format!("unknown root '{}'", "r".repeat(100_000)))
        .with_detail("field", "p".repeat(100_000))
        .with_detail("n", 3);
    let env = failed_envelope::<()>(OperationId::generate(), None, err);
    let json = serde_json::to_string(&env).unwrap();
    assert!(json.len() < 4096, "{} bytes", json.len());
    let msg = &env.error.as_ref().unwrap().message;
    assert!(msg.starts_with("unknown root 'rrr") && msg.ends_with('…'), "{msg}");
    assert_eq!(env.error.as_ref().unwrap().details["n"], 3);
}

#[tokio::test]
async fn directory_listings_are_sorted_on_the_host_before_truncation() {
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
    // The record's fifth tab-separated field onward is the name: byte order under LC_ALL=C, matching the cursor.
    assert!(fake.calls()[0].contains("| sort -z -t '\t' -k5"), "{}", fake.calls()[0]);
}
