use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use sentinel_core::effect::Effect;
use sentinel_core::error::{ErrorCode, RetryStrategy, SentinelError};
use sentinel_core::identity::{HostId, HostVisibility, OperationId, Principal, PrincipalId, Role};
use sentinel_core::operation::{OperationState, RemoteTermination};
use sentinel_gateway::config::Budgets;
use sentinel_gateway::jobs::operations::Operations;
use sentinel_gateway::jobs::scheduler::Scheduler;

fn h(s: &str) -> HostId {
    HostId::parse(s).unwrap()
}

fn observer() -> Principal {
    Principal {
        id: PrincipalId::parse("me").unwrap(),
        role: Role::Observer,
        visible_hosts: HostVisibility::All,
    }
}

fn other_principal() -> Principal {
    Principal {
        id: PrincipalId::parse("other").unwrap(),
        role: Role::Observer,
        visible_hosts: HostVisibility::Only(BTreeSet::new()),
    }
}

#[tokio::test]
async fn per_host_reads_capped_at_four() {
    let s = Scheduler::new(&Budgets::default());
    let host = h("h1");
    let held: Vec<_> = futures::future::join_all((0..4).map(|_| s.acquire_read(&host)))
        .await
        .into_iter()
        .map(Result::unwrap)
        .collect();
    assert_eq!(s.snapshot().active, 4);
    let fifth = tokio::time::timeout(Duration::from_millis(200), s.acquire_read(&host)).await;
    assert!(fifth.is_err(), "fifth should still be waiting");
    assert!(s.acquire_read(&h("h2")).await.is_ok(), "another host is not blocked");
    drop(held);
    assert!(s.acquire_read(&host).await.is_ok());
}

#[tokio::test]
async fn pending_overflow_rejects_immediately() {
    let b = Budgets {
        max_active_operations: 1,
        max_pending_operations: 1,
        queue_wait_secs: 5,
        ..Default::default()
    };
    let s = Scheduler::new(&b);
    let _a = s.acquire_read(&h("h1")).await.unwrap();
    let s2 = s.clone();
    let _w = tokio::spawn(async move { s2.acquire_read(&h("h2")).await.map(|_| ()) });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(s.snapshot().pending, 1);
    let t = Instant::now();
    let e = s.acquire_read(&h("h3")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::BudgetExceeded);
    assert_eq!(e.retry, RetryStrategy::RetryAfter { seconds: 1 });
    assert!(t.elapsed() < Duration::from_millis(100));
}

#[tokio::test(start_paused = true)]
async fn queue_wait_times_out() {
    let b = Budgets {
        max_active_operations: 1,
        ..Default::default()
    };
    let s = Scheduler::new(&b);
    let _a = s.acquire_read(&h("h1")).await.unwrap();
    let e = s.acquire_read(&h("h2")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::BudgetExceeded);
    assert_eq!(e.details["reason"], "queue_wait_exceeded");
    assert_eq!(s.snapshot().pending, 0, "a timed-out waiter is no longer pending");
}

#[test]
fn operations_lifecycle_and_ownership() {
    let ops = Operations::new();
    let me = observer();
    let other = other_principal();
    let op = ops.begin(&me, Some(&h("h1")), "ssh_hosts_list", Effect::Read);
    assert_eq!(ops.get(&me, &op.id).unwrap().state, OperationState::Queued);
    ops.mark_running(&op.id);
    assert_eq!(ops.get(&me, &op.id).unwrap().state, OperationState::Running);
    assert_eq!(ops.get(&other, &op.id).unwrap_err().code, ErrorCode::NotFound);
    assert_eq!(ops.cancel(&other, &op.id).unwrap_err().code, ErrorCode::NotFound);
    let c = ops.cancel(&me, &op.id).unwrap();
    assert_eq!(c.state, OperationState::CancelRequested);
    assert!(op.cancel.is_cancelled());
    ops.finish_err(
        &op.id,
        &SentinelError::new(ErrorCode::Timeout, "cancelled").with_detail("cancelled", true),
    );
    let r = ops.get(&me, &op.id).unwrap();
    assert_eq!(r.state, OperationState::Cancelled);
    assert_eq!(r.remote_termination, RemoteTermination::Unconfirmed);
    assert!(r.error.is_some());
}

#[test]
fn finish_paths() {
    let ops = Operations::new();
    let me = observer();
    let ok = ops.begin(&me, Some(&h("h1")), "t", Effect::Read);
    ops.mark_running(&ok.id);
    ops.finish_ok(&ok.id, None);
    assert_eq!(ops.get(&me, &ok.id).unwrap().state, OperationState::Succeeded);
    let failed = ops.begin(&me, Some(&h("h1")), "t", Effect::Read);
    ops.mark_running(&failed.id);
    ops.finish_err(&failed.id, &SentinelError::new(ErrorCode::HostKeyChanged, "x"));
    let r = ops.get(&me, &failed.id).unwrap();
    assert_eq!(r.state, OperationState::Failed);
    assert_eq!(r.remote_termination, RemoteTermination::NotApplicable);
    let timed = ops.begin(&me, Some(&h("h1")), "t", Effect::Read);
    ops.mark_running(&timed.id);
    ops.finish_err(&timed.id, &SentinelError::new(ErrorCode::Timeout, "slow"));
    let r = ops.get(&me, &timed.id).unwrap();
    assert_eq!(r.state, OperationState::Failed);
    assert_eq!(r.remote_termination, RemoteTermination::Unconfirmed);
    let rej = ops.begin_rejected(
        &me,
        Some(&h("h1")),
        "t",
        Effect::Read,
        &SentinelError::new(ErrorCode::PolicyDenied, "no"),
    );
    assert_eq!(ops.get(&me, &rej).unwrap().state, OperationState::Rejected);
}

#[test]
fn cancel_of_finished_op_is_noop() {
    let ops = Operations::new();
    let me = observer();
    let op = ops.begin(&me, None, "t", Effect::Read);
    ops.mark_running(&op.id);
    ops.finish_ok(&op.id, None);
    let c = ops.cancel(&me, &op.id).unwrap();
    assert_eq!(c.state, OperationState::Succeeded);
    assert!(!op.cancel.is_cancelled());
}

#[test]
fn unknown_operation_not_found() {
    assert_eq!(
        Operations::new().get(&observer(), &OperationId::generate()).unwrap_err().code,
        ErrorCode::NotFound
    );
}

#[test]
fn sweep_removes_old_terminal_operations_only() {
    let ops = Operations::new();
    let me = observer();
    let done = ops.begin(&me, None, "t", Effect::Read);
    ops.mark_running(&done.id);
    ops.finish_ok(&done.id, None);
    let live = ops.begin(&me, None, "t", Effect::Read);
    assert_eq!(ops.sweep_finished(Duration::ZERO), 1);
    assert!(ops.get(&me, &done.id).is_err());
    assert!(ops.get(&me, &live.id).is_ok());
}

/// Security review 2026-10-18: a waiter blocked on a saturated host must not hold a global slot (spec §10.4).
#[tokio::test]
async fn saturated_host_waiters_do_not_starve_other_hosts() {
    let b = Budgets {
        max_active_operations: 2,
        per_host_reads: 1,
        queue_wait_secs: 5,
        ..Default::default()
    };
    let s = Scheduler::new(&b);
    let _a = s.acquire_read(&h("busy")).await.unwrap();
    let s2 = s.clone();
    let _waiter = tokio::spawn(async move { s2.acquire_read(&h("busy")).await.map(|_| ()) });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let other = tokio::time::timeout(Duration::from_millis(500), s.acquire_read(&h("idle"))).await;
    assert!(other.is_ok(), "a request for an idle host was blocked by a waiter on a busy host");
}
