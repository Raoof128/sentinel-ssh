//! Bounded scheduling (spec §11.2, §11.3): a global active cap, a per-host read cap and a bounded pending queue.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sentinel_core::error::{ErrorCode, Result, RetryStrategy, SentinelError};
use sentinel_core::identity::HostId;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::Budgets;

#[derive(Debug)]
struct Inner {
    global: Arc<Semaphore>,
    max_active: usize,
    per_host_limit: usize,
    per_host: Mutex<HashMap<HostId, Arc<Semaphore>>>,
    pending: AtomicUsize,
    max_pending: usize,
    queue_wait: Duration,
}

#[derive(Debug, Clone)]
pub struct Scheduler {
    inner: Arc<Inner>,
}

/// Held for the duration of one read operation; releases both permits on drop.
#[derive(Debug)]
pub struct ReadPermit {
    _global: OwnedSemaphorePermit,
    _host: OwnedSemaphorePermit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerSnapshot {
    pub active: usize,
    pub pending: usize,
}

struct PendingGuard<'a>(&'a AtomicUsize);

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Scheduler {
    pub fn new(b: &Budgets) -> Self {
        Self {
            inner: Arc::new(Inner {
                global: Arc::new(Semaphore::new(b.max_active_operations)),
                max_active: b.max_active_operations,
                per_host_limit: b.per_host_reads,
                per_host: Mutex::new(HashMap::new()),
                pending: AtomicUsize::new(0),
                max_pending: b.max_pending_operations,
                queue_wait: Duration::from_secs(b.queue_wait_secs),
            }),
        }
    }

    fn host_semaphore(&self, host: &HostId) -> Arc<Semaphore> {
        let mut m = self.inner.per_host.lock().expect("per-host semaphores");
        m.entry(host.clone())
            .or_insert_with(|| Arc::new(Semaphore::new(self.inner.per_host_limit)))
            .clone()
    }

    pub async fn acquire_read(&self, host: &HostId) -> Result<ReadPermit> {
        let i = &self.inner;
        if i.pending.fetch_add(1, Ordering::SeqCst) >= i.max_pending {
            i.pending.fetch_sub(1, Ordering::SeqCst);
            return Err(SentinelError::new(ErrorCode::BudgetExceeded, "gateway queue is full")
                .with_detail("reason", "pending_limit")
                .with_retry(RetryStrategy::RetryAfter { seconds: 1 }));
        }
        let _pending = PendingGuard(&i.pending);
        let host_sem = self.host_semaphore(host);
        // Host permit first: a waiter blocked on a saturated host must not hold a global slot other hosts need.
        let acquire = async {
            let h = host_sem.acquire_owned().await.expect("semaphore never closed");
            let g = i.global.clone().acquire_owned().await.expect("semaphore never closed");
            ReadPermit { _global: g, _host: h }
        };
        tokio::time::timeout(i.queue_wait, acquire).await.map_err(|_| {
            SentinelError::new(
                ErrorCode::BudgetExceeded,
                format!("waited {} s for a free slot", i.queue_wait.as_secs()),
            )
            .with_detail("reason", "queue_wait_exceeded")
        })
    }

    pub fn snapshot(&self) -> SchedulerSnapshot {
        SchedulerSnapshot {
            active: self.inner.max_active - self.inner.global.available_permits(),
            pending: self.inner.pending.load(Ordering::SeqCst),
        }
    }
}
