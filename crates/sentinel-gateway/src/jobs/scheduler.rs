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
    /// Bulk transfers: one per host, separate from the interactive read pool (spec §11.3).
    per_host_transfers: Mutex<HashMap<HostId, Arc<Semaphore>>>,
    pending: AtomicUsize,
    max_pending: usize,
    pending_per_host: Mutex<HashMap<HostId, usize>>,
    max_pending_per_host: usize,
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

struct HostPendingGuard<'a>(&'a Mutex<HashMap<HostId, usize>>, HostId);

impl Drop for HostPendingGuard<'_> {
    fn drop(&mut self) {
        let mut m = self.0.lock().expect("per-host pending");
        if let Some(n) = m.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.1);
            }
        }
    }
}

/// A slot for a tool that runs no SSH (inventory, artefact reads): a global slot only.
#[derive(Debug)]
pub struct LocalPermit {
    _global: OwnedSemaphorePermit,
}

impl Scheduler {
    pub fn new(b: &Budgets) -> Self {
        Self {
            inner: Arc::new(Inner {
                global: Arc::new(Semaphore::new(b.max_active_operations)),
                max_active: b.max_active_operations,
                per_host_limit: b.per_host_reads,
                per_host: Mutex::new(HashMap::new()),
                per_host_transfers: Mutex::new(HashMap::new()),
                pending: AtomicUsize::new(0),
                max_pending: b.max_pending_operations,
                pending_per_host: Mutex::new(HashMap::new()),
                max_pending_per_host: b.max_pending_per_host,
                queue_wait: Duration::from_secs(b.queue_wait_secs),
            }),
        }
    }

    fn host_semaphore(map: &Mutex<HashMap<HostId, Arc<Semaphore>>>, host: &HostId, permits: usize) -> Arc<Semaphore> {
        let mut m = map.lock().expect("per-host semaphores");
        m.entry(host.clone()).or_insert_with(|| Arc::new(Semaphore::new(permits))).clone()
    }

    /// One of the per-host interactive read slots plus a global slot.
    pub async fn acquire_read(&self, host: &HostId) -> Result<ReadPermit> {
        let sem = Self::host_semaphore(&self.inner.per_host, host, self.inner.per_host_limit);
        self.acquire(host, sem).await
    }

    /// The host's single bulk-transfer slot plus a global slot. Never takes a read slot, so a long download cannot
    /// stall inspection of the same host.
    pub async fn acquire_transfer(&self, host: &HostId) -> Result<ReadPermit> {
        let sem = Self::host_semaphore(&self.inner.per_host_transfers, host, 1);
        self.acquire(host, sem).await
    }

    /// A global slot for a local tool, under the same pending and queue-wait limits.
    pub async fn acquire_local(&self) -> Result<LocalPermit> {
        let i = &self.inner;
        let _pending = self.enter_queue()?;
        let g = tokio::time::timeout(i.queue_wait, i.global.clone().acquire_owned())
            .await
            .map_err(|_| self.queue_wait_exceeded())?
            .expect("semaphore never closed");
        Ok(LocalPermit { _global: g })
    }

    fn enter_queue(&self) -> Result<PendingGuard<'_>> {
        let i = &self.inner;
        if i.pending.fetch_add(1, Ordering::SeqCst) >= i.max_pending {
            i.pending.fetch_sub(1, Ordering::SeqCst);
            return Err(SentinelError::new(ErrorCode::BudgetExceeded, "gateway queue is full")
                .with_detail("reason", "pending_limit")
                .with_retry(RetryStrategy::RetryAfter { seconds: 1 }));
        }
        Ok(PendingGuard(&i.pending))
    }

    fn queue_wait_exceeded(&self) -> SentinelError {
        SentinelError::new(
            ErrorCode::BudgetExceeded,
            format!("waited {} s for a free slot", self.inner.queue_wait.as_secs()),
        )
        .with_detail("reason", "queue_wait_exceeded")
    }

    async fn acquire(&self, host: &HostId, host_sem: Arc<Semaphore>) -> Result<ReadPermit> {
        let i = &self.inner;
        let _pending = self.enter_queue()?;
        let _host_pending = {
            let mut m = i.pending_per_host.lock().expect("per-host pending");
            let n = m.entry(host.clone()).or_insert(0);
            if *n >= i.max_pending_per_host {
                return Err(SentinelError::new(ErrorCode::BudgetExceeded, "this host's queue is full")
                    .with_detail("reason", "host_pending_limit")
                    .with_retry(RetryStrategy::RetryAfter { seconds: 1 }));
            }
            *n += 1;
            HostPendingGuard(&i.pending_per_host, host.clone())
        };
        // Host permit first: a waiter blocked on a saturated host must not hold a global slot other hosts need.
        let acquire = async {
            let h = host_sem.acquire_owned().await.expect("semaphore never closed");
            let g = i.global.clone().acquire_owned().await.expect("semaphore never closed");
            ReadPermit { _global: g, _host: h }
        };
        tokio::time::timeout(i.queue_wait, acquire)
            .await
            .map_err(|_| self.queue_wait_exceeded())
    }

    pub fn snapshot(&self) -> SchedulerSnapshot {
        SchedulerSnapshot {
            active: self.inner.max_active - self.inner.global.available_permits(),
            pending: self.inner.pending.load(Ordering::SeqCst),
        }
    }
}
