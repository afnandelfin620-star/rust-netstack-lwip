//! Defer only within one Future::poll. Nothing is retained across an async wait.
use std::{cell::RefCell, future::Future, sync::{Arc, atomic::Ordering}};
use crate::{lwip::*, tcp_stream_context::TcpStreamContext, LWIP_MUTEX};

#[derive(Default)]
struct Batch { active: bool, dirty: Vec<(usize, Arc<TcpStreamContext>)> }
thread_local! { static BATCH: RefCell<Batch> = RefCell::new(Batch::default()); }

// Called under LWIP_MUTEX. The Arc is the PCB lifetime token, not PCB ownership.
pub(crate) fn defer(pcb: usize, ctx: &Arc<TcpStreamContext>) -> bool {
    BATCH.with(|b| {
        let mut b = b.borrow_mut();
        if !b.active { return false; }
        if !b.dirty.iter().any(|(_, c)| Arc::ptr_eq(c, ctx)) {
            b.dirty.push((pcb, ctx.clone()));
        }
        true
    })
}

// Called under LWIP_MUTEX before explicit output/shutdown. Avoid a duplicate flush.
pub(crate) fn forget(ctx: &Arc<TcpStreamContext>) {
    BATCH.with(|b| b.borrow_mut().dirty.retain(|(_, c)| !Arc::ptr_eq(c, ctx)));
}

pub(crate) unsafe fn output(pcb: *mut tcp_pcb) -> err_t {
    #[cfg(feature = "datapath-diagnostics")]
    metrics::OUTPUT.fetch_add(1, Ordering::Relaxed);
    tcp_output(pcb)
}

struct Scope;
impl Drop for Scope {
    fn drop(&mut self) {
        BATCH.with(|b| b.borrow_mut().active = false);
        let _lock = LWIP_MUTEX.lock();
        loop {
            let next = BATCH.with(|b| b.borrow_mut().dirty.pop());
            let Some((pcb, ctx)) = next else { break };
            // Error/close/drop may have freed the PCB during this poll. An old
            // entry must never dereference it, even if its address was reused.
            if !ctx.pcb_gone.load(Ordering::Acquire) {
                unsafe { output(pcb as *mut tcp_pcb); }
            }
        }
    }
}

/// Batch TCP output during each synchronous poll of this future. Flush before
/// Pending, Ready, or unwinding; no timer, payload queue, or additional task.
pub async fn batch_tcp_output<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    futures::future::poll_fn(|cx| {
        BATCH.with(|b| { let mut b = b.borrow_mut(); assert!(!b.active, "nested output batch"); b.active = true; });
        let _scope = Scope;
        future.as_mut().poll(cx)
    }).await
}

#[cfg(feature = "datapath-diagnostics")]
pub mod metrics {
    use std::sync::atomic::{AtomicU64, Ordering};
    pub(crate) static WRITE: AtomicU64 = AtomicU64::new(0);
    pub(crate) static OUTPUT: AtomicU64 = AtomicU64::new(0);
    pub(crate) static TUN_PACKETS: AtomicU64 = AtomicU64::new(0);
    pub(crate) static TUN_BYTES: AtomicU64 = AtomicU64::new(0);
    /// Process-lifetime counters. Output counts Rust-initiated calls only;
    /// lwIP's internal ACK/timer-driven tcp_output calls are not included.
    pub fn snapshot() -> [u64; 4] {
        [&WRITE, &OUTPUT, &TUN_PACKETS, &TUN_BYTES].map(|v| v.load(Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{task::{Context, Poll}, pin::Pin};
    #[test]
    fn scope_deduplicates_and_clears_before_pending_and_cancel() {
        let (tx, _) = tokio::sync::mpsc::unbounded_channel();
        let ctx = Arc::new(TcpStreamContext::new("127.0.0.1:1".parse().unwrap(), tx));
        // A retired PCB entry must be skipped, never dereferenced.
        ctx.pcb_gone.store(true, Ordering::Release);
        let mut future = Box::pin(batch_tcp_output(async {
            assert!(defer(0, &ctx)); assert!(defer(0, &ctx));
            BATCH.with(|b| assert_eq!(b.borrow().dirty.len(), 1));
            futures::future::pending::<()>().await;
        }));
        let waker = futures::task::noop_waker();
        assert!(matches!(future.as_mut().poll(&mut Context::from_waker(&waker)), Poll::Pending));
        BATCH.with(|b| { assert!(!b.borrow().active); assert!(b.borrow().dirty.is_empty()); });
        drop(future);
        assert!(!defer(0, &ctx));
        let mut done = Box::pin(batch_tcp_output(async { assert!(defer(0, &ctx)); }));
        assert!(Pin::as_mut(&mut done).poll(&mut Context::from_waker(&waker)).is_ready());
        BATCH.with(|b| assert!(b.borrow().dirty.is_empty()));
    }
}
