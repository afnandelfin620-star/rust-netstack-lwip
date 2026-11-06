use std::future::Future;
use std::marker::PhantomPinned;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{io, os::raw, pin::Pin, sync::Once, time};

use futures::sink::Sink;
use futures::stream::Stream;
use futures::task::{Context, Poll};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;

use super::lwip::*;
use super::output::{output_ip4, output_ip6, OUTPUT_CB_PTR};
use super::tcp_listener::TcpListener;
use super::udp::UdpSocket;
use super::LWIP_MUTEX;
use crate::Error;

static LWIP_INIT: Once = Once::new();

// lwIP is a process-global singleton in this configuration (NO_SYS, one global
// netif, global pcb lists and `OUTPUT_CB_PTR`). Only one NetStack may exist at a
// time; this guards against a second one silently corrupting the first. Reset in
// `Drop`, so a new NetStack can be created after the previous one is dropped.
static NETSTACK_ALIVE: AtomicBool = AtomicBool::new(false);

/// Shared, reference-counted owner of the process-global lwIP stack state: the
/// timer task, the output-callback `Sender`, and the `NETSTACK_ALIVE` guard.
///
/// `NetStack`, `TcpListener`, `UdpSocket` (and every `TcpStream`/`SendHalf`
/// derived from them) each hold an `Arc<StackHandle>`, so teardown — aborting
/// the timer, clearing `OUTPUT_CB_PTR`, freeing the `Sender`, and releasing the
/// singleton guard — happens only when the *last* handle is dropped, regardless
/// of the order the user drops them in. This removes the footgun where dropping
/// `NetStack` first would silently stop driving lwIP for still-live listeners
/// and streams (or let a second `NetStack` repoint the global callback).
pub(crate) struct StackHandle {
    // Raw pointer (kept as usize so `StackHandle` stays `Send`) to a
    // heap-allocated `Sender` used only by the lwIP output callback. Owned here
    // and freed on drop. Deliberately separate from `NetStack::rx` so the
    // callback never has to form a reference to `NetStack`, which would alias
    // the `&mut` taken in `poll_next` and be undefined behaviour.
    output_tx: usize,
    // Background task driving lwIP's timers; aborted on drop so it doesn't keep
    // running (and calling into lwIP) after the stack is gone.
    timer: JoinHandle<()>,
}

impl Drop for StackHandle {
    fn drop(&mut self) {
        log::trace!("drop netstack");
        // Stop the timer task so it no longer drives lwIP after the stack is
        // gone. It only holds LWIP_MUTEX inside a synchronous block (no `.await`
        // in scope), so aborting can never leave the lock held.
        self.timer.abort();
        {
            let _g = LWIP_MUTEX.lock();
            // Only clear the global if it still points at our Sender: a later
            // NetStack may have overwritten it.
            if OUTPUT_CB_PTR.load(Ordering::Acquire) == self.output_tx {
                OUTPUT_CB_PTR.store(0, Ordering::Release);
            }
            // Reclaim the callback Sender. Safe under the lock: the output
            // callback only runs while LWIP_MUTEX is held, so it cannot be
            // reading this pointer concurrently, and it will no longer see it.
            unsafe { drop(Box::from_raw(self.output_tx as *mut Sender<Vec<u8>>)) };
        }
        // Allow a new NetStack to be created now that this one is gone.
        NETSTACK_ALIVE.store(false, Ordering::Release);
    }
}

pub struct NetStack {
    rx: Receiver<Vec<u8>>,
    sink_buf: Option<Vec<u8>>, // We're flushing per item, no need large buffer.
    // Timed backoff for retrying `poll_flush` when lwIP is out of pbuf memory.
    // lwIP gives no "memory freed" notification, so retry on a short timer
    // instead of self-waking, which would spin the executor at 100% CPU.
    alloc_backoff: Option<Pin<Box<tokio::time::Sleep>>>,
    // Keeps the shared lwIP stack alive for as long as this `NetStack` exists.
    _stack: Arc<StackHandle>,
    _pin: PhantomPinned,
}

impl NetStack {
    pub fn new() -> Result<(Pin<Box<Self>>, Pin<Box<TcpListener>>, Pin<Box<UdpSocket>>), Error> {
        NetStack::with_buffer_size(512, 64)
    }

    pub fn with_buffer_size(
        stack_buffer_size: usize,
        udp_buffer_size: usize,
    ) -> Result<(Pin<Box<Self>>, Pin<Box<TcpListener>>, Pin<Box<UdpSocket>>), Error> {
        let (stack, handle) = NetStack::_new(stack_buffer_size)?;
        // Each derived handle shares ownership of the stack, so it stays alive
        // (timer running, callback registered) until all of them are dropped.
        let listener = TcpListener::new(handle.clone())?;
        let udp = UdpSocket::new(udp_buffer_size, handle)?;
        Ok((stack, listener, udp))
    }

    fn _new(buffer_size: usize) -> Result<(Pin<Box<Self>>, Arc<StackHandle>), Error> {
        if NETSTACK_ALIVE.swap(true, Ordering::AcqRel) {
            return Err(Error::AlreadyRunning);
        }

        {
            let _g = LWIP_MUTEX.lock();
            LWIP_INIT.call_once(|| unsafe { lwip_init() });
            // Configure the (loopback) netif we repurpose as the TUN interface.
            // Held under the lock for consistency with every other lwIP access,
            // even though nothing else touches lwIP this early in setup.
            unsafe {
                (*netif_list).output = Some(output_ip4);
                (*netif_list).output_ip6 = Some(output_ip6);
                (*netif_list).mtu = 1500;
            }
        }

        let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel(buffer_size);
        let output_tx = Box::into_raw(Box::new(tx)) as usize;

        let timer = tokio::spawn(async move {
            loop {
                {
                    let _g = LWIP_MUTEX.lock();
                    unsafe { sys_check_timeouts() };
                }
                tokio::time::sleep(time::Duration::from_millis(250)).await;
            }
        });

        let handle = Arc::new(StackHandle { output_tx, timer });

        let stack = Box::pin(NetStack {
            rx,
            sink_buf: None,
            alloc_backoff: None,
            _stack: handle.clone(),
            _pin: PhantomPinned::default(),
        });

        {
            let _g = LWIP_MUTEX.lock();
            OUTPUT_CB_PTR.store(output_tx, Ordering::Release);
        }

        Ok((stack, handle))
    }

}

impl Stream for NetStack {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let me = unsafe { self.get_unchecked_mut() };
        // `poll_recv` registers `cx`'s waker on `Pending` and the channel wakes
        // it when the output callback sends, so no manual waker is needed.
        match me.rx.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => Poll::Ready(Some(Ok(pkt))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<Vec<u8>> for NetStack {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let me = unsafe { self.get_unchecked_mut() };
        if me.sink_buf.is_none() {
            Poll::Ready(Ok(()))
        } else {
            unsafe { Pin::new_unchecked(me) }.poll_flush(cx)
        }
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        unsafe { self.get_unchecked_mut() }.sink_buf.replace(item);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let me = unsafe { self.get_unchecked_mut() };
        let item = match me.sink_buf.take() {
            Some(item) => item,
            None => return Poll::Ready(Ok(())),
        };
        if item.is_empty() {
            return Poll::Ready(Ok(()));
        }
        unsafe {
            let _g = LWIP_MUTEX.lock();

            let pbuf = pbuf_alloc(pbuf_layer_PBUF_RAW, item.len() as u16_t, pbuf_type_PBUF_RAM);
            if pbuf.is_null() {
                // lwIP is out of memory. Keep the packet (don't drop it) and
                // retry after a short backoff — memory is reclaimed as the
                // timer task processes ACKs/timeouts, typically within a few
                // milliseconds. Self-waking instead would busy-spin the
                // executor at 100% CPU for as long as the pressure lasts.
                log::trace!("pbuf_alloc null alloc");
                me.sink_buf = Some(item);
                const BACKOFF: time::Duration = time::Duration::from_millis(10);
                let deadline = tokio::time::Instant::now() + BACKOFF;
                let sleep = match me.alloc_backoff.as_mut() {
                    Some(sleep) => {
                        // Re-arm the existing (elapsed) timer from a previous
                        // failed retry.
                        sleep.as_mut().reset(deadline);
                        sleep
                    }
                    None => me
                        .alloc_backoff
                        .insert(Box::pin(tokio::time::sleep_until(deadline))),
                };
                // Freshly armed 10ms ahead, so this registers the timer wakeup
                // rather than completing.
                let _ = sleep.as_mut().poll(cx);
                return Poll::Pending;
            }
            me.alloc_backoff = None;
            pbuf_take(
                pbuf,
                item.as_ptr() as *const raw::c_void,
                item.len() as u16_t,
            );

            if let Some(input_fn) = (*netif_list).input {
                let err = input_fn(pbuf, netif_list);
                if err == err_enum_t_ERR_OK as err_t {
                    Poll::Ready(Ok(()))
                } else {
                    pbuf_free(pbuf);
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("input error: {}", err),
                    )))
                }
            } else {
                pbuf_free(pbuf);
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "input fn not set",
                )))
            }
        }
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}


#[cfg(test)]
mod error_lifecycle_tests {
    use super::*;
    use crate::tcp_stream::{TcpStream, tcp_recv_cb};
    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

    #[test]
    fn failed_write_and_shutdown_preserve_pcb_cleanup_and_eof() {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            let (_stack, handle) = NetStack::_new(32).unwrap();
            for shutdown in [false, true] {
                let pcb = {
                    let _lock = LWIP_MUTEX.lock();
                    unsafe {
                        let pcb = tcp_new(); assert!(!pcb.is_null());
                        assert_eq!(tcp_bind(pcb, std::ptr::null(), 54321), err_enum_t_ERR_OK as err_t);
                        pcb
                    }
                };
                let mut stream = { let _lock = LWIP_MUTEX.lock(); TcpStream::new(pcb, handle.clone()) };
                let waker = futures::task::noop_waker();
                let mut cx = Context::from_waker(&waker);
                // A bound CLOSED PCB is alive but cannot write or SHUT_WR (ERR_CONN).
                // Poll once first: a regression to Interrupted must fail, not hang write_all.
                let error = if shutdown {
                    match stream.as_mut().poll_shutdown(&mut cx) { Poll::Ready(Err(e)) => e, _ => panic!("expected shutdown error") }
                } else {
                    match stream.as_mut().poll_write(&mut cx, b"x") { Poll::Ready(Err(e)) => e, _ => panic!("expected write error") }
                };
                assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
                assert_eq!(stream.write_all(b"x").await.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
                // Error must not have pretended the PCB was freed: its callback is still valid.
                { let _lock = LWIP_MUTEX.lock(); unsafe {
                    tcp_recv_cb((*pcb).callback_arg, pcb, std::ptr::null_mut(), err_enum_t_ERR_OK as err_t);
                } }
                let mut data = [0;1];
                assert_eq!(stream.read(&mut data).await.unwrap(), 0);
                assert_eq!(stream.read(&mut data).await.unwrap(), 0);
                drop(stream);
                // Actual destruction must release the bind, not leave a PCB with dangling callbacks.
                { let _lock = LWIP_MUTEX.lock(); unsafe {
                    let replacement = tcp_new(); assert!(!replacement.is_null());
                    let result = tcp_bind(replacement, std::ptr::null(), 54321);
                    tcp_abort(replacement);
                    assert_eq!(result, err_enum_t_ERR_OK as err_t, "old PCB leaked its port");
                } }
            }
        });
    }
}
