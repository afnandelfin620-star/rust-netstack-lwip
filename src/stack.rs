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
use super::output::{output_ip4, output_ip6, OutputTarget, OUTPUT_CB_PTR};
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
/// timer task, the output-callback target, and the `NETSTACK_ALIVE` guard.
///
/// `NetStack`, `TcpListener`, `UdpSocket` (and every `TcpStream`/`SendHalf`
/// derived from them) each hold an `Arc<StackHandle>`, so teardown — aborting
/// the timer, clearing `OUTPUT_CB_PTR`, freeing the output target, and releasing the
/// singleton guard — happens only when the *last* handle is dropped, regardless
/// of the order the user drops them in. This removes the footgun where dropping
/// `NetStack` first would silently stop driving lwIP for still-live listeners
/// and streams (or let a second `NetStack` repoint the global callback).
pub(crate) struct StackHandle {
    // Raw pointer (kept as usize so `StackHandle` stays `Send`) to a
    // heap-allocated `OutputTarget` used only by the lwIP output callback. Owned here
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
            // Only clear the global if it still points at our target: a later
            // NetStack may have overwritten it.
            if OUTPUT_CB_PTR.load(Ordering::Acquire) == self.output_tx {
                OUTPUT_CB_PTR.store(0, Ordering::Release);
            }
            // Reclaim the callback target. Safe under the lock: the output
            // callback only runs while LWIP_MUTEX is held, so it cannot be
            // reading this pointer concurrently, and it will no longer see it.
            unsafe { drop(Box::from_raw(self.output_tx as *mut OutputTarget)) };
        }
        // Allow a new NetStack to be created now that this one is gone.
        NETSTACK_ALIVE.store(false, Ordering::Release);
    }
}

pub struct NetStack {
    rx: Receiver<Vec<u8>>,
    sink_buf: Option<bytes::Bytes>, // We're flushing per item, no need large buffer.
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
                (*netif_list).mtu = crate::TUN_MTU;
                (*netif_list).mtu6 = crate::TUN_MTU;
            }
        }

        let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel(buffer_size);
        let output_tx = Box::into_raw(Box::new(OutputTarget::Channel(tx))) as usize;

        let timer = tokio::spawn(async move {
            loop {
                {
                    let _g = LWIP_MUTEX.lock();
                    #[cfg(feature = "timer-diagnostics")]
                    let measurement = crate::timer_diagnostics::Measurement::start();
                    unsafe { sys_check_timeouts() };
                    #[cfg(feature = "timer-diagnostics")]
                    measurement.finish();
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

/// Keeps the callback alive and disables output before releasing its resources.
pub struct DirectOutput { stack: Arc<StackHandle>, errors: tokio::sync::watch::Receiver<crate::output::OutputError> }
impl DirectOutput {
    pub async fn wait_error(&mut self) -> io::Error {
        loop {
            if let Some((kind, os)) = *self.errors.borrow_and_update() {
                let msg = match os {
                    Some(code) => format!("direct TUN output failed: {kind:?} (os error {code})"),
                    None => format!("direct TUN output failed: {kind:?}"),
                };
                return io::Error::new(kind, msg);
            }
            if self.errors.changed().await.is_err() { return io::ErrorKind::BrokenPipe.into(); }
        }
    }
}
impl Drop for DirectOutput {
    fn drop(&mut self) {
        let _lock = LWIP_MUTEX.lock();
        unsafe { *(self.stack.output_tx as *mut OutputTarget) = OutputTarget::Disabled; }
    }
}
impl NetStack {
    /// Writer must be nonblocking and must not call back into lwIP or panic.
    /// The callback borrows each packet only until this function returns.
    pub fn direct_output<F>(&self, writer: F) -> io::Result<DirectOutput>
    where F: Fn(&[io::IoSlice<'_>]) -> io::Result<usize> + Send + Sync + 'static {
        let _lock = LWIP_MUTEX.lock();
        let (tx, rx) = tokio::sync::watch::channel(None);
        unsafe {
            let target = &mut *(self._stack.output_tx as *mut OutputTarget);
            if matches!(target, OutputTarget::Direct { .. }) {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "direct output already registered"));
            }
            *target = OutputTarget::Direct { writer: Box::new(writer), errors: tx, failed: false, stats: Default::default() };
        }
        Ok(DirectOutput { stack: self._stack.clone(), errors: rx })
    }
}

pub struct StackInput { _stack: Arc<StackHandle> }
pub type StackStream = Pin<Box<NetStack>>;
impl NetStack {
    pub fn split_io(self: Pin<Box<Self>>) -> (StackInput, StackStream) {
        (StackInput { _stack: self._stack.clone() }, self)
    }
}
// Must be dropped under LWIP_MUTEX, unless ownership passes to netif input.
struct OwnedInputPbuf(*mut pbuf);
impl Drop for OwnedInputPbuf {
    fn drop(&mut self) { unsafe { pbuf_free(self.0); } }
}
impl StackInput {
    /// Read into contiguous PBUF_RAM; callback must be nonblocking and not re-enter lwIP.
    /// # Safety
    /// On Ok(n), the callback must have initialized the first n bytes.
    pub unsafe fn ingest_packet_with<F>(&mut self, capacity: usize, read: F) -> io::Result<usize>
    where F: FnOnce(&mut [std::mem::MaybeUninit<u8>]) -> io::Result<usize> {
        // PBUF_RAM rounds payload length up inside a u16. Leave room for
        // the largest MEM_ALIGNMENT (8) used by our supported targets.
        let capacity = u16::try_from(capacity).ok().filter(|n| *n != 0 && *n as usize <= 65528 - crate::TUN_HEADROOM)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid pbuf capacity"))?;
        let _lock = LWIP_MUTEX.lock();
        let raw = pbuf_alloc(pbuf_layer_PBUF_RAW, capacity + crate::TUN_HEADROOM as u16, pbuf_type_PBUF_RAM);
        if raw.is_null() {
            return Err(io::Error::new(io::ErrorKind::OutOfMemory, "pbuf allocation failed"));
        }
        let owned = OwnedInputPbuf(raw);
        if pbuf_remove_header(raw, crate::TUN_HEADROOM as _) != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "pbuf headroom reservation failed"));
        }
        let storage = std::slice::from_raw_parts_mut(
            std::ptr::addr_of!((*raw).payload).read_unaligned().cast::<std::mem::MaybeUninit<u8>>(), capacity as usize);
        let n = read(storage)?;
        if n > capacity as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "read exceeded pbuf capacity"));
        }
        if n == 0 { return Ok(0); }
        pbuf_realloc(raw, n as u16);
        let input = (*netif_list).input.ok_or_else(||
            io::Error::new(io::ErrorKind::NotConnected, "netif input missing"))?;
        let err = input(raw, netif_list);
        if err != err_enum_t_ERR_OK as err_t {
            return Err(io::Error::new(io::ErrorKind::Other, format!("netif input failed: {err}")));
        }
        std::mem::forget(owned);
        Ok(n)
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

impl NetStack {
    fn poll_ready_internal(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let me = unsafe { self.get_unchecked_mut() };
        if me.sink_buf.is_none() {
            Poll::Ready(Ok(()))
        } else {
            unsafe { Pin::new_unchecked(me) }.poll_flush_internal(cx)
        }
    }

    fn poll_flush_internal(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
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
}

impl Sink<bytes::Bytes> for NetStack {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_ready_internal(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: bytes::Bytes) -> Result<(), Self::Error> {
        unsafe { self.get_unchecked_mut() }.sink_buf.replace(item);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_flush_internal(cx)
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl Sink<Vec<u8>> for NetStack {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_ready_internal(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        unsafe { self.get_unchecked_mut() }.sink_buf.replace(bytes::Bytes::from(item));
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_flush_internal(cx)
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
            crate::udp::verify_owned_datagrams(handle.clone()).await;
            let mut input = StackInput { _stack: handle.clone() };
            // Exercise the actual largest packet through the TUN ingestion API,
            // including reserved headroom, IPv4 and UDP length fields.
            {
                let udp = UdpSocket::new(4, handle.clone()).unwrap();
                let (_sender, mut receiver) = udp.split();
                let size = crate::TUN_MTU as usize;
                let mut wire = vec![0x5a; size];
                wire[..28].fill(0);
                wire[0] = 0x45;
                wire[2..4].copy_from_slice(&(size as u16).to_be_bytes());
                wire[8] = 64; wire[9] = 17;
                wire[12..16].copy_from_slice(&[10,0,0,2]);
                wire[16..20].copy_from_slice(&[10,0,0,1]);
                wire[20..22].copy_from_slice(&12345u16.to_be_bytes());
                wire[22..24].copy_from_slice(&443u16.to_be_bytes());
                wire[24..26].copy_from_slice(&((size - 20) as u16).to_be_bytes());
                unsafe {
                    assert_eq!(input.ingest_packet_with(size + 1, |buf| {
                        for (dst, src) in buf.iter_mut().zip(&wire) { dst.write(*src); }
                        Ok(size)
                    }).unwrap(), size);
                }
                let (payload, src, dst) = tokio::time::timeout(time::Duration::from_secs(1), receiver.recv_from()).await.unwrap().unwrap();
                assert_eq!((src.port(), dst.port()), (12345, 443));
                assert_eq!(payload.len(), size - 28);
                assert!(payload.iter().all(|b| *b == 0x5a));
            }

            unsafe {
                for capacity in [0, 65209, 65528, 65535, 65536, usize::MAX] {
                    assert_eq!(input.ingest_packet_with(capacity, |_| panic!("must not read"))
                        .unwrap_err().kind(), io::ErrorKind::InvalidInput);
                }
                // More allocations than the 32 MiB heap can hold if cleanup leaks.
                for _ in 0..600 {
                    assert_eq!(input.ingest_packet_with(65208, |_| Err(io::ErrorKind::WouldBlock.into()))
                        .unwrap_err().kind(), io::ErrorKind::WouldBlock);
                }
                assert_eq!(input.ingest_packet_with(64, |_| Ok(65)).unwrap_err().kind(), io::ErrorKind::InvalidData);
                assert_eq!(input.ingest_packet_with(64, |_| Ok(0)).unwrap(), 0);
                let mut held = Vec::new();
                {
                    let _lock = LWIP_MUTEX.lock();
                    loop {
                        let p = pbuf_alloc(pbuf_layer_PBUF_RAW, 2048, pbuf_type_PBUF_RAM);
                        if p.is_null() { break; }
                        held.push(p);
                    }
                }
                assert_eq!(input.ingest_packet_with(2048, |_| panic!("OOM must not consume input"))
                    .unwrap_err().kind(), io::ErrorKind::OutOfMemory);
                {
                    let _lock = LWIP_MUTEX.lock();
                    for p in held { pbuf_free(p); }
                }
                let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _ = input.ingest_packet_with(65208, |_| panic!("reader panic"));
                }));
                assert!(panic.is_err());
                // Invalid IP version is deliberately discarded by lwIP, which owns/free it.
                for _ in 0..600 {
                    assert_eq!(input.ingest_packet_with(65208, |buf| {
                        for byte in &mut buf[..40] { byte.write(0); }
                        Ok(40)
                    }).unwrap(), 40);
                }
            }
            // Receive chained pbufs without an intermediate payload Vec. A small
            // read preserves the tail; the following large read batches packets.
            {
                let mut stream = {
                    let _lock = LWIP_MUTEX.lock();
                    unsafe {
                        let pcb = tcp_new();
                        let stream = TcpStream::new(pcb, handle.clone());
                        for pair in [(b"abc".as_slice(), b"def".as_slice()), (b"ghi".as_slice(), b"jkl".as_slice())] {
                            let p = pbuf_alloc(pbuf_layer_PBUF_RAW, 3, pbuf_type_PBUF_RAM);
                            let q = pbuf_alloc(pbuf_layer_PBUF_RAW, 3, pbuf_type_PBUF_RAM);
                            assert!(!p.is_null() && !q.is_null());
                            pbuf_take(p, pair.0.as_ptr().cast(), 3);
                            pbuf_take(q, pair.1.as_ptr().cast(), 3);
                            pbuf_cat(p, q);
                            assert_eq!(tcp_recv_cb((*pcb).callback_arg, pcb, p, 0), 0);
                        }
                        tcp_recv_cb((*pcb).callback_arg, pcb, std::ptr::null_mut(), 0);
                        stream
                    }
                };
                let mut first = [0;2];
                stream.read_exact(&mut first).await.unwrap();
                assert_eq!(&first, b"ab");
                let mut rest = [0;32];
                let n = stream.read(&mut rest).await.unwrap();
                assert_eq!(&rest[..n], b"cdefghijkl");
                assert_eq!(stream.read(&mut rest).await.unwrap(), 0);
            }
            // Remote framing must prepend in place and retain the original
            // receive-window credit until the last Bytes reference is released.
            for shared in [false, true] {
                let (mut stream, pcb, raw, address) = {
                    let _lock = LWIP_MUTEX.lock();
                    unsafe {
                        let pcb = tcp_new();
                        let stream = TcpStream::new(pcb, handle.clone());
                        let p = pbuf_alloc(pbuf_layer_PBUF_RAW, 323, pbuf_type_PBUF_RAM);
                        assert!(!p.is_null());
                        pbuf_remove_header(p, 320);
                        pbuf_take(p, b"abc".as_ptr().cast(), 3);
                        let address = std::ptr::addr_of!((*p).payload).read_unaligned() as usize;
                        if shared { pbuf_ref(p); }
                        std::ptr::addr_of_mut!((*pcb).rcv_wnd).write_unaligned(1000);
                        tcp_recv_cb((*pcb).callback_arg, pcb, p, 0);
                        (stream, pcb, p, address)
                    }
                };
                let frame = futures::future::poll_fn(|cx| stream.as_mut().poll_read_frame(cx, b"HEAD")).await.unwrap();
                assert_eq!(&frame[..], b"HEADabc");
                if !shared {
                    assert_eq!(frame[4..].as_ptr() as usize, address);
                    { let _lock = LWIP_MUTEX.lock(); unsafe {
                        assert_eq!(std::ptr::addr_of!((*pcb).rcv_wnd).read_unaligned(), 1000);
                    } }
                } else {
                    assert_ne!(frame[4..].as_ptr() as usize, address);
                    let _lock = LWIP_MUTEX.lock();
                    unsafe {
                        assert_eq!(std::ptr::read_unaligned(raw).len, 3);
                        pbuf_free(raw);
                    }
                }
                let copy = frame.clone(); drop(frame);
                drop(copy);
                { let _lock = LWIP_MUTEX.lock(); unsafe {
                    assert_eq!(std::ptr::addr_of!((*pcb).rcv_wnd).read_unaligned(), 1003);
                } }
                drop(stream);
            }
            // A frame queued to WebSocket can outlive the connection or be
            // cancelled. Its destructor must not touch the freed PCB.
            for _ in 0..600 {
                let mut stream = {
                    let _lock = LWIP_MUTEX.lock();
                    unsafe {
                        let pcb = tcp_new();
                        let stream = TcpStream::new(pcb, handle.clone());
                        let p = pbuf_alloc(pbuf_layer_PBUF_RAW, 323, pbuf_type_PBUF_RAM);
                        pbuf_remove_header(p, 320);
                        pbuf_take(p, b"abc".as_ptr().cast(), 3);
                        tcp_recv_cb((*pcb).callback_arg, pcb, p, 0);
                        stream
                    }
                };
                let frame = futures::future::poll_fn(|cx| stream.as_mut().poll_read_frame(cx, b"HEAD")).await.unwrap();
                drop(stream);
                assert_eq!(&frame[..], b"HEADabc");
                drop(frame);
            }
            // Cancellation with one partly-read chain and another queued chain
            // must reclaim both, without crediting a detached/freed PCB.
            for _ in 0..600 {
                let mut stream = {
                    let _lock = LWIP_MUTEX.lock();
                    unsafe {
                        let pcb = tcp_new();
                        let stream = TcpStream::new(pcb, handle.clone());
                        for _ in 0..2 {
                            let p = pbuf_alloc(pbuf_layer_PBUF_RAW, 32768, pbuf_type_PBUF_RAM);
                            assert!(!p.is_null(), "cancelled receive leaked pbufs");
                            let payload = std::ptr::addr_of!((*p).payload).read_unaligned();
                            std::ptr::write_bytes(payload.cast::<u8>(), 0x5a, 32768);
                            tcp_recv_cb((*pcb).callback_arg, pcb, p, 0);
                        }
                        stream
                    }
                };
                let mut byte = [0];
                stream.read_exact(&mut byte).await.unwrap();
                assert_eq!(byte, [0x5a]);
                drop(stream);
            }
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
            crate::output::verify_direct_output(&_stack).await;
        });
    }
}
