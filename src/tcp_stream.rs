use std::marker::PhantomPinned;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::{cmp::min, io, net::SocketAddr, os::raw, pin::Pin};

use futures::task::{Context, Poll};
use log::*;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc::{unbounded_channel, UnboundedReceiver},
};

use super::lwip::*;
use super::stack::StackHandle;
use super::tcp_stream_context::TcpStreamContext;
use super::util;
use super::LWIP_MUTEX;

#[allow(unused_variables)]
pub unsafe extern "C" fn tcp_recv_cb(
    arg: *mut raw::c_void,
    tpcb: *mut tcp_pcb,
    p: *mut pbuf,
    err: err_t,
) -> err_t {
    if arg.is_null() {
        warn!("tcp connection has been closed");
        return err_enum_t_ERR_CONN as err_t;
    }

    // SAFETY: `arg` points to the `TcpStreamContext` of a pinned, still-alive
    // TcpStream (cleared to null in its Drop). We form only a shared reference;
    // every field is thread-safe.
    let ctx = &*(arg as *const TcpStreamContext);

    if err != err_enum_t_ERR_OK as err_t {
        // lwIP documents this as currently always ERR_OK, but surface it if
        // that ever changes rather than silently ignoring it.
        warn!("netstack tcp recv error {} {}", err, ctx.local_addr);
    }

    if p.is_null() {
        trace!("netstack tcp eof {}", ctx.local_addr);
        if ctx.tx_closed.load(Ordering::Acquire) {
            // Our FIN is already out and the peer's FIN just arrived, so the
            // pcb is completing the close handshake (CLOSING or TIME_WAIT).
            // From TIME_WAIT lwIP frees it after 2*TCP_MSL with NO callback
            // (tcp_slowtmr reclaims tw pcbs silently), so this is the last
            // moment the pcb is certainly alive: detach the callbacks and mark
            // it off-limits now. Drop/poll_* must not touch it after this.
            ctx.pcb_gone.store(true, Ordering::Release);
            tcp_arg(tpcb, std::ptr::null_mut());
            tcp_recv(tpcb, None);
            tcp_sent(tpcb, None);
            tcp_err(tpcb, None);
            tcp_poll(tpcb, None, 0);
            // A writer parked before the shutdown would otherwise never be
            // woken again (the sent/poll callbacks are detached now).
            ctx.write_waker.wake();
        }
        let _ = ctx.read_tx.send(0);
        return err_enum_t_ERR_OK as err_t;
    }

    // Transfer ownership, not payload bytes. No window credit until consumed.
    if ctx.read_tx.send(p as usize).is_err() { pbuf_free(p); }
    err_enum_t_ERR_OK as err_t
}

#[allow(unused_variables)]
pub extern "C" fn tcp_sent_cb(arg: *mut raw::c_void, tpcb: *mut tcp_pcb, len: u16_t) -> err_t {
    if arg.is_null() {
        return err_enum_t_ERR_OK as err_t;
    }
    // SAFETY: see `tcp_recv_cb`.
    let ctx = unsafe { &*(arg as *const TcpStreamContext) };
    ctx.write_waker.wake();
    err_enum_t_ERR_OK as err_t
}

#[allow(unused_variables)]
pub extern "C" fn tcp_err_cb(arg: *mut ::std::os::raw::c_void, err: err_t) {
    if arg.is_null() {
        return;
    }
    // SAFETY: see `tcp_recv_cb`.
    let ctx = unsafe { &*(arg as *const TcpStreamContext) };
    trace!("netstack tcp err {} {}", err, ctx.local_addr);
    // lwIP has already freed the pcb when this callback fires; it must never
    // be touched again. ERR_CLSD is not a failure: it reports the close
    // handshake completing after both sides shut down (the CLOSE_WAIT ->
    // LAST_ACK path), so the reader should see a clean EOF, not a broken pipe.
    ctx.pcb_gone.store(true, Ordering::Release);
    if err != err_enum_t_ERR_CLSD as err_t {
        ctx.errored.store(true, Ordering::Release);
    }
    // Wake a parked reader via a zero-pointer sentinel and a parked writer.
    let _ = ctx.read_tx.send(0);
    ctx.write_waker.wake();
}

#[allow(unused_variables)]
pub extern "C" fn tcp_poll_cb(arg: *mut ::std::os::raw::c_void, tpcb: *mut tcp_pcb) -> err_t {
    if arg.is_null() {
        return err_enum_t_ERR_OK as err_t;
    }
    // SAFETY: see `tcp_recv_cb`.
    let ctx = unsafe { &*(arg as *const TcpStreamContext) };
    ctx.write_waker.wake();
    err_enum_t_ERR_OK as err_t
}

pub struct TcpStream {
    src_addr: SocketAddr,
    dest_addr: SocketAddr,
    pcb: usize,
    // Own the received chain until copied into the caller's reusable buffer.
    read_current: Option<ReceivedPbuf>,
    callback_ctx: Arc<TcpStreamContext>,
    // Receiving end of the channel fed by `tcp_recv_cb`; owned solely by the
    // async side, so it needs no sharing/locking.
    read_rx: UnboundedReceiver<usize>,
    is_eof: bool,
    // Keeps the shared lwIP stack alive for as long as this connection exists,
    // so the timer keeps driving it even if the netstack/listener are dropped.
    _stack: Arc<StackHandle>,
    _pin: PhantomPinned,
}

impl TcpStream {
    pub(crate) fn new(pcb: *mut tcp_pcb, stack: Arc<StackHandle>) -> Pin<Box<Self>> {
        unsafe {
            // Since we have no idea how to deal with a full bounded channel upon receiving
            // data from lwIP, an unbounded channel is used instead.
            //
            // Note that lwIP is in charge of flow control. If reader is slower than writer,
            // lwIP will propagate the pressure back by announcing a decreased window size.
            // Thus our unbounded channel will never be overwhelmed. To achieve this, we must
            // call `tcp_recved` when the data from our internal buffer are consumed.
            let (read_tx, read_rx) = unbounded_channel();
            let pcb_v = std::ptr::read_unaligned(pcb);
            let src_addr = util::to_socket_addr(&pcb_v.remote_ip, pcb_v.remote_port);
            let dest_addr = util::to_socket_addr(&pcb_v.local_ip, pcb_v.local_port);
            let stream = Box::pin(TcpStream {
                src_addr,
                dest_addr,
                pcb: pcb as usize,
                read_current: None,
                callback_ctx: Arc::new(TcpStreamContext::new(src_addr, read_tx)),
                read_rx,
                is_eof: false,
                _stack: stack,
                _pin: PhantomPinned::default(),
            });
            let arg = Arc::as_ptr(&stream.callback_ctx);
            tcp_arg(pcb, arg as *mut raw::c_void);
            tcp_recv(pcb, Some(tcp_recv_cb));
            tcp_sent(pcb, Some(tcp_sent_cb));
            tcp_err(pcb, Some(tcp_err_cb));
            tcp_poll(pcb, Some(tcp_poll_cb), 8 as _);
            stream.apply_pcb_opts();
            trace!("netstack tcp new {}", stream.local_addr());
            stream
        }
    }

    fn apply_pcb_opts(&self) {
        // Set only the individual fields we care about, rather than round-
        // tripping the whole `tcp_pcb` through read/write (which would clobber
        // every other field). Use raw field pointers + unaligned access since
        // the pcb has no alignment guarantee here.
        unsafe {
            let pcb = self.pcb as *mut tcp_pcb;
            #[cfg(target_os = "ios")]
            {
                let so_options = std::ptr::addr_of_mut!((*pcb).so_options);
                so_options.write_unaligned(so_options.read_unaligned() | SOF_KEEPALIVE as u8);
            }
            let flags = std::ptr::addr_of_mut!((*pcb).flags);
            flags.write_unaligned(flags.read_unaligned() | TF_NODELAY as tcpflags_t);
        }
    }

    pub fn local_addr(&self) -> &SocketAddr {
        &self.src_addr
    }

    pub fn remote_addr(&self) -> &SocketAddr {
        &self.dest_addr
    }

    fn send_buf_size(&self) -> usize {
        unsafe { std::ptr::read_unaligned(self.pcb as *const tcp_pcb).snd_buf as usize }
    }
}

fn broken_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe")
}

// The receive callback relinquishes the entire pbuf chain. lwIP no longer
// mutates it. Keep stack/flags alive until this chain is consumed or dropped.
struct ReceivedPbuf {
    root: usize,
    node: usize,
    offset: usize,
    pcb: usize,
    length: u16,
    ctx: Arc<TcpStreamContext>,
    _stack: Arc<StackHandle>,
}
impl Drop for ReceivedPbuf {
    fn drop(&mut self) {
        let _lock = LWIP_MUTEX.lock();
        unsafe {
            pbuf_free(self.root as *mut pbuf);
            if !self.ctx.pcb_gone.load(Ordering::Acquire) {
                tcp_recved(self.pcb as *mut tcp_pcb, self.length);
            }
        }
    }
}
impl AsyncRead for TcpStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let me = unsafe { self.get_unchecked_mut() };
        if buf.remaining() == 0 { return Poll::Ready(Ok(())); }
        if me.callback_ctx.errored.load(Ordering::Acquire) { return Poll::Ready(Err(broken_pipe())); }
        let initial = buf.filled().len();
        loop {
            if let Some(packet) = me.read_current.as_mut() {
                while packet.node != 0 && buf.remaining() > 0 {
                    // Exclusive payload ownership passed from the receive callback;
                    // lwIP no longer modifies it. No lwIP lock is held while copying.
                    let node = unsafe { std::ptr::read_unaligned(packet.node as *const pbuf) };
                    let count = min(buf.remaining(), node.len as usize - packet.offset);
                    let data = unsafe { std::slice::from_raw_parts(
                        (node.payload as *const u8).add(packet.offset), count) };
                    buf.put_slice(data);
                    packet.offset += count;
                    if packet.offset == node.len as usize {
                        packet.node = node.next as usize;
                        packet.offset = 0;
                    }
                }
                if packet.node == 0 { me.read_current = None; }
                if buf.remaining() == 0 { return Poll::Ready(Ok(())); }
            }
            if me.is_eof { return Poll::Ready(Ok(())); }
            match me.read_rx.poll_recv(cx) {
                Poll::Pending => return if buf.filled().len() > initial {
                    Poll::Ready(Ok(()))
                } else { Poll::Pending },
                Poll::Ready(None) => return if buf.filled().len() > initial {
                    Poll::Ready(Ok(()))
                } else { Poll::Ready(Err(broken_pipe())) },
                Poll::Ready(Some(0)) => {
                    me.is_eof = true;
                    return if me.callback_ctx.errored.load(Ordering::Acquire) && buf.filled().len() == initial {
                        Poll::Ready(Err(broken_pipe()))
                    } else { Poll::Ready(Ok(())) };
                }
                Poll::Ready(Some(raw)) => {
                    let root = unsafe { std::ptr::read_unaligned(raw as *const pbuf) };
                    me.read_current = Some(ReceivedPbuf { root: raw, node: raw, offset: 0,
                        pcb: me.pcb, length: root.tot_len, ctx: me.callback_ctx.clone(),
                        _stack: me._stack.clone() });
                }
            }
        }
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let _guard = LWIP_MUTEX.lock();
        trace!("netstack tcp drop {}", &self.callback_ctx.local_addr);
        self.read_rx.close();
        while let Ok(raw) = self.read_rx.try_recv() {
            if raw != 0 { unsafe { pbuf_free(raw as *mut pbuf); } }
        }

        // If the pcb is gone (errored, close handshake completed, or parked in
        // TIME_WAIT for lwIP to reclaim), the callbacks are already detached
        // and the pcb may already be freed — don't touch it.
        if !self.callback_ctx.pcb_gone.load(Ordering::Acquire) {
            unsafe {
                let pcb = self.pcb as *mut tcp_pcb;
                // Detach our callbacks first: the TcpStreamContext is freed once
                // this Drop returns, so lwIP must not call back into it. With
                // recv cleared, lwIP falls back to tcp_recv_null, which drains
                // any further input and closes on the peer's FIN.
                tcp_arg(pcb, std::ptr::null_mut());
                tcp_recv(pcb, None);
                tcp_sent(pcb, None);
                tcp_err(pcb, None);
                tcp_poll(pcb, None, 0);
                if self.callback_ctx.tx_closed.load(Ordering::Acquire) {
                    // poll_shutdown only closed the TX side (SHUT_WR), which
                    // does not set TF_RXCLOSED, so lwIP would never time out a
                    // pcb parked in FIN_WAIT_2 awaiting the peer's FIN — leaking
                    // it. tcp_close sets TF_RXCLOSED and hands the pcb back for
                    // reclamation; fall back to abort if it can't (ERR_MEM).
                    if tcp_close(pcb) != err_enum_t_ERR_OK as err_t {
                        tcp_abort(pcb);
                    }
                } else {
                    tcp_abort(pcb);
                }
            }
        }
        // Any outstanding owned chunks must not credit this PCB after teardown.
        self.callback_ctx.pcb_gone.store(true, Ordering::Release);
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        let _guard = LWIP_MUTEX.lock();
        // `pcb_gone` covers both cases that make writing impossible: an error
        // (`errored` implies it) and a completed close.
        if self.callback_ctx.pcb_gone.load(Ordering::Acquire) {
            return Poll::Ready(Err(broken_pipe()));
        }
        let to_write = buf.len().min(self.send_buf_size()).min(u16::MAX as usize);
        if to_write == 0 {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            self.callback_ctx.write_waker.register(cx.waker());
            return Poll::Pending;
        }
        let err = unsafe {
            tcp_write(
                self.pcb as *mut tcp_pcb,
                buf.as_ptr() as *const raw::c_void,
                to_write as u16_t,
                TCP_WRITE_FLAG_COPY as u8,
            )
        };
        if err == err_enum_t_ERR_OK as err_t {
            // The bytes are now owned by lwIP (queued in `unsent`), so the write
            // has succeeded regardless of whether we can flush them right now.
            // tcp_output only *attempts* to send; a non-OK result here (usually
            // ERR_MEM under memory pressure) is transient — lwIP flushes on the
            // next timer tick, ACK, or poll_flush — so reporting it as a write
            // failure would spuriously get an otherwise-healthy connection reset.
            let out = unsafe { tcp_output(self.pcb as *mut tcp_pcb) };
            if out != err_enum_t_ERR_OK as err_t {
                trace!(
                    "netstack tcp_output deferred ({}) on {}",
                    out, self.callback_ctx.local_addr
                );
            }
            Poll::Ready(Ok(to_write))
        } else if err == err_enum_t_ERR_MEM as err_t {
            // trace!("netstack tcp err_mem on {}", &local_addr);
            self.callback_ctx.write_waker.register(cx.waker());
            Poll::Pending
        } else {
            // Operation errors do not free the PCB. Drop must still detach
            // callbacks and release it; only lwIP lifecycle callbacks mark it gone.
            Poll::Ready(Err(broken_pipe()))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let _guard = LWIP_MUTEX.lock();
        if self.callback_ctx.errored.load(Ordering::Acquire) {
            return Poll::Ready(Err(broken_pipe()));
        }
        if self.callback_ctx.pcb_gone.load(Ordering::Acquire) {
            // Gracefully closed: everything (including our FIN) has been sent
            // and acknowledged, so there is nothing left to flush.
            return Poll::Ready(Ok(()));
        }
        let err = unsafe { tcp_output(self.pcb as *mut tcp_pcb) };
        if err == err_enum_t_ERR_OK as err_t {
            Poll::Ready(Ok(()))
        } else if err == err_enum_t_ERR_MEM as err_t {
            // Transient: lwIP couldn't build/send segments right now. Park until
            // the sent/poll callback signals progress and retry, rather than
            // reporting a spurious flush failure that would reset the connection.
            self.callback_ctx.write_waker.register(cx.waker());
            Poll::Pending
        } else {
            Poll::Ready(Err(broken_pipe()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let _guard = LWIP_MUTEX.lock();
        if self.callback_ctx.errored.load(Ordering::Acquire) {
            return Poll::Ready(Err(broken_pipe()));
        }
        // Idempotent: already shut down (or the close handshake has since
        // completed and the pcb is gone) — nothing more to do.
        if self.callback_ctx.tx_closed.load(Ordering::Acquire)
            || self.callback_ctx.pcb_gone.load(Ordering::Acquire)
        {
            return Poll::Ready(Ok(()));
        }
        trace!("netstack tcp shutdown {}", &self.callback_ctx.local_addr);
        let err = unsafe { tcp_shutdown(self.pcb as *mut tcp_pcb, 0, 1) };
        if err == err_enum_t_ERR_MEM as err_t {
            self.callback_ctx.write_waker.register(cx.waker());
            Poll::Pending
        } else if err != err_enum_t_ERR_OK as err_t {
            Poll::Ready(Err(broken_pipe()))
        } else {
            self.callback_ctx.tx_closed.store(true, Ordering::Release);
            Poll::Ready(Ok(()))
        }
    }
}
