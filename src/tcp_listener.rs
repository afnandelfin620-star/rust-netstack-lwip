use std::marker::PhantomPinned;
use std::ptr::null_mut;
use std::sync::Arc;
use std::{net::SocketAddr, os::raw, pin::Pin};

use futures::stream::Stream;
use futures::task::{Context, Poll};
use log::*;
use tokio::sync::mpsc::{UnboundedSender, UnboundedReceiver, unbounded_channel};

use super::lwip::*;
use super::stack::StackHandle;
use super::tcp_stream::TcpStream;
use super::LWIP_MUTEX;
use crate::Error;

/// State shared between a `TcpListener` and its lwIP accept callback.
///
/// Lives in its own heap allocation (owned by `TcpListener` as a raw pointer)
/// so the callback reaches it through a shared `&TcpListenerContext` and never
/// forms a reference into `TcpListener`, which would alias the `&mut` taken in
/// `poll_next`. `UnboundedSender` is `Sync` and `send` needs only `&self`.
struct TcpListenerContext {
    sender: UnboundedSender<Pin<Box<TcpStream>>>,
    // Cloned into each accepted `TcpStream` so a live connection keeps the
    // whole stack alive even if the listener/netstack are dropped first.
    stack: Arc<StackHandle>,
}

#[allow(unused_variables)]
pub extern "C" fn tcp_accept_cb(arg: *mut raw::c_void, newpcb: *mut tcp_pcb, err: err_t) -> err_t {
    if arg.is_null() {
        warn!("tcp listener has been closed");
        return err_enum_t_ERR_CONN as err_t;
    }
    if newpcb.is_null() {
        warn!("tcp full");
        return err_enum_t_ERR_OK as err_t;
    }
    if err != err_enum_t_ERR_OK as err_t {
        warn!("accept tcp failed: {}", err);
        // Not sure what to do if there was an error, just ignore it.
        return err_enum_t_ERR_OK as err_t;
    }
    // SAFETY: `arg` points to the `TcpListenerContext`, a separate heap
    // allocation reached only by shared reference, so it can never alias the
    // `&mut TcpListener` in `poll_next`. `TcpListener::drop` unregisters this
    // callback under LWIP_MUTEX before freeing the context.
    let ctx = unsafe { &*(arg as *const TcpListenerContext) };
    let stream = TcpStream::new(newpcb, ctx.stack.clone());
    let _ = ctx.sender.send(stream);
    err_enum_t_ERR_OK as err_t
}

pub struct TcpListener {
    tpcb: usize,
    // Raw pointer (as usize) to the heap-allocated `TcpListenerContext` used by
    // the accept callback; owned here and freed on drop.
    ctx: usize,
    receiver: UnboundedReceiver<Pin<Box<TcpStream>>>,
    _pin: PhantomPinned,
}

impl TcpListener {
    pub(crate) fn new(stack: Arc<StackHandle>) -> Result<Pin<Box<Self>>, Error> {
        unsafe {
            let _g = LWIP_MUTEX.lock();
            let tpcb = tcp_new();
            if tpcb.is_null() { return Err(Error::LwIP(err_enum_t_ERR_MEM as err_t)); }
            let err = tcp_bind(tpcb, &ip_addr_any_type, 0);
            if err != err_enum_t_ERR_OK as err_t {
                error!("bind TCP failed: {}", err);
                tcp_abort(tpcb);
                return Err(Error::LwIP(err));
            }
            let mut reason: err_t = 0;
            let listening = tcp_listen_with_backlog_and_err(
                tpcb,
                TCP_DEFAULT_LISTEN_BACKLOG as u8,
                &mut reason,
            );
            if listening.is_null() {
                error!("listen TCP failed: {}", reason);
                // Failed listen leaves the original CLOSED PCB owned by the caller.
                tcp_abort(tpcb);
                return Err(Error::LwIP(reason));
            }
            let tpcb = listening; // Successful listen consumed the original PCB.
            let (sender, receiver) = unbounded_channel();
            let ctx = Box::into_raw(Box::new(TcpListenerContext { sender, stack })) as usize;
            let listener = Box::pin(TcpListener {
                tpcb: tpcb as usize,
                ctx,
                receiver,
                _pin: PhantomPinned::default(),
            });
            tcp_arg(tpcb, ctx as *mut raw::c_void);
            tcp_accept(tpcb, Some(tcp_accept_cb));
            Ok(listener)
        }
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        {
            let _g = LWIP_MUTEX.lock();
            unsafe {
                tcp_arg(self.tpcb as *mut tcp_pcb, null_mut());
                tcp_accept(self.tpcb as *mut tcp_pcb, None);
                tcp_close(self.tpcb as *mut tcp_pcb);
            }
        }
        // Free the callback context (and drop its `Arc<StackHandle>`) only after
        // releasing LWIP_MUTEX: if this is the last handle, `StackHandle::drop`
        // re-takes the same non-reentrant lock.
        unsafe { drop(Box::from_raw(self.ctx as *mut TcpListenerContext)) };
    }
}

impl Stream for TcpListener {
    type Item = (Pin<Box<TcpStream>>, SocketAddr, SocketAddr);

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let me = unsafe { self.get_unchecked_mut() };
        match me.receiver.poll_recv(cx) {
            Poll::Ready(Some(stream)) => {
                let local_addr = stream.local_addr().to_owned();
                let remote_addr = stream.remote_addr().to_owned();
                return Poll::Ready(Some((stream, local_addr, remote_addr)));
            },
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
