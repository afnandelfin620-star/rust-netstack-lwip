use std::{io, net::SocketAddr, os::raw, pin::Pin};
use std::marker::PhantomPinned;
use std::sync::Arc;

use futures::stream::Stream;
use futures::task::{Context, Poll};
use futures::StreamExt;
use log::{error, warn};
use tokio::sync::mpsc::{channel, Receiver, Sender};

use super::lwip::*;
use super::stack::StackHandle;
use super::util;
use crate::Error;

pub unsafe extern "C" fn udp_recv_cb(
    arg: *mut raw::c_void,
    _pcb: *mut udp_pcb,
    p: *mut pbuf,
    addr: *const ip_addr_t,
    port: u16_t,
    dst_addr: *const ip_addr_t,
    dst_port: u16_t,
) {
    if arg.is_null() {
        if !p.is_null() { pbuf_free(p); }
        warn!("udp socket has been closed");
        return;
    }
    // SAFETY: `arg` points to the `UdpSocketContext` of a still-alive
    // `UdpSocket`. The context is a separate heap allocation (not a field
    // reached by `poll_next`'s `&mut`), so this shared reference can never alias
    // that `&mut`, and only shared references are ever formed to it. `Sender` is
    // `Sync`, so `try_send` needs no lock. `UdpSocket::drop` unregisters this
    // callback under `LWIP_MUTEX` before freeing the context, so it is valid.
    let ctx = &*(arg as *const UdpSocketContext);
    let src_addr = util::to_socket_addr(&*addr, port);
    let dst_addr = util::to_socket_addr(&*dst_addr, dst_port);
    if p.is_null() { return; }
    if ctx.tx.try_send((p as usize, src_addr, dst_addr)).is_err() {
        pbuf_free(p);
        log::trace!("netstack udp recv channel full, dropping inbound datagram");
    }
    // No manual waker: `poll_next`'s `rx.poll_recv` registers the task's waker
    // and the channel wakes it when this `try_send` succeeds.
}

fn send_udp(
    src_addr: &SocketAddr,
    dst_addr: &SocketAddr,
    pcb: usize,
    data: &[u8],
) -> io::Result<()> {
    unsafe {
        let _g = super::LWIP_MUTEX.lock();
        let pbuf =
            pbuf_alloc_reference(data.as_ptr() as *mut _, data.len() as _, pbuf_type_PBUF_REF);
        if pbuf.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "pbuf_alloc_reference failed",
            ));
        }
        let src_ip = util::to_ip_addr_t(src_addr.ip());
        let dst_ip = util::to_ip_addr_t(dst_addr.ip());
        let err = udp_sendto(
            pcb as *mut udp_pcb,
            pbuf,
            &dst_ip as *const _,
            dst_addr.port(),
            &src_ip as *const _,
            src_addr.port(),
        );
        pbuf_free(pbuf);
        if err != err_enum_t_ERR_OK as err_t {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("udp_sendto error: {}", err),
            ));
        }
        Ok(())
    }
}

type RawUdpPkt = (usize, SocketAddr, SocketAddr);
pub type UdpPkt = (UdpPayload, SocketAddr, SocketAddr);

/// Immutable datagram ownership. Payload stays in lwIP until its final owner drops.
#[derive(Clone)]
pub struct UdpPayload(PayloadStorage);
#[derive(Clone)]
enum PayloadStorage { Bytes(bytes::Bytes), Pbuf(Arc<DatagramPbuf>) }
struct DatagramPbuf {
    raw: usize,
    len: usize,
    _stack: Arc<StackHandle>,
    // Only parsers requiring contiguous input flatten a chained datagram.
    flat: std::sync::OnceLock<Vec<u8>>,
}
impl Drop for DatagramPbuf {
    fn drop(&mut self) {
        let _lock = super::LWIP_MUTEX.lock();
        unsafe { pbuf_free(self.raw as *mut pbuf); }
    }
}
impl From<Vec<u8>> for UdpPayload {
    fn from(data: Vec<u8>) -> Self { Self(PayloadStorage::Bytes(data.into())) }
}
impl UdpPayload {
    /// Consumes ownership and prepends an application header in-place when safe.
    /// Shared/chained/external pbufs fall back to a single final message allocation.
    pub fn into_frame(mut self, header: &[u8]) -> bytes::Bytes {
        if let PayloadStorage::Pbuf(owner) = &mut self.0 {
            if let Some(p) = Arc::get_mut(owner) {
                if unsafe { crate::prepend_owned_pbuf(p.raw, header) } {
                    p.len += header.len();
                    p.flat.take();
                    return bytes::Bytes::from_owner(self);
                }
            }
        }
        let mut result = bytes::BytesMut::with_capacity(header.len() + self.len());
        result.extend_from_slice(header);
        for part in self.slices() { result.extend_from_slice(part); }
        result.freeze()
    }
    pub fn len(&self) -> usize {
        match &self.0 { PayloadStorage::Bytes(b) => b.len(), PayloadStorage::Pbuf(p) => p.len }
    }
    pub fn is_empty(&self) -> bool { self.len() == 0 }
    pub fn slices(&self) -> impl Iterator<Item = &[u8]> {
        let (mut node, mut bytes) = match &self.0 {
            PayloadStorage::Bytes(b) => (0, Some(b.as_ref())),
            PayloadStorage::Pbuf(p) => (p.raw, None),
        };
        std::iter::from_fn(move || {
            if let Some(b) = bytes.take() { return Some(b); }
            if node == 0 { return None; }
            let part = unsafe { std::ptr::read_unaligned(node as *const pbuf) };
            node = part.next as usize;
            Some(unsafe { std::slice::from_raw_parts(part.payload as *const u8, part.len as usize) })
        })
    }
}
impl std::ops::Deref for UdpPayload {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match &self.0 {
            PayloadStorage::Bytes(b) => b,
            PayloadStorage::Pbuf(p) => {
                let first = unsafe { std::ptr::read_unaligned(p.raw as *const pbuf) };
                if first.next.is_null() {
                    return unsafe { std::slice::from_raw_parts(first.payload as *const u8, first.len as usize) };
                }
                p.flat.get_or_init(|| {
                    let mut data = Vec::with_capacity(p.len);
                    for part in self.slices() { data.extend_from_slice(part); }
                    data
                })
            }
        }
    }
}


/// State shared between a `UdpSocket` and the lwIP `udp_recv` callback.
///
/// Lives in its own heap allocation (owned by `UdpSocket` as a raw pointer) so
/// the callback reaches it through a shared `&UdpSocketContext` and never forms
/// a reference into `UdpSocket` itself, which would alias the `&mut` taken in
/// `poll_next`. `Sender` is `Sync`, so the callback needs no surrounding lock.
struct UdpSocketContext {
    tx: Sender<RawUdpPkt>,
}

/// Shared ownership of the underlying lwIP `udp_pcb`.
///
/// The pcb is removed only when the last handle (the `UdpSocket`/`RecvHalf`
/// and every `SendHalf` obtained from `split`) is dropped, so a `SendHalf`
/// can never outlive the pcb it sends on.
struct UdpPcb(usize);

impl Drop for UdpPcb {
    fn drop(&mut self) {
        let _g = super::LWIP_MUTEX.lock();
        unsafe { udp_remove(self.0 as *mut udp_pcb) };
    }
}

pub struct UdpSocket {
    pcb: Arc<UdpPcb>,
    // Raw pointer (kept as usize so `UdpSocket` stays `Send`) to the
    // heap-allocated `UdpSocketContext` used only by the lwIP recv callback.
    // Owned here and freed on drop. Kept separate from `rx` so the callback
    // never forms a reference into `UdpSocket`, which would alias the `&mut`
    // taken in `poll_next`.
    ctx: usize,
    rx: Receiver<RawUdpPkt>,
    // Keeps the shared lwIP stack alive for as long as this socket exists.
    _stack: Arc<StackHandle>,
    _pin: PhantomPinned
}

impl UdpSocket {
    pub(crate) fn new(buffer_size: usize, stack: Arc<StackHandle>) -> Result<Pin<Box<Self>>, Error> {
        unsafe {
            // lwIP is compiled with NO_SYS=1 (no internal locking), so every
            // call into it must be serialized by LWIP_MUTEX. The background
            // `sys_check_timeouts` task spawned in `NetStack::_new` may already
            // be running by the time this is called.
            let _g = super::LWIP_MUTEX.lock();
            let pcb = udp_new();
            // Bind before building the socket so a failure doesn't drop a
            // half-initialised `UdpSocket` (whose `Drop` would re-take this
            // non-reentrant lock and deadlock).
            let err = udp_bind(pcb, &ip_addr_any_type, 0);
            if err != err_enum_t_ERR_OK as err_t {
                error!("bind UDP failed: {}", err);
                udp_remove(pcb);
                return Err(Error::LwIP(err));
            }
            let (tx, rx): (Sender<RawUdpPkt>, Receiver<RawUdpPkt>) = channel(buffer_size);
            let ctx = Box::into_raw(Box::new(UdpSocketContext { tx })) as usize;
            let socket = Box::pin(Self {
                pcb: Arc::new(UdpPcb(pcb as usize)),
                ctx,
                rx,
                _stack: stack,
                _pin: PhantomPinned::default()
            });
            udp_recv(pcb, Some(udp_recv_cb), ctx as *mut raw::c_void);
            Ok(socket)
        }
    }

    pub fn split(self: Pin<Box<Self>>) -> (SendHalf, RecvHalf) {
        let pcb = self.pcb.clone();
        let stack = self._stack.clone();
        (SendHalf { pcb, _stack: stack }, RecvHalf { socket: self })
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        // Unregister the callback so lwIP stops calling into `tx`/`waker`,
        // which are about to be freed. The pcb itself is removed by
        // `UdpPcb::drop` once the last shared handle (this + any `SendHalf`)
        // is gone. Release the lock before the fields (incl. the pcb `Arc`)
        // are dropped, since `UdpPcb::drop` takes the same non-reentrant lock.
        let _g = super::LWIP_MUTEX.lock();
        unsafe {
            udp_recv(self.pcb.0 as *mut udp_pcb, None, std::ptr::null_mut());
            self.rx.close();
            while let Ok((raw, _, _)) = self.rx.try_recv() { pbuf_free(raw as *mut pbuf); }
            // Reclaim the callback context. Safe under the lock: the callback
            // only runs while LWIP_MUTEX is held and has just been unregistered,
            // so it can no longer observe this pointer.
            drop(Box::from_raw(self.ctx as *mut UdpSocketContext));
        }
    }
}

impl Stream for UdpSocket {
    type Item = UdpPkt;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let this = unsafe { self.get_unchecked_mut() };
        // `poll_recv` registers `cx`'s waker; the recv callback's `try_send`
        // wakes it. No separate waker handling is needed.
        this.rx.poll_recv(cx).map(|packet| packet.map(|(raw, src, dst)| {
            let len = unsafe { std::ptr::read_unaligned(raw as *const pbuf).tot_len as usize };
            (UdpPayload(PayloadStorage::Pbuf(Arc::new(DatagramPbuf {
                raw, len, _stack: this._stack.clone(), flat: std::sync::OnceLock::new(),
            }))), src, dst)
        }))
    }
}

pub struct SendHalf {
    // Shared with the `RecvHalf`/`UdpSocket`; keeps the pcb alive for as long
    // as this half exists, so `send_to` can never hit a removed pcb.
    pcb: Arc<UdpPcb>,
    // Keeps the shared lwIP stack (timer + output callback) alive so `send_to`
    // still has a working output path even if the netstack is dropped first.
    _stack: Arc<StackHandle>,
}

impl SendHalf {
    pub fn send_to(
        &self,
        data: &[u8],
        src_addr: &SocketAddr,
        dst_addr: &SocketAddr,
    ) -> io::Result<()> {
        send_udp(src_addr, dst_addr, self.pcb.0, data)
    }
}

pub struct RecvHalf {
    pub(crate) socket: Pin<Box<UdpSocket>>,
}

impl RecvHalf {
    pub async fn recv_from(&mut self) -> io::Result<UdpPkt> {
        match self.socket.next().await {
            Some(pkt) => Ok(pkt),
            None => Err(io::Error::new(
                io::ErrorKind::Other,
                "recv_from udp socket failed: tx closed",
            )),
        }
    }
}

impl Stream for RecvHalf {
    type Item = UdpPkt;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.socket).poll_next(cx)
    }
}

#[cfg(test)]
pub(crate) async fn verify_owned_datagrams(stack: Arc<StackHandle>) {
    // Unique contiguous headroom must preserve the payload address. Shared,
    // chained and headroom-less buffers must not be mutated.
    for (reserve, shared, chained) in [(320, false, false), (320, true, false), (0, false, false), (320, false, true)] {
        let (payload, address) = {
            let _lock = super::LWIP_MUTEX.lock();
            unsafe {
                let p = pbuf_alloc(pbuf_layer_PBUF_RAW, reserve + 3, pbuf_type_PBUF_RAM);
                assert!(!p.is_null());
                assert_eq!(pbuf_remove_header(p, reserve as _), 0);
                let address = std::ptr::addr_of!((*p).payload).read_unaligned();
                pbuf_take(p, b"abc".as_ptr().cast(), 3);
                if chained {
                    let tail = pbuf_alloc(pbuf_layer_PBUF_RAW, 3, pbuf_type_PBUF_RAM);
                    pbuf_take(tail, b"def".as_ptr().cast(), 3);
                    pbuf_cat(p, tail);
                }
                (UdpPayload(PayloadStorage::Pbuf(Arc::new(DatagramPbuf {
                    raw: p as usize, len: if chained { 6 } else { 3 },
                    _stack: stack.clone(), flat: std::sync::OnceLock::new(),
                }))), address as usize)
            }
        };
        let retained = if shared { Some(payload.clone()) } else { None };
        let frame = payload.into_frame(b"HEAD");
        assert_eq!(&frame[..], if chained { b"HEADabcdef".as_slice() } else { b"HEADabc".as_slice() });
        if reserve > 0 && !shared && !chained {
            assert_eq!(frame[4..].as_ptr() as usize, address, "payload was copied");
        } else { assert_ne!(frame[4..].as_ptr() as usize, address); }
        if let Some(retained) = retained { assert_eq!(&*retained, b"abc"); }
        let clone = frame.clone();
        drop(frame);
        assert!(clone.starts_with(b"HEAD"));
    }

    for _ in 0..600 {
        let socket = UdpSocket::new(1, stack.clone()).unwrap();
        let (_, mut receiver) = socket.split();
        let original_payload;
        {
            let _lock = super::LWIP_MUTEX.lock();
            unsafe {
                let ip = util::to_ip_addr_t("127.0.0.1".parse().unwrap());
                let p = pbuf_alloc(pbuf_layer_PBUF_RAW, 16384, pbuf_type_PBUF_RAM);
                let q = pbuf_alloc(pbuf_layer_PBUF_RAW, 16384, pbuf_type_PBUF_RAM);
                assert!(!p.is_null() && !q.is_null());
                original_payload = std::ptr::addr_of!((*p).payload).read_unaligned();
                std::ptr::write_bytes(original_payload.cast::<u8>(), 0x41, 16384);
                std::ptr::write_bytes(std::ptr::addr_of!((*q).payload).read_unaligned().cast::<u8>(), 0x42, 16384);
                pbuf_cat(p, q);
                let ctx = receiver.socket.ctx as *mut raw::c_void;
                udp_recv_cb(ctx, std::ptr::null_mut(), p, &ip, 1000, &ip, 2000);
                // Full queue must release the rejected packet under the existing lock.
                let rejected = pbuf_alloc(pbuf_layer_PBUF_RAW, 32768, pbuf_type_PBUF_RAM);
                assert!(!rejected.is_null());
                udp_recv_cb(ctx, std::ptr::null_mut(), rejected, &ip, 1000, &ip, 2000);
            }
        }
        let (payload, src, dst) = receiver.recv_from().await.unwrap();
        assert_eq!(src.port(), 1000);
        assert_eq!(dst.port(), 2000);
        assert_eq!(payload.len(), 32768);
        assert_eq!(payload.slices().next().unwrap().as_ptr(), original_payload as *const u8);
        assert_eq!(payload.slices().count(), 2);
        drop(receiver);
        let copy = payload.clone();
        drop(payload);
        assert_eq!(copy.slices().next().unwrap()[0], 0x41);
        assert_eq!(copy.slices().nth(1).unwrap()[0], 0x42);
        // The parsing-only fallback must preserve both fragments.
        assert_eq!(copy[16384], 0x42);
    }
    // Closing without consuming the queued packet must also reclaim it.
    for _ in 0..600 {
        let socket = UdpSocket::new(1, stack.clone()).unwrap();
        {
            let _lock = super::LWIP_MUTEX.lock();
            unsafe {
                let ip = util::to_ip_addr_t("127.0.0.1".parse().unwrap());
                let p = pbuf_alloc(pbuf_layer_PBUF_RAW, 65528, pbuf_type_PBUF_RAM);
                assert!(!p.is_null());
                udp_recv_cb(socket.ctx as *mut raw::c_void, std::ptr::null_mut(), p, &ip, 1, &ip, 2);
            }
        }
        drop(socket);
    }
}

impl AsRef<[u8]> for UdpPayload {
    fn as_ref(&self) -> &[u8] { self }
}
