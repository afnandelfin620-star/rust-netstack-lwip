use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;

use futures::task::AtomicWaker;
use tokio::sync::mpsc::UnboundedSender;

/// State shared between a `TcpStream` and the lwIP C callbacks registered on its
/// pcb.
///
/// Every field is individually thread-safe, so this struct is `Sync` with no
/// `unsafe` and no surrounding lock: the callbacks reach it through a shared
/// `&TcpStreamContext` (from `tcp_arg`), never a `&mut`, so it can never alias
/// the `&mut TcpStream` held by the async side.
///
/// `LWIP_MUTEX` still serializes the lwIP calls themselves, but the correctness
/// of this struct no longer depends on that discipline.
pub struct TcpStreamContext {
    /// Peer address, kept only for logging.
    pub local_addr: SocketAddr,
    /// Carries received pbuf ownership — and a zero-pointer sentinel on EOF/error — to
    /// `TcpStream::poll_read`. `send` needs only `&self`.
    pub read_tx: UnboundedSender<usize>,
    /// The connection failed (reset/aborted). Reported to the user as an
    /// error. Implies `pcb_gone`.
    pub errored: AtomicBool,
    /// The pcb must no longer be touched: lwIP freed it (error callback, or
    /// the close handshake completing via `ERR_CLSD`), or it entered
    /// TIME_WAIT — from which lwIP reclaims it silently, with no callback.
    /// The lwIP callbacks are detached by whoever sets this. Only written
    /// while `LWIP_MUTEX` is held; decisions to call into lwIP based on it
    /// must read it under the same lock.
    pub pcb_gone: AtomicBool,
    /// The TX side has been shut down (our FIN sent) via `poll_shutdown`.
    /// Only written while `LWIP_MUTEX` is held.
    pub tx_closed: AtomicBool,
    /// Registered by `poll_write`, woken by the sent/poll/err callbacks.
    pub write_waker: AtomicWaker,
}

impl TcpStreamContext {
    pub fn new(local_addr: SocketAddr, read_tx: UnboundedSender<usize>) -> Self {
        TcpStreamContext {
            local_addr,
            read_tx,
            errored: AtomicBool::new(false),
            pcb_gone: AtomicBool::new(false),
            tx_closed: AtomicBool::new(false),
            write_waker: AtomicWaker::new(),
        }
    }
}
