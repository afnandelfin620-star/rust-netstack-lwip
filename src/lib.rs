mod lwip;
mod mutex;
mod output;
mod stack;
mod tcp_listener;
mod tcp_stream;
mod tcp_stream_context;
pub mod udp;
mod util;

pub(crate) static LWIP_MUTEX: mutex::LwipMutex = mutex::LwipMutex::new();

pub use stack::{NetStack, StackInput, StackStream};
pub use tcp_listener::TcpListener;
pub use tcp_stream::TcpStream;
pub use udp::UdpSocket;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("LwIP error ({0})")]
    LwIP(i8),
    #[error("a NetStack instance is already running")]
    AlreadyRunning,
}

#[cfg(feature = "timer-diagnostics")]
pub mod timer_diagnostics;

/// Reserved ahead of TUN packets for the largest L5 UDP address header (279B).
pub const TUN_HEADROOM: usize = 320;

// Caller owns the pbuf; mutation and the refcount check are serialized with lwIP.
pub(crate) unsafe fn prepend_owned_pbuf(raw: usize, header: &[u8]) -> bool {
    let _lock = LWIP_MUTEX.lock();
    let p = raw as *mut lwip::pbuf;
    let value = std::ptr::read_unaligned(p);
    if !value.next.is_null() || value.ref_ != 1 { return false; }
    if lwip::pbuf_add_header(p, header.len() as _) != 0 { return false; }
    let payload = std::ptr::addr_of!((*p).payload).read_unaligned();
    std::ptr::copy_nonoverlapping(header.as_ptr(), payload.cast::<u8>(), header.len());
    true
}
