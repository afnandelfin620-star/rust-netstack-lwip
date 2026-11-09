use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::mpsc::Sender;

use super::lwip::*;

/// Pointer (as usize) to the heap-allocated `OutputTarget` used by the lwIP output callback; 0 when no `NetStack` is alive. All accesses happen
/// under LWIP_MUTEX; the atomic just avoids `static mut`.
pub static OUTPUT_CB_PTR: AtomicUsize = AtomicUsize::new(0);

/// Counts output attempts dropped specifically because the nonblocking TUN is busy.
/// Bytes include the complete IP packet, and retransmitted attempts count again.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirectOutputStats {
    pub would_block_packets: u64,
    pub would_block_bytes: u64,
    /// Dropped because the kernel could not allocate the packet buffer
    /// (ENOBUFS/ENOMEM, e.g. under memory pressure). TCP retransmits them.
    pub no_buffer_packets: u64,
    pub no_buffer_bytes: u64,
}

/// Kernel packet-buffer exhaustion on a TUN write. Transient, like WouldBlock:
/// failing the whole TUN pipeline for it would tear down the VPN.
fn is_no_buffer(e: &std::io::Error) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const ENOBUFS: i32 = 105;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const ENOBUFS: i32 = 55;
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "ios")))]
    const ENOBUFS: i32 = i32::MIN;
    e.kind() == std::io::ErrorKind::OutOfMemory || e.raw_os_error() == Some(ENOBUFS)
}

/// Fatal output error: kind plus the raw OS error, if any, for diagnosis.
pub(crate) type OutputError = Option<(std::io::ErrorKind, Option<i32>)>;

pub fn direct_output_stats() -> DirectOutputStats {
    let _lock = crate::LWIP_MUTEX.lock();
    let ptr = OUTPUT_CB_PTR.load(Ordering::Acquire);
    if ptr == 0 { return DirectOutputStats::default(); }
    unsafe {
        match &*(ptr as *const OutputTarget) {
            OutputTarget::Direct { stats, .. } => *stats,
            _ => DirectOutputStats::default(),
        }
    }
}

pub(crate) type PacketWriter = dyn Fn(&[std::io::IoSlice<'_>]) -> std::io::Result<usize> + Send + Sync;
pub(crate) enum OutputTarget {
    Channel(Sender<Vec<u8>>), // Compatibility for in-process peers/tests, not Android TUN.
    Direct { writer: Box<PacketWriter>, errors: tokio::sync::watch::Sender<OutputError>, failed: bool, stats: DirectOutputStats },
    Disabled,
}

fn output(_netif: *mut netif, p: *mut pbuf) -> err_t {
    unsafe {
        let ptr = OUTPUT_CB_PTR.load(Ordering::Acquire);
        if ptr == 0 { return err_enum_t_ERR_ABRT as err_t; }
        // All accesses and destruction are serialized by LWIP_MUTEX. The packet
        // is borrowed only during this synchronous, nonblocking callback.
        let target = &mut *(ptr as *mut OutputTarget);
        match target {
            OutputTarget::Disabled => err_enum_t_ERR_IF as err_t,
            OutputTarget::Channel(tx) => {
                let len = std::ptr::read_unaligned(p).tot_len;
                let mut buf: Vec<u8> = Vec::with_capacity(len as usize);
                pbuf_copy_partial(p, buf.as_mut_ptr().cast(), len, 0);
                buf.set_len(len as usize);
                let _ = tx.try_send(buf);
                err_enum_t_ERR_OK as err_t
            }
            OutputTarget::Direct { writer, errors, failed, stats } => {
                if *failed { return err_enum_t_ERR_IF as err_t; }
                match write_packet(p, writer.as_ref()) {
                    Ok(()) => {
                        #[cfg(feature = "datapath-diagnostics")]
                        {
                            crate::output_batch::metrics::TUN_PACKETS.fetch_add(1, Ordering::Relaxed);
                            crate::output_batch::metrics::TUN_BYTES.fetch_add(std::ptr::read_unaligned(p).tot_len as u64, Ordering::Relaxed);
                        }
                        err_enum_t_ERR_OK as err_t
                    },
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // Already under LWIP_MUTEX: no extra atomics/locks or logs per packet.
                        stats.would_block_packets = stats.would_block_packets.saturating_add(1);
                        stats.would_block_bytes = stats.would_block_bytes.saturating_add(std::ptr::read_unaligned(p).tot_len as u64);
                        // Deliberate drop: TCP retains data for retransmission; UDP does not.
                        err_enum_t_ERR_OK as err_t
                    }
                    Err(e) if is_no_buffer(&e) => {
                        stats.no_buffer_packets = stats.no_buffer_packets.saturating_add(1);
                        stats.no_buffer_bytes = stats.no_buffer_bytes.saturating_add(std::ptr::read_unaligned(p).tot_len as u64);
                        // Rare by nature: log at 1, 2, 4, 8, ... occurrences only.
                        if stats.no_buffer_packets.is_power_of_two() {
                            log::warn!("TUN write dropped, kernel out of buffers ({} so far): {}", stats.no_buffer_packets, e);
                        }
                        // Same deliberate drop as WouldBlock.
                        err_enum_t_ERR_OK as err_t
                    }
                    Err(e) => {
                        *failed = true;
                        errors.send_replace(Some((e.kind(), e.raw_os_error())));
                        err_enum_t_ERR_IF as err_t
                    }
                }
            }
        }
    }
}

unsafe fn write_packet(p: *mut pbuf, writer: &PacketWriter) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind, IoSlice};
    let head = std::ptr::read_unaligned(p);
    let length = head.tot_len as usize;
    if head.next.is_null() && head.len as usize == length {
        let data = std::slice::from_raw_parts(head.payload.cast::<u8>(), length);
        return write_slices(&[IoSlice::new(data)], length, writer);
    }
    let mut inline: [IoSlice<'_>; 64] = std::array::from_fn(|_| IoSlice::new(&[]));
    // Only unusually fragmented chains allocate descriptors, never payload bytes.
    let mut overflow = Vec::new();
    let mut count = 0;
    let mut remaining = length;
    let mut node = p;
    while remaining > 0 && !node.is_null() {
        let part = std::ptr::read_unaligned(node);
        let len = remaining.min(part.len as usize);
        if len > 0 {
            let slice = IoSlice::new(std::slice::from_raw_parts(part.payload.cast::<u8>(), len));
            if count < inline.len() { inline[count] = slice; }
            else {
                if overflow.is_empty() { overflow.extend_from_slice(&inline); }
                overflow.push(slice);
            }
            count += 1;
            remaining -= len;
        }
        node = part.next;
    }
    if remaining != 0 { return Err(Error::new(ErrorKind::InvalidData, "short pbuf chain")); }
    let slices = if count <= inline.len() { &inline[..count] } else { &overflow[..] };
    write_slices(slices, length, writer)
}

fn write_slices(slices: &[std::io::IoSlice<'_>], length: usize, writer: &PacketWriter) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    loop {
        match writer(slices) {
            Ok(n) if n == length => return Ok(()),
            Ok(_) => return Err(Error::new(ErrorKind::WriteZero, "partial TUN packet write")),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

#[allow(unused_variables)]
pub extern "C" fn output_ip4(netif: *mut netif, p: *mut pbuf, ipaddr: *const ip4_addr_t) -> err_t {
    output(netif, p)
}

#[allow(unused_variables)]
#[allow(unused)]
pub extern "C" fn output_ip6(netif: *mut netif, p: *mut pbuf, ipaddr: *const ip6_addr_t) -> err_t {
    output(netif, p)
}

#[cfg(test)]
pub(crate) async fn verify_direct_output(stack: &crate::NetStack) {
    use std::{io, sync::{Arc, atomic::{AtomicUsize, Ordering}}};
    for (mode, node_count) in [(0, 1), (0, 70), (1, 70), (2, 70), (3, 70), (4, 70), (5, 70), (6, 70)] {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let address = Arc::new(AtomicUsize::new(0));
        let expected_address = address.clone();
        let mut registration = stack.direct_output(move |parts| {
            let call = count.fetch_add(1, Ordering::Relaxed);
            let len: usize = parts.iter().map(|p| p.len()).sum();
            assert_eq!(len, node_count);
            assert_eq!(parts[0].as_ptr() as usize, expected_address.load(Ordering::Relaxed));
            assert_eq!(parts.len(), node_count); // descriptor overflow path, still one packet
            for p in parts { assert_eq!(&p[..], b"x"); }
            match mode {
                1 => Err(io::ErrorKind::WouldBlock.into()),
                2 if call == 0 => Err(io::ErrorKind::Interrupted.into()),
                3 => Ok(len - 1),
                4 => Err(io::ErrorKind::BrokenPipe.into()),
                5 => Err(io::ErrorKind::OutOfMemory.into()),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                6 => Err(io::Error::from_raw_os_error(105)), // ENOBUFS
                #[cfg(not(any(target_os = "linux", target_os = "android")))]
                6 => Err(io::ErrorKind::OutOfMemory.into()),
                _ => Ok(len),
            }
        }).unwrap();
        assert!(stack.direct_output(|_| Ok(0)).is_err());
        assert_eq!(direct_output_stats(), DirectOutputStats::default());
        {
            let _lock = crate::LWIP_MUTEX.lock();
            unsafe {
                let root = pbuf_alloc(pbuf_layer_PBUF_RAW, 1, pbuf_type_PBUF_RAM);
                pbuf_take(root, b"x".as_ptr().cast(), 1);
                for _ in 1..node_count {
                    let p = pbuf_alloc(pbuf_layer_PBUF_RAW, 1, pbuf_type_PBUF_RAM);
                    pbuf_take(p, b"x".as_ptr().cast(), 1);
                    pbuf_cat(root, p);
                }
                address.store(std::ptr::addr_of!((*root).payload).read_unaligned() as usize, Ordering::Relaxed);
                let result = output(std::ptr::null_mut(), root);
                assert_eq!(result, if mode == 3 || mode == 4 { err_enum_t_ERR_IF as err_t } else { err_enum_t_ERR_OK as err_t });
                assert_eq!(std::ptr::read_unaligned(root).tot_len as usize, node_count);
                pbuf_free(root); // callback never takes ownership
            }
        }
        let stats = direct_output_stats();
        assert_eq!(stats.would_block_packets, if mode == 1 { 1 } else { 0 });
        assert_eq!(stats.would_block_bytes, if mode == 1 { node_count as u64 } else { 0 });
        assert_eq!(stats.no_buffer_packets, if mode >= 5 { 1 } else { 0 });
        assert_eq!(stats.no_buffer_bytes, if mode >= 5 { node_count as u64 } else { 0 });
        assert_eq!(calls.load(Ordering::Relaxed), if mode == 2 { 2 } else { 1 });
        if mode == 3 || mode == 4 {
            let e = registration.wait_error().await;
            assert_eq!(e.kind(), if mode == 3 { io::ErrorKind::WriteZero } else { io::ErrorKind::BrokenPipe });
        }
        drop(registration);
        // Registration teardown disables output; it must not fall back to copying.
        let _lock = crate::LWIP_MUTEX.lock();
        assert_eq!(output(std::ptr::null_mut(), std::ptr::null_mut()), err_enum_t_ERR_IF as err_t);
    }
}
