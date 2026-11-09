//! Tests and micro-benchmark for the fused checksum in `lwip/custom/l5_chksum.c`.
//!
//! `lwip_standard_chksum` (lwIP algorithm 3) is still compiled and is used as
//! the reference implementation.

use std::os::raw::{c_int, c_void};

extern "C" {
    fn lwip_standard_chksum(dataptr: *const c_void, len: c_int) -> u16;
    fn l5_chksum(dataptr: *const c_void, len: c_int) -> u16;
    fn l5_chksum_copy(dst: *mut c_void, src: *const c_void, len: u16) -> u16;
}

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn reference(data: &[u8]) -> u16 {
    unsafe { lwip_standard_chksum(data.as_ptr().cast(), data.len() as c_int) }
}

fn check(src_buf: &[u8], src_off: usize, dst_off: usize, len: usize) {
    let src = &src_buf[src_off..src_off + len];
    let want = reference(src);
    let got = unsafe { l5_chksum(src.as_ptr().cast(), len as c_int) };
    assert_eq!(got, want, "l5_chksum len={len} src_off={src_off}");

    let mut dst_buf = vec![0xA5u8; len + 16];
    let got = unsafe {
        l5_chksum_copy(dst_buf[dst_off..].as_mut_ptr().cast(), src.as_ptr().cast(), len as u16)
    };
    assert_eq!(got, want, "l5_chksum_copy len={len} src_off={src_off} dst_off={dst_off}");
    assert_eq!(&dst_buf[dst_off..dst_off + len], src, "copy content len={len}");
    assert!(dst_buf[..dst_off].iter().all(|&b| b == 0xA5), "wrote before dst");
    assert!(dst_buf[dst_off + len..].iter().all(|&b| b == 0xA5), "wrote past dst end");
}

#[test]
fn matches_reference_small_lengths_all_alignments() {
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    let buf: Vec<u8> = (0..1024).map(|_| rng.next() as u8).collect();
    for len in 0..=300 {
        for src_off in 0..8 {
            for dst_off in 0..8 {
                check(&buf, src_off, dst_off, len);
            }
        }
    }
}

#[test]
fn matches_reference_random_and_large_lengths() {
    let mut rng = XorShift(0xDEAD_BEEF_CAFE_F00D);
    let buf: Vec<u8> = (0..65535 + 16).map(|_| rng.next() as u8).collect();
    for len in [511, 512, 513, 1460, 1500, 8191, 16384, 65534, 65535] {
        for off in 0..8 {
            check(&buf, off, (off * 3) % 8, len);
        }
    }
    for _ in 0..500 {
        let len = (rng.next() % 65536) as usize;
        let src_off = (rng.next() % 8) as usize;
        let dst_off = (rng.next() % 8) as usize;
        check(&buf, src_off, dst_off, len);
    }
}

#[test]
fn edge_values() {
    // All zeros -> 0; all 0xFF -> 0xFFFF (same as reference), worst-case carries.
    for len in [1usize, 2, 3, 63, 64, 65, 65535] {
        let zeros = vec![0u8; len + 8];
        let ones = vec![0xFFu8; len + 8];
        for off in 0..8 {
            check(&zeros, off, off, len);
            check(&ones, off, 7 - off, len);
        }
    }
}

/// `cargo test --release chksum_bench -- --ignored --nocapture`
#[test]
#[ignore]
fn chksum_bench() {
    use std::time::Instant;
    let len = 8191usize; // TCP_MSS: the size lwIP copies per segment
    let src: Vec<u8> = (0..len).map(|i| (i * 31) as u8).collect();
    let mut dst = vec![0u8; len];
    let iters = 400_000usize;
    let gb = (len * iters) as f64 / 1e9;

    let t = Instant::now();
    let mut acc = 0u32;
    for _ in 0..iters {
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), len);
            acc = acc.wrapping_add(lwip_standard_chksum(dst.as_ptr().cast(), len as c_int) as u32);
        }
        std::hint::black_box(&mut dst);
    }
    let old = t.elapsed().as_secs_f64();

    let t = Instant::now();
    for _ in 0..iters {
        unsafe {
            acc = acc.wrapping_add(l5_chksum_copy(dst.as_mut_ptr().cast(), src.as_ptr().cast(), len as u16) as u32);
        }
        std::hint::black_box(&mut dst);
    }
    let new = t.elapsed().as_secs_f64();
    println!(
        "memcpy+alg3: {:.2} GB/s   l5_chksum_copy: {:.2} GB/s   speedup {:.2}x  (acc {acc})",
        gb / old, gb / new, old / new
    );
}

