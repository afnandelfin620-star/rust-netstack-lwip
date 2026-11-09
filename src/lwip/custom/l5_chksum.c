/*
 * Fast Internet checksum for lwIP (LWIP_CHKSUM / LWIP_CHKSUM_COPY).
 *
 * lwIP's default LWIP_CHKSUM_COPY does MEMCPY and then a second, 32-bit,
 * branchy checksum pass over the destination. On the download path every TCP
 * payload byte goes through it, so it shows up as a top user-space hotspot.
 *
 * This version does copy + sum in ONE pass with wide loads:
 *   - aarch64: NEON, 64 bytes/iteration, vpadalq_u32 (u32 pairs -> u64 lanes)
 *   - others:  64-bit scalar loads, both 32-bit halves summed into u64
 *
 * Semantics match lwip_standard_chksum exactly: the returned value is the
 * folded (non-inverted) one's-complement sum of the buffer read as native-order
 * 16-bit words starting at the buffer's first byte, with an odd trailing byte
 * occupying the lowest-addressed byte of a zero-padded word. Any alignment is
 * accepted (unaligned access is done via memcpy / vld1q_u8).
 *
 * Summing 32-bit words into 64-bit accumulators is equivalent to summing
 * 16-bit words modulo 0xFFFF, so folding at the end yields the same value.
 * Each lane add is < 2^33, so accumulators cannot overflow for any len < 2^31.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>
#define L5_CHKSUM_NEON 1
#endif

static inline uint64_t l5_load64(const unsigned char *p) {
  uint64_t v;
  memcpy(&v, p, sizeof v);
  return v;
}

static inline uint16_t l5_fold(uint64_t s) {
  s = (s & 0xffffffffu) + (s >> 32);
  s = (s & 0xffffffffu) + (s >> 32);
  s = (s & 0xffffu) + (s >> 16);
  s = (s & 0xffffu) + (s >> 16);
  s = (s & 0xffffu) + (s >> 16);
  return (uint16_t)s;
}

/* Sums (and optionally copies) the < 8 byte tail. */
static inline uint64_t l5_tail(unsigned char *d, const unsigned char *s, size_t n) {
  uint64_t sum = 0;
  if (n >= 4) {
    uint32_t w;
    memcpy(&w, s, 4);
    if (d) { memcpy(d, &w, 4); d += 4; }
    sum += w;
    s += 4;
    n -= 4;
  }
  if (n >= 2) {
    uint16_t w;
    memcpy(&w, s, 2);
    if (d) { memcpy(d, &w, 2); d += 2; }
    sum += w;
    s += 2;
    n -= 2;
  }
  if (n) {
    uint16_t w = 0;
    memcpy(&w, s, 1); /* lowest-addressed byte of a zero-padded word */
    if (d) { *d = *s; }
    sum += w;
  }
  return sum;
}

/* d == NULL: checksum only. Otherwise copy src -> d while summing. */
static inline uint16_t l5_sum_copy(unsigned char *d, const unsigned char *s, size_t n) {
  uint64_t sum = 0;

#if L5_CHKSUM_NEON
  if (n >= 64) {
    uint64x2_t a0 = vdupq_n_u64(0), a1 = vdupq_n_u64(0);
    uint64x2_t a2 = vdupq_n_u64(0), a3 = vdupq_n_u64(0);
    do {
      uint8x16_t v0 = vld1q_u8(s);
      uint8x16_t v1 = vld1q_u8(s + 16);
      uint8x16_t v2 = vld1q_u8(s + 32);
      uint8x16_t v3 = vld1q_u8(s + 48);
      if (d) {
        vst1q_u8(d, v0);
        vst1q_u8(d + 16, v1);
        vst1q_u8(d + 32, v2);
        vst1q_u8(d + 48, v3);
        d += 64;
      }
      a0 = vpadalq_u32(a0, vreinterpretq_u32_u8(v0));
      a1 = vpadalq_u32(a1, vreinterpretq_u32_u8(v1));
      a2 = vpadalq_u32(a2, vreinterpretq_u32_u8(v2));
      a3 = vpadalq_u32(a3, vreinterpretq_u32_u8(v3));
      s += 64;
      n -= 64;
    } while (n >= 64);
    /* Each lane < 2^48 here (<= 2048 adds of < 2^33 for a 64 KiB buffer). */
    a0 = vaddq_u64(vaddq_u64(a0, a1), vaddq_u64(a2, a3));
    sum = l5_fold(vgetq_lane_u64(a0, 0)) + (uint64_t)l5_fold(vgetq_lane_u64(a0, 1));
  }
#endif

  {
    uint64_t b0 = 0, b1 = 0;
    while (n >= 16) {
      uint64_t w0 = l5_load64(s);
      uint64_t w1 = l5_load64(s + 8);
      if (d) {
        memcpy(d, &w0, 8);
        memcpy(d + 8, &w1, 8);
        d += 16;
      }
      b0 += (uint32_t)w0;
      b0 += w0 >> 32;
      b1 += (uint32_t)w1;
      b1 += w1 >> 32;
      s += 16;
      n -= 16;
    }
    if (n >= 8) {
      uint64_t w0 = l5_load64(s);
      if (d) { memcpy(d, &w0, 8); d += 8; }
      b0 += (uint32_t)w0;
      b0 += w0 >> 32;
      s += 8;
      n -= 8;
    }
    sum += l5_fold(b0) + (uint64_t)l5_fold(b1);
  }

  sum += l5_tail(d, s, n);
  return l5_fold(sum);
}

uint16_t l5_chksum(const void *dataptr, int len) {
  if (len <= 0) {
    return 0;
  }
  return l5_sum_copy(NULL, (const unsigned char *)dataptr, (size_t)len);
}

uint16_t l5_chksum_copy(void *dst, const void *src, uint16_t len) {
  return l5_sum_copy((unsigned char *)dst, (const unsigned char *)src, (size_t)len);
}

