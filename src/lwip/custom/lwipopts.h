/**
 * @file lwipopts.h
 * @author Ambroz Bizjak <ambrop7@gmail.com>
 *
 * @section LICENSE
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef LWIP_CUSTOM_LWIPOPTS_H
#define LWIP_CUSTOM_LWIPOPTS_H

// Match memory alignment to the target's pointer width. lwIP's default is 1,
// which is unsafe on 64-bit targets: structs placed in the `mem` heap would be
// under-aligned and accessed with alignment-assuming loads (UB, and on ARM a
// SIGBUS risk). Use the compiler's pointer size so every platform (Android,
// iOS, macOS, Linux) gets 8 on 64-bit and 4 on 32-bit.
#if defined(__SIZEOF_POINTER__) && __SIZEOF_POINTER__ >= 8
    #define MEM_ALIGNMENT 8
#else
    #define MEM_ALIGNMENT 4
#endif

// enable tun2socks logic
#define TUN2SOCKS 1

#define NO_SYS 1
#define LWIP_TIMERS 1

#define IP_DEFAULT_TTL 64
#define LWIP_ARP 0
#define ARP_QUEUEING 0
#define IP_FORWARD 0
#define LWIP_ICMP 0
#define LWIP_RAW 1
#define LWIP_DHCP 0
#define LWIP_AUTOIP 0
#define LWIP_SNMP 0
#define LWIP_IGMP 0
#define LWIP_DNS 0
#define LWIP_UDP 1
#define LWIP_UDPLITE 0
#define LWIP_TCP 1
#define LWIP_CALLBACK_API 1
#define LWIP_NETIF_API 0
#define LWIP_NETIF_LOOPBACK 0
#define LWIP_HAVE_LOOPIF 1
#define LWIP_HAVE_SLIPIF 0
#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define PPP_SUPPORT 0
#define LWIP_IPV6 1
#define LWIP_IPV6_MLD 0
#define LWIP_IPV6_AUTOCONFIG 1

#if defined __linux__
#include <endian.h>

// BYTE_ORDER by default is LITTLE_ENDIAN if undefined,
// detects only big endian here.
#if defined __BYTE_ORDER && defined __BIG_ENDIAN
#if _BYTE_ORDER == __BIG_ENDIAN
#define BYTE_ORDER BIG_ENDIAN
#endif
#endif
#endif

// disable checksum checks
#define CHECKSUM_CHECK_IP 0
#define CHECKSUM_CHECK_UDP 0
#define CHECKSUM_CHECK_TCP 0
#define CHECKSUM_CHECK_ICMP 0
#define CHECKSUM_CHECK_ICMP6 0

#define LWIP_CHECKSUM_ON_COPY 1
// Algorithm 3 is still compiled (as lwip_standard_chksum) and serves as the
// reference implementation in the l5_chksum unit tests.
#define LWIP_CHKSUM_ALGORITHM 3

// Single-pass, wide (NEON on arm64) checksum and fused copy+checksum; see
// custom/l5_chksum.c. Replaces MEMCPY followed by a second checksum pass.
#include <stdint.h>
uint16_t l5_chksum(const void *dataptr, int len);
uint16_t l5_chksum_copy(void *dst, const void *src, uint16_t len);
#define LWIP_CHKSUM l5_chksum
#define LWIP_CHKSUM_COPY(dst, src, len) l5_chksum_copy(dst, src, len)

// TCP_MSS is set per platform below (see the note at the defaults).

// TIME_WAIT lasts 2*TCP_MSL. The default MSL (60s) makes closed connections
// linger 120s, holding a tcp_pcb each; under connection churn (a VPN carries
// every short-lived connection on the device) that piles up TIME_WAIT pcbs and
// pressures the shared MEMP_NUM_TCP_PCB pool. 2*MSL exists to let stale WAN
// duplicates die before a 4-tuple is reused, but this netstack is device-local
// (app <-> netstack, no WAN path for these segments), so a short MSL is safe
// and frees pcbs ~6x faster (TIME_WAIT 20s instead of 120s).
#define TCP_MSL 10000UL

// ---- Per-platform sizing ---------------------------------------------------
//
// Connection-count targets (a VPN handles every connection on the device):
// iOS ~512, other platforms ~2048. Each simultaneous connection needs one
// tcp_pcb (256 B, static); idle connections cost only that. MEMP_NUM_TCP_SEG is
// the shared pool of queued segments used only by actively-transferring
// connections (up to TCP_SND_QUEUELEN = 64 each); running out throttles a
// sender (graceful ERR_MEM), it does not drop connections.
//
// The lwIP TCP here is device-local (app <-> netstack, ~microsecond RTT), so a
// small window still saturates it; the window mainly bounds how much unread
// data buffers per connection (lwIP ooseq pbufs + the read channel). MEM_SIZE
// is the shared heap for PBUF_RAM: TCP send buffers (up to TCP_SND_BUF per
// active sender) and transient inbound pbufs — sized for concurrent active
// transfer, not for the full connection count (idle connections use no heap).
//
// iOS keeps everything lean so the worst case across its ~512 connections
// stays within the Network Extension memory budget; other platforms use the
// larger sizes below for higher throughput.
#if defined __APPLE__
#include <TargetConditionals.h>
#if TARGET_OS_IPHONE
#define TCP_MSS 8191
#define LWIP_TCP_KEEPALIVE 1
#define MEMP_NUM_TCP_PCB 512
#define MEMP_NUM_TCP_SEG 4096
#define TCP_WND (16 * TCP_MSS)
#define TCP_SND_BUF (8 * TCP_MSS)
#define MEM_SIZE (1024 * 1024)
#endif
#endif

// Defaults for every platform not tuned above.
#ifndef TCP_MSS
// Empirical sweet spot on Android (tested on 23116PN5BC, Android 16, tun0 MTU 65207):
// - 3600 (<1 page):   5.61B user + 13.73B kernel = 19.35B instr/GiB (2.3x syscall/packet overhead)
// - 8191 (~2 pages):  5.41B user +  6.72B kernel = 12.13B instr/GiB (best overall)
// - 16324 (~4 pages): 5.40B user + 10.14B kernel = 15.54B instr/GiB (+51% kernel skb overhead)
// - 65147 (~64 KiB):  persistent ENOBUFS (errno 105) on TUN write, causing RTO stalls
#define TCP_MSS 8191
#endif
#ifndef MEMP_NUM_TCP_PCB
#define MEMP_NUM_TCP_PCB 2048
#endif
#ifndef MEMP_NUM_TCP_SEG
#define MEMP_NUM_TCP_SEG 16384
#endif
#ifndef TCP_WND
#define LWIP_WND_SCALE 1
#define TCP_RCV_SCALE 3
#define TCP_WND (256 * 1024)
#endif
#ifndef TCP_SND_BUF
#define TCP_SND_BUF (256 * 1024)
#ifndef TCP_SNDLOWAT
#define TCP_SNDLOWAT (4 * TCP_MSS)
#endif
#endif
#ifndef MEM_SIZE
#define MEM_SIZE (32 * 1024 * 1024)
#endif
// -----------------------------------------------------------------------------

// PBUF_POOL is unused on this data path (RX uses PBUF_RAM via the sink, TX uses
// PBUF_RAM, UDP uses PBUF_REF), so the default large pool is ~1.5 KB/entry of
// wasted static RAM. Keep a small margin for incidental/cold-path allocations.
// The lwIP sanity checks tie PBUF_POOL_SIZE to TCP_WND assuming pool-based RX
// (false here), so they are disabled; the checks that DO still apply are
// re-asserted in sys_arch.c, where lwIP's derived macros are available.
#define PBUF_POOL_SIZE 16
#define LWIP_DISABLE_TCP_SANITY_CHECKS 1

// #define TCP_MSS 1460
// #define TCP_WND (16 * TCP_MSS)
// #define TCP_SND_BUF (8 * TCP_MSS)
// #define MEM_LIBC_MALLOC 1
// #define MEMP_MEM_MALLOC 1

#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS

// needed on 64-bit systems, enable it always so that the same configuration
// is used regardless of the platform
#define IPV6_FRAG_COPYHEADER 1

/* Leave LWIP_DEBUG undefined: lwIP tests it with #ifdef, not #if. */
#define LWIP_DBG_MIN_LEVEL LWIP_DBG_LEVEL_ALL
#define LWIP_DBG_TYPES_ON LWIP_DBG_OFF
#define NETIF_DEBUG LWIP_DBG_OFF
#define PBUF_DEBUG LWIP_DBG_OFF
#define INET_DEBUG LWIP_DBG_OFF
#define IP_DEBUG LWIP_DBG_OFF
#define IP_REASS_DEBUG LWIP_DBG_OFF
#define RAW_DEBUG LWIP_DBG_OFF
#define MEM_DEBUG LWIP_DBG_OFF
#define MEMP_DEBUG LWIP_DBG_OFF
#define SYS_DEBUG LWIP_DBG_OFF
#define TIMERS_DEBUG LWIP_DBG_OFF
#define TCP_DEBUG LWIP_DBG_ON
#define TCP_INPUT_DEBUG LWIP_DBG_OFF
#define TCP_RTO_DEBUG LWIP_DBG_OFF
#define TCP_CWND_DEBUG LWIP_DBG_OFF
#define TCP_WND_DEBUG LWIP_DBG_OFF
#define TCP_RST_DEBUG LWIP_DBG_ON
#define TCP_QLEN_DEBUG LWIP_DBG_ON
#define TCP_OUTPUT_DEBUG LWIP_DBG_ON
#define UDP_DEBUG LWIP_DBG_OFF
#define TCPIP_DEBUG LWIP_DBG_OFF
#define IP6_DEBUG LWIP_DBG_OFF

#define LWIP_STATS 0
#define LWIP_STATS_DISPLAY 0
#define LWIP_PERF 0

#endif
