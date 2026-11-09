#include "lwip/opt.h"
#include "lwip/def.h" /* LWIP_MIN/LWIP_MAX, used by the TCP_SND*LOWAT macros */
#include "lwip/sys.h"

/* lwipopts.h sets LWIP_DISABLE_TCP_SANITY_CHECKS because two of lwIP's checks
 * assume PBUF_POOL-based RX (they tie PBUF_POOL_SIZE to TCP_WND), which does
 * not apply to this stack (RX/TX use PBUF_RAM). That switch is all-or-nothing,
 * so re-assert here the checks from init.c that DO still apply. This file is
 * compiled after opt.h has derived TCP_SND_QUEUELEN etc., which lwipopts.h
 * itself cannot see. */
#if LWIP_TCP
#if !MEMP_MEM_MALLOC && (MEMP_NUM_TCP_SEG < TCP_SND_QUEUELEN)
#error "MEMP_NUM_TCP_SEG should be at least as big as TCP_SND_QUEUELEN"
#endif
#if TCP_SND_BUF < (2 * TCP_MSS)
#error "TCP_SND_BUF must be at least as much as (2 * TCP_MSS)"
#endif
#if TCP_SND_QUEUELEN < (2 * (TCP_SND_BUF / TCP_MSS))
#error "TCP_SND_QUEUELEN must be at least as much as (2 * TCP_SND_BUF/TCP_MSS)"
#endif
#if TCP_SNDLOWAT >= TCP_SND_BUF
#error "TCP_SNDLOWAT must be less than TCP_SND_BUF"
#endif
/* Only meaningful when snd_buf is a u16; with window scaling tcpwnd_size_t
 * (and so snd_buf) is u32. */
#if !LWIP_WND_SCALE && (TCP_SNDLOWAT >= (0xFFFF - (4 * TCP_MSS)))
#error "TCP_SNDLOWAT must at least be 4*MSS below u16_t overflow"
#endif
#if TCP_SNDQUEUELOWAT >= TCP_SND_QUEUELEN
#error "TCP_SNDQUEUELOWAT must be less than TCP_SND_QUEUELEN"
#endif
#if TCP_WND < TCP_MSS
#error "TCP_WND is smaller than MSS"
#endif
#endif /* LWIP_TCP */

#ifdef _WIN32
  // defines both win32 and win64
  #ifdef _MSC_VER
  #pragma warning (push, 3)
  #endif
  #include <windows.h>
  #ifdef _MSC_VER
  #pragma warning (pop)
  #endif
  #include <time.h>
  
  #include <lwip/arch.h>
  #include <lwip/stats.h>
  #include <lwip/debug.h>
  #include <lwip/tcpip.h>
  
  /** Set this to 1 to enable assertion checks that SYS_ARCH_PROTECT() is only
   * called once in a call stack (calling it nested might cause trouble in some
   * implementations, so let's avoid this in core code as long as we can).
   */
  #ifndef LWIP_SYS_ARCH_CHECK_NESTED_PROTECT
  #define LWIP_SYS_ARCH_CHECK_NESTED_PROTECT 1
  #endif
  
  /** Set this to 1 to enable assertion checks that SYS_ARCH_PROTECT() is *not*
   * called before functions potentiolly involving the OS scheduler.
   *
   * This scheme is currently broken only for non-core-locking when waking up
   * threads waiting on a socket via select/poll.
   */
  #ifndef LWIP_SYS_ARCH_CHECK_SCHEDULING_UNPROTECTED
  #define LWIP_SYS_ARCH_CHECK_SCHEDULING_UNPROTECTED LWIP_TCPIP_CORE_LOCKING
  #endif
  
  #define LWIP_WIN32_SYS_ARCH_ENABLE_PROTECT_COUNTER (LWIP_SYS_ARCH_CHECK_NESTED_PROTECT || LWIP_SYS_ARCH_CHECK_SCHEDULING_UNPROTECTED)
  
  /* These functions are used from NO_SYS also, for precise timer triggering */
  static LARGE_INTEGER freq, sys_start_time;
  #define SYS_INITIALIZED() (freq.QuadPart != 0)
  
  static DWORD netconn_sem_tls_index;

  u32_t
  sys_win_rand(void)
  {
    u32_t ret;
    if (SUCCEEDED(BCryptGenRandom(NULL, (PUCHAR)&ret, sizeof(ret), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        return ret;
    }
    LWIP_ASSERT("BCryptGenRandom failed", 0);
    return 0;
  }
  
  static void
  sys_win_rand_init(void)
  {
    // BCryptGenRandom does not require any setup
  }
  
  static void
  sys_init_timing(void)
  {
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&sys_start_time);
  }
  
  static LONGLONG
  sys_get_ms_longlong(void)
  {
    LONGLONG ret;
    LARGE_INTEGER now;
  #if NO_SYS
    if (!SYS_INITIALIZED()) {
      sys_init();
      LWIP_ASSERT("initialization failed", SYS_INITIALIZED());
    }
  #endif /* NO_SYS */
    QueryPerformanceCounter(&now);
    ret = now.QuadPart-sys_start_time.QuadPart;
    return (u32_t)(((ret)*1000)/freq.QuadPart);
  }
  
  u32_t
  sys_jiffies(void)
  {
    return (u32_t)sys_get_ms_longlong();
  }
  
  u32_t
  sys_now(void)
  {
    return (u32_t)sys_get_ms_longlong();
  }
  
  CRITICAL_SECTION critSec;
  #if LWIP_WIN32_SYS_ARCH_ENABLE_PROTECT_COUNTER
  static int protection_depth;
  #endif
  
  static void
  InitSysArchProtect(void)
  {
    InitializeCriticalSection(&critSec);
  }
  
  sys_prot_t
  sys_arch_protect(void)
  {
  #if NO_SYS
    if (!SYS_INITIALIZED()) {
      sys_init();
      LWIP_ASSERT("initialization failed", SYS_INITIALIZED());
    }
  #endif
    EnterCriticalSection(&critSec);
  #if LWIP_SYS_ARCH_CHECK_NESTED_PROTECT
    LWIP_ASSERT("nested SYS_ARCH_PROTECT", protection_depth == 0);
  #endif
  #if LWIP_WIN32_SYS_ARCH_ENABLE_PROTECT_COUNTER
    protection_depth++;
  #endif
    return 0;
  }
  
  void
  sys_arch_unprotect(sys_prot_t pval)
  {
    LWIP_UNUSED_ARG(pval);
  #if LWIP_SYS_ARCH_CHECK_NESTED_PROTECT
    LWIP_ASSERT("missing SYS_ARCH_PROTECT", protection_depth == 1);
  #else
    LWIP_ASSERT("missing SYS_ARCH_PROTECT", protection_depth > 0);
  #endif
  #if LWIP_WIN32_SYS_ARCH_ENABLE_PROTECT_COUNTER
    protection_depth--;
  #endif
    LeaveCriticalSection(&critSec);
  }
  
  #if LWIP_SYS_ARCH_CHECK_SCHEDULING_UNPROTECTED
  /** This checks that SYS_ARCH_PROTECT() hasn't been called by protecting
   * and then checking the level
   */
  static void
  sys_arch_check_not_protected(void)
  {
    sys_arch_protect();
    LWIP_ASSERT("SYS_ARCH_PROTECT before scheduling", protection_depth == 1);
    sys_arch_unprotect(0);
  }
  #else
  #define sys_arch_check_not_protected()
  #endif
  
  static void
  msvc_sys_init(void)
  {
    sys_win_rand_init();
    sys_init_timing();
    InitSysArchProtect();
    netconn_sem_tls_index = TlsAlloc();
    LWIP_ASSERT("TlsAlloc failed", netconn_sem_tls_index != TLS_OUT_OF_INDEXES);
  }
  
  void
  sys_init(void)
  {
    msvc_sys_init();
  }

  #include <stdarg.h>
  
  /* This is an example implementation for LWIP_PLATFORM_DIAG:
   * format a string and pass it to your output function.
   */
  void
  lwip_win32_platform_diag(const char *format, ...)
  {
    va_list ap;
    /* get the varargs */
    va_start(ap, format);
    /* print via varargs; to use another output function, you could use
       vsnprintf here */
    vprintf(format, ap);
    va_end(ap);
  }
#else
  #include <time.h>
  /* lwIP timers (RTO, TIME_WAIT, delayed-ACK, keepalive) key off deltas of
   * sys_now(), so it must be monotonic. gettimeofday() returns the wall clock,
   * which NTP/user/timezone adjustments can move backward (freezing timers) or
   * forward (firing them all at once); use CLOCK_MONOTONIC instead. */
  u32_t sys_now(void)
  {
      struct timespec ts;
      clock_gettime(CLOCK_MONOTONIC, &ts);
      /* Multiply in 64 bits: on 32-bit targets `tv_sec * 1000L` overflows
       * (signed, UB) once uptime exceeds ~24.8 days. The final u32 wrap-around
       * (~49.7 days) is fine — lwIP handles sys_now() wrapping by design. */
      return (u32_t)((u64_t)ts.tv_sec * 1000 + (u32_t)(ts.tv_nsec / 1000000));
  }
#endif
