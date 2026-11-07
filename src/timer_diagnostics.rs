//! Process-lifetime counters; no timer, logging, or reset on query.
use std::sync::Mutex;

#[derive(Clone, Copy, Default)]
pub struct Snapshot {
    pub calls: u64,
    pub elapsed_ns: u64,
    pub thread_cpu_ns: u64,
    pub max_gap_ns: u64,
    pub last_boot_ns: u64,
}
static STATS: Mutex<Snapshot> = Mutex::new(Snapshot {
    calls: 0, elapsed_ns: 0, thread_cpu_ns: 0, max_gap_ns: 0, last_boot_ns: 0,
});

#[cfg(target_os = "android")]
fn clock(id: libc::clockid_t) -> u64 {
    let mut t: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(id, &mut t) } != 0 { return 0; }
    t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
}
/// (Includes suspend, excludes suspend, current thread CPU time).
pub fn clocks() -> (u64, u64, u64) {
    #[cfg(target_os = "android")]
    { (clock(libc::CLOCK_BOOTTIME), clock(libc::CLOCK_MONOTONIC), clock(libc::CLOCK_THREAD_CPUTIME_ID)) }
    #[cfg(not(target_os = "android"))]
    { (0, 0, 0) }
}
pub fn snapshot() -> Snapshot { *STATS.lock().unwrap_or_else(|e| e.into_inner()) }
pub struct Measurement { boot: u64, mono: u64, cpu: u64 }
impl Measurement {
    pub fn start() -> Self {
        let (boot, mono, cpu) = clocks();
        Self { boot, mono, cpu }
    }
    pub fn finish(self) {
        let (_, mono, cpu) = clocks();
        let mut s = STATS.lock().unwrap_or_else(|e| e.into_inner());
        if s.last_boot_ns != 0 { s.max_gap_ns = s.max_gap_ns.max(self.boot.saturating_sub(s.last_boot_ns)); }
        s.calls += 1;
        s.elapsed_ns += mono.saturating_sub(self.mono);
        s.thread_cpu_ns += cpu.saturating_sub(self.cpu);
        s.last_boot_ns = self.boot;
    }
}
