//! End-to-end throughput benchmark for `netstack-lwip`.
//!
//! `NetStack` never dials — it only *accepts* TCP connections that arrive as raw
//! IP packets on its `Sink` (as if from a TUN device). To measure throughput we
//! therefore need an *active* TCP peer that produces and consumes raw IP
//! packets. This example uses [`smoltcp`] (a pure-Rust userspace TCP/IP stack in
//! bare-IP `Medium::Ip` mode) as that peer, wired directly to the `NetStack`
//! Sink/Stream in memory — no OS TUN device and no root required.
//!
//! Data path exercised end to end:
//!   * download (netstack -> peer): `TcpStream::poll_write` -> `tcp_output` ->
//!     `output_ip4` -> stack `Stream` -> smoltcp -> counted on recv.
//!   * upload   (peer -> netstack): smoltcp -> stack `Sink` -> `tcp_in` ->
//!     `tcp_recv_cb` -> channel -> `TcpStream::poll_read` -> counted.
//!
//! The `TUN2SOCKS=1` lwIP build accepts any destination IP, so the peer simply
//! dials `10.0.0.1:80` from `10.0.0.2`.
//!
//! Usage:
//!   cargo run --release --example throughput -- [--bytes N] [--dir up|down|both] [--chunk N]
//!
//! Defaults: --bytes 268435456 (256 MiB), --dir both, --chunk 65536 (64 KiB).

use std::pin::Pin;
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::Notify;
use std::sync::Arc;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

use netstack_lwip::{NetStack, TcpStream};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dir {
    Download, // netstack writes, peer reads
    Upload,   // peer writes, netstack reads
}

impl Dir {
    fn name(self) -> &'static str {
        match self {
            Dir::Download => "download (netstack -> peer)",
            Dir::Upload => "upload   (peer -> netstack)",
        }
    }
}

// ---------------------------------------------------------------------------
// smoltcp in-memory device: RX is fed by lwIP's output, TX is drained into
// lwIP's input. Both are tokio unbounded channels so the (sync) smoltcp poll
// loop can drain RX via `try_recv` and the async pump tasks can await them.
// ---------------------------------------------------------------------------

struct ChanDevice {
    rx: UnboundedReceiver<Vec<u8>>, // packets coming out of lwIP, to hand to smoltcp
    tx: UnboundedSender<Vec<u8>>,   // packets smoltcp emits, to feed into lwIP
    mtu: usize,
}

struct RxTok(Vec<u8>);
struct TxTok(UnboundedSender<Vec<u8>>);

impl RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for TxTok {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        // A closed receiver just means lwIP is gone (teardown); drop silently.
        let _ = self.0.send(buf);
        r
    }
}

impl Device for ChanDevice {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok;

    fn receive(&mut self, _t: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.try_recv().ok()?;
        Some((RxTok(pkt), TxTok(self.tx.clone())))
    }

    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TxTok(self.tx.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu; // matches lwIP netif MTU (1500)
        caps
    }
}

/// Result of one direction: bytes transferred and the elapsed time measured by
/// whichever side was the *receiver* (from first byte to the last).
struct Report {
    bytes: u64,
    elapsed: Duration,
}

async fn run_direction(dir: Dir, total: u64, chunk: usize, local_port: u16) -> Report {
    let (stack, mut listener, _udp) = NetStack::new().expect("create netstack");

    // lwIP output -> smoltcp RX
    let (in_tx, in_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    // smoltcp TX -> lwIP input
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    // Wakes the smoltcp driver as soon as a packet arrives from lwIP.
    let wake = Arc::new(Notify::new());

    // Optional validation of the production direct-output callback. This peer
    // adapter copies only because smoltcp's in-memory device owns its input.
    let direct_output = if std::env::var_os("NETSTACK_DIRECT_OUTPUT").is_some() {
        let tx = in_tx.clone();
        let notify = wake.clone();
        let inject_drop = std::env::var_os("NETSTACK_DROP_ONCE").is_some();
        let dropped = std::sync::atomic::AtomicBool::new(false);
        Some(stack.direct_output(move |parts| {
            let len: usize = parts.iter().map(|p| p.len()).sum();
            if inject_drop && len > 100 && !dropped.swap(true, std::sync::atomic::Ordering::Relaxed) {
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            let mut packet = Vec::with_capacity(len);
            for part in parts { packet.extend_from_slice(part); }
            tx.send(packet).map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
            notify.notify_one();
            Ok(len)
        }).unwrap())
    } else { None };
    let (mut sink, mut stream) = stack.split();

    // Pump: drain lwIP's outbound packets into the smoltcp device RX.
    let pump_in = {
        let wake = wake.clone();
        tokio::spawn(async move {
            while let Some(item) = stream.next().await {
                match item {
                    Ok(pkt) => {
                        if in_tx.send(pkt).is_err() {
                            break; // driver gone
                        }
                        wake.notify_one();
                    }
                    Err(_) => break,
                }
            }
        })
    };

    // Pump: feed smoltcp's outbound packets into lwIP. The NetStack sink buffers
    // a single item and flushes per-send, so `send` (feed + flush) is correct.
    let pump_out = tokio::spawn(async move {
        while let Some(pkt) = out_rx.recv().await {
            if sink.send(pkt).await.is_err() {
                break;
            }
        }
    });

    // smoltcp driver: the active TCP peer. Owns the device, interface and socket.
    let driver = {
        let wake = wake.clone();
        tokio::spawn(async move {
            let mut dev = ChanDevice {
                rx: in_rx,
                tx: out_tx,
                mtu: std::env::var("NETSTACK_PEER_MTU").ok()
                    .map(|v| v.parse().expect("NETSTACK_PEER_MTU")).unwrap_or(1500),
            };
            let config = Config::new(HardwareAddress::Ip);
            let mut iface = Interface::new(config, &mut dev, SmolInstant::now());
            iface.update_ip_addrs(|addrs| {
                addrs
                    .push(IpCidr::new(IpAddress::v4(10, 0, 0, 2), 24))
                    .expect("push addr");
            });

            // Large buffers so smoltcp advertises a big window and never becomes
            // the bottleneck; lwIP's own TCP_WND/TCP_SND_BUF are the real caps.
            let rx_buf = tcp::SocketBuffer::new(vec![0u8; 1 << 20]);
            let tx_buf = tcp::SocketBuffer::new(vec![0u8; 1 << 20]);
            let mut socket = tcp::Socket::new(rx_buf, tx_buf);
            // Minimise peer-induced delay so the measurement reflects the
            // netstack: no Nagle coalescing, and ACK immediately (no ack delay).
            socket.set_nagle_enabled(false);
            socket.set_ack_delay(None);

            let mut sockets = SocketSet::new(Vec::new());
            let handle = sockets.add(socket);
            sockets
                .get_mut::<tcp::Socket>(handle)
                .connect(iface.context(), (IpAddress::v4(10, 0, 0, 1), 80), local_port)
                .expect("smoltcp connect");

            let send_buf = vec![0x5Au8; chunk];
            let mut recv_scratch = vec![0u8; chunk];
            let mut sent: u64 = 0;
            let mut recv: u64 = 0;
            let mut start: Option<Instant> = None;
            let mut closing = false;

            loop {
                // Drive smoltcp to quiescence before parking. smoltcp emits at
                // most ONE segment per poll() call, so to keep a full window in
                // flight we must poll repeatedly (doing socket I/O each pass)
                // until poll reports nothing more happened. Polling once and
                // then awaiting would collapse the transfer to one segment per
                // scheduler round-trip (stop-and-wait).
                loop {
                    let s = sockets.get_mut::<tcp::Socket>(handle);
                    match dir {
                        Dir::Download => {
                            while s.can_recv() {
                                match s.recv_slice(&mut recv_scratch) {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        assert!(recv_scratch[..n].iter().all(|b| *b == 0xA5), "download payload corruption");
                                        if start.is_none() {
                                            start = Some(Instant::now());
                                        }
                                        recv += n as u64;
                                    }
                                }
                            }
                        }
                        Dir::Upload => {
                            while sent < total && s.can_send() {
                                let want = ((total - sent) as usize).min(send_buf.len());
                                match s.send_slice(&send_buf[..want]) {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => sent += n as u64,
                                }
                            }
                            if sent >= total && !closing {
                                s.close(); // send FIN once all data is queued
                                closing = true;
                            }
                        }
                    }

                    if iface.poll(SmolInstant::now(), &mut dev, &mut sockets)
                        == smoltcp::iface::PollResult::None
                    {
                        break;
                    }
                }

                // Termination: download is done once we've received everything;
                // upload once we've sent everything and the socket has closed.
                let s = sockets.get_mut::<tcp::Socket>(handle);
                let done = match dir {
                    Dir::Download => recv >= total,
                    Dir::Upload => closing && !s.is_open(),
                };
                if done {
                    break;
                }

                // Park until lwIP hands us a packet (ACK/data/window update),
                // with a 1ms backstop for retransmit/timeout progress.
                let _ = tokio::time::timeout(Duration::from_millis(1), wake.notified()).await;
            }

            // Flush any final ACK/FIN so the netstack side sees clean EOF.
            iface.poll(SmolInstant::now(), &mut dev, &mut sockets);

            let elapsed = start.map(|s| s.elapsed()).unwrap_or_default();
            (recv, elapsed)
        })
    };

    // netstack application side: accept the connection and drive the TcpStream.
    // Returns the stream so it stays alive until the whole run completes.
    let app = tokio::spawn(async move {
        let (mut ns, _local, _remote): (Pin<Box<TcpStream>>, _, _) =
            listener.next().await.expect("accepted connection");

        let mut recv: u64 = 0;
        let mut start: Option<Instant> = None;

        match dir {
            Dir::Download => {
                let buf = vec![0xA5u8; chunk];
                let mut sent: u64 = 0;
                let transfer = async {
                let mut messages = 0;
                while sent < total {
                    let n = ((total - sent) as usize).min(buf.len());
                    if std::env::var_os("NETSTACK_VECTORED").is_some() {
                        let middle = n / 2;
                        let mut offset = 0;
                        while offset < n {
                            let first = if offset < middle { &buf[offset..middle] } else { &[] };
                            let second = &buf[offset.max(middle)..n];
                            let wrote = ns.write_vectored(&[std::io::IoSlice::new(first), std::io::IoSlice::new(second)]).await.unwrap();
                            assert!(wrote > 0);
                            offset += wrote;
                        }
                    } else { ns.write_all(&buf[..n]).await.expect("netstack write"); }
                    sent += n as u64;
                    messages += 1;
                    if messages % 32 == 0 { tokio::task::yield_now().await; }
                }
                };
                if std::env::var_os("NETSTACK_BATCH_OUTPUT").is_some() {
                    netstack_lwip::batch_tcp_output(transfer).await;
                } else { transfer.await; }
                ns.flush().await.ok();
                ns.shutdown().await.ok();
            }
            Dir::Upload => {
                let mut buf = vec![0u8; chunk];
                loop {
                    let n = ns.read(&mut buf).await.expect("netstack read");
                    if n == 0 {
                        break; // EOF
                    }
                    assert!(buf[..n].iter().all(|b| *b == 0x5A), "upload payload corruption");
                    if start.is_none() {
                        start = Some(Instant::now());
                    }
                    recv += n as u64;
                    if recv >= total {
                        break;
                    }
                }
                // Close our side so the peer's FIN-wait completes and the
                // connection tears down cleanly on both ends.
                ns.shutdown().await.ok();
            }
        }

        let elapsed = start.map(|s| s.elapsed()).unwrap_or_default();
        (recv, elapsed, ns)
    });

    // Await both concurrently: the receiver side owns the authoritative
    // measurement, but each direction needs both tasks to run to completion
    // (e.g. upload only finishes once the app closes and the peer sees the FIN).
    let (drv_res, app_res) = futures::future::join(driver, app).await;
    let (drv_recv, drv_elapsed) = drv_res.expect("driver task");
    let (app_recv, app_elapsed, ns) = app_res.expect("app task");

    let report = match dir {
        Dir::Download => Report {
            bytes: drv_recv,
            elapsed: drv_elapsed,
        },
        Dir::Upload => Report {
            bytes: app_recv,
            elapsed: app_elapsed,
        },
    };

    // Tear everything down so the process-global NetStack singleton is released
    // before the next direction: drop the connection, then stop the pumps
    // (dropping the sink/stream halves, hence the NetStack), then the listener.
    drop(ns);
    pump_in.abort();
    pump_out.abort();
    let _ = pump_in.await;
    let _ = pump_out.await;
    // `listener` was moved into (and dropped by) the completed `app` task.
    drop(_udp);
    drop(direct_output);

    report
}

fn parse_args() -> (u64, Vec<Dir>, usize) {
    let mut bytes: u64 = 256 * 1024 * 1024;
    let mut dirs = vec![Dir::Download, Dir::Upload];
    let mut chunk: usize = 64 * 1024;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bytes" => {
                bytes = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .expect("--bytes N");
            }
            "--chunk" => {
                chunk = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .expect("--chunk N");
            }
            "--dir" => {
                dirs = match args.next().as_deref() {
                    Some("down") | Some("download") => vec![Dir::Download],
                    Some("up") | Some("upload") => vec![Dir::Upload],
                    Some("both") | None => vec![Dir::Download, Dir::Upload],
                    Some(other) => panic!("unknown --dir {other:?} (use up|down|both)"),
                };
            }
            "-h" | "--help" => {
                eprintln!(
                    "usage: throughput [--bytes N] [--dir up|down|both] [--chunk N]"
                );
                std::process::exit(0);
            }
            other => panic!("unknown arg {other:?}"),
        }
    }
    (bytes, dirs, chunk)
}

fn main() {
    let (bytes, dirs, chunk) = parse_args();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async move {
        println!(
            "netstack-lwip throughput: {} bytes ({:.1} MiB) per direction, {}-byte app chunks\n",
            bytes,
            bytes as f64 / (1024.0 * 1024.0),
            chunk,
        );

        for (i, dir) in dirs.into_iter().enumerate() {
            // Distinct local port per connection: lwIP's global TCP state
            // persists across NetStack instances, so a fresh connection must not
            // reuse a 4-tuple still lingering in TIME_WAIT from a prior run.
            let local_port = 49500 + i as u16;
            let report = run_direction(dir, bytes, chunk, local_port).await;
            assert_eq!(report.bytes, bytes, "incomplete transfer");
            #[cfg(feature = "datapath-diagnostics")]
            eprintln!("datapath [write, output, tun packets, tun bytes]: {:?}", netstack_lwip::datapath_snapshot());

            assert_eq!(
                report.bytes, bytes,
                "{}: transferred {} bytes, expected {}",
                dir.name(),
                report.bytes,
                bytes
            );

            let secs = report.elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
            let mib_s = report.bytes as f64 / (1024.0 * 1024.0) / secs;
            let gbit_s = report.bytes as f64 * 8.0 / 1e9 / secs;
            println!(
                "{}: {:.0} MiB in {:.3}s  ->  {:.1} MiB/s  ({:.2} Gbps)",
                dir.name(),
                report.bytes as f64 / (1024.0 * 1024.0),
                secs,
                mib_s,
                gbit_s,
            );
        }
    });

    // Prove the singleton was fully torn down: a fresh stack must be creatable.
    let rt2 = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    rt2.block_on(async {
        NetStack::new().expect("NetStack recreatable after full teardown");
    });

    println!("\ndone.");
}
