//! Wire capture: a rolling pcap of the sensor's own traffic, for TCP/TLS
//! fingerprinting and timing. Decrypt the 443 traffic with `tls/keylog.txt`.
//!
//! Captures on Linux's `any` device (cooked headers), keeping only packets of
//! connections *to* the sensor ports: inbound to them, outbound from them. That
//! excludes SSH and everything else, including the host's own outbound HTTP(S)
//! (package updates, image pulls), which a plain `port 443` filter would keep.
//! Files rotate by size into `pcap/` and are aged out with the other captures
//! under the total disk cap. Needs `CAP_NET_RAW`.

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};

use anyhow::{Context, Result};
use pcap::{Active, Capture, Savefile};

use crate::storage::Storage;

/// Large enough for any packet on common links, so payloads are complete.
const SNAPLEN: i32 = 262_144;
/// Kernel block-retire timeout: the longest a captured packet waits in a
/// partly filled ring block before the writer can see it.
const READ_TIMEOUT: Duration = Duration::from_secs(1);
/// Pause when the ring is empty; idle wake-ups flush buffered packets and
/// check for shutdown. The kernel buffer holds traffic meanwhile.
const IDLE_SLEEP: Duration = Duration::from_millis(50);
const KERNEL_BUFFER: i32 = 8 << 20;
const PCAP_FILE_HEADER: u64 = 24;
const PCAP_RECORD_HEADER: u64 = 16;

/// BPF filter for traffic of connections to the sensor's `ports`.
pub fn filter_expr(ports: &[u16]) -> String {
    let any = |dir: &str| ports.iter().map(|p| format!("{dir} port {p}")).collect::<Vec<_>>().join(" or ");
    format!("tcp and ((inbound and ({})) or (outbound and ({})))", any("dst"), any("src"))
}

pub struct WireCapture {
    stop: Arc<AtomicBool>,
    _thread: JoinHandle<()>,
}

impl WireCapture {
    /// Opens the capture (failing fast without `CAP_NET_RAW`) and starts the
    /// writer thread.
    pub fn start(storage: Arc<Storage>, ports: &[u16], file_bytes: u64) -> Result<Self> {
        let filter = filter_expr(ports);
        let mut cap = Capture::from_device("any")
            .and_then(|c| {
                c.snaplen(SNAPLEN)
                    .promisc(false)
                    .timeout(READ_TIMEOUT.as_millis() as i32)
                    .buffer_size(KERNEL_BUFFER)
                    .open()
            })
            .context(
                "opening wire capture on `any` (needs CAP_NET_RAW; set PHP_TARPIT_PCAP=false to run without it)",
            )?;
        cap.filter(&filter, true).with_context(|| format!("compiling capture filter {filter:?}"))?;
        // Blocking reads never return on an idle link (TPACKET_V3 only retires
        // non-empty blocks), so the writer could neither flush nor stop.
        let cap = cap.setnonblock().context("setting wire capture non-blocking")?;
        let mut ring = Ring { storage, file_bytes, seq: 0, current: None };
        ring.rotate(&cap)?;
        tracing::info!(filter, file_bytes, "wire capture started");

        let stop = Arc::new(AtomicBool::new(false));
        let thread = std::thread::Builder::new()
            .name("wire-capture".into())
            .spawn({
                let stop = stop.clone();
                move || ring.run(cap, &stop)
            })
            .context("spawning wire capture thread")?;
        Ok(Self { stop, _thread: thread })
    }
}

impl Drop for WireCapture {
    /// The thread notices within [`IDLE_SLEEP`], flushes and exits.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

struct Ring {
    storage: Arc<Storage>,
    file_bytes: u64,
    seq: u64,
    current: Option<(Savefile, PathBuf, u64)>,
}

impl Ring {
    fn run(&mut self, mut cap: Capture<Active>, stop: &AtomicBool) {
        let mut unflushed = false;
        while !stop.load(Ordering::Relaxed) {
            match cap.next_packet() {
                Ok(packet) => {
                    let (file, _, size) = self.current.as_mut().expect("a file is always open");
                    file.write(&packet);
                    let n = PCAP_RECORD_HEADER + u64::from(packet.header.caplen);
                    *size += n;
                    self.storage.add(n);
                    unflushed = true;
                }
                // Non-blocking: nothing queued right now.
                Err(pcap::Error::TimeoutExpired) => {
                    if unflushed {
                        self.flush();
                        unflushed = false;
                    }
                    std::thread::sleep(IDLE_SLEEP);
                    continue;
                }
                Err(e) => {
                    tracing::error!(error = %e, "wire capture read failed; stopping");
                    break;
                }
            }
            // Rotate after the write: files exceed the limit by at most one packet.
            if self.current.as_ref().is_some_and(|(_, _, size)| *size >= self.file_bytes)
                && let Err(e) = self.rotate(&cap)
            {
                tracing::error!(error = %e, "wire capture rotation failed; stopping");
                break;
            }
        }
        self.flush();
        if let Some((_, path, _)) = self.current.take() {
            self.storage.set_live_file(&path, false);
        }
    }

    fn flush(&mut self) {
        if let Some((file, path, _)) = &mut self.current
            && let Err(e) = file.flush()
        {
            tracing::error!(path = %path.display(), error = %e, "wire capture flush failed");
        }
    }

    /// Closes the current file (if any) and starts the next one.
    fn rotate(&mut self, cap: &Capture<Active>) -> Result<()> {
        self.seq += 1;
        let name = format!("{}-{:06}.pcap", chrono::Utc::now().format("%Y%m%dT%H%M%SZ"), self.seq);
        let path = self.storage.pcap_dir().join(name);
        let file = cap.savefile(&path).with_context(|| format!("creating {}", path.display()))?;
        self.storage.add(PCAP_FILE_HEADER);
        self.storage.set_live_file(&path, true);
        if let Some((mut old, old_path, _)) = self.current.replace((file, path, PCAP_FILE_HEADER)) {
            let _ = old.flush();
            drop(old);
            self.storage.set_live_file(&old_path, false);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use pcap::Linktype;

    use super::*;

    const PACKET_HOST: u16 = 0;
    const PACKET_OUTGOING: u16 = 4;

    /// A Linux cooked (SLL) frame carrying a bare TCP header.
    fn frame(pkttype: u16, ipv6: bool, sport: u16, dport: u16) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend(pkttype.to_be_bytes());
        f.extend(1u16.to_be_bytes()); // ARPHRD_ETHER
        f.extend(6u16.to_be_bytes());
        f.extend([0u8; 8]);
        if ipv6 {
            f.extend(0x86ddu16.to_be_bytes());
            f.extend([0x60, 0, 0, 0, 0, 20, 6, 64]);
            f.extend([0x20, 0x01, 0x0d, 0xb8].iter().chain(&[0; 11]).chain(&[1])); // 2001:db8::1
            f.extend([0x20, 0x01, 0x0d, 0xb8].iter().chain(&[0; 11]).chain(&[2]));
        } else {
            f.extend(0x0800u16.to_be_bytes());
            f.extend([0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2]);
        }
        f.extend(sport.to_be_bytes());
        f.extend(dport.to_be_bytes());
        f.extend([0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x10, 0xff, 0xff, 0, 0, 0, 0]);
        f
    }

    #[test]
    fn filter_keeps_sensor_connections_and_drops_ssh_and_host_egress() {
        let cap = Capture::dead(Linktype::LINUX_SLL).unwrap();
        let bpf = cap.compile(&filter_expr(&[80, 443]), true).unwrap();
        let keeps = |pkttype, ipv6, sport, dport| bpf.filter(&frame(pkttype, ipv6, sport, dport));

        // Scanner -> sensor and sensor -> scanner, IPv4 and IPv6.
        assert!(keeps(PACKET_HOST, false, 51000, 443));
        assert!(keeps(PACKET_OUTGOING, false, 443, 51000));
        assert!(keeps(PACKET_HOST, true, 51000, 80));
        assert!(keeps(PACKET_OUTGOING, true, 80, 51000));
        // SSH to the host.
        assert!(!keeps(PACKET_HOST, false, 51000, 22));
        assert!(!keeps(PACKET_OUTGOING, false, 22, 51000));
        // The host's own HTTPS client traffic (apt, image pulls).
        assert!(!keeps(PACKET_OUTGOING, false, 51000, 443));
        assert!(!keeps(PACKET_HOST, false, 443, 51000));
    }
}
