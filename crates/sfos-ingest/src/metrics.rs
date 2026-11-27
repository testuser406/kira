use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};

#[derive(Default)]
pub struct Metrics {
    pub udp_port: std::sync::atomic::AtomicU16,
    pub datagrams: AtomicU64,
    pub lines: AtomicU64,
    pub parsed: AtomicU64,
    pub rejected: AtomicU64,
    pub denied: AtomicU64,
    pub queued: AtomicU64,
    pub written: AtomicU64,
    pub db_errors: AtomicU64,
    pub dropped: AtomicU64,
    pub spilled: AtomicU64,
    pub replayed: AtomicU64,
    pub queue_high_water: AtomicU64,
    pub filtered: AtomicU64,
    pub user_resolved: AtomicU64,
    pub user_ambiguous: AtomicU64,
}

impl Metrics {
    pub fn record_queue_depth(&self, depth: usize) {
        self.queue_high_water
            .fetch_max(depth as u64, Ordering::Relaxed);
    }

    pub fn snapshot(&self, queue_depth: usize, queue_capacity: usize) -> Value {
        self.record_queue_depth(queue_depth);
        let queue_utilization_percent = if queue_capacity == 0 {
            0.0
        } else {
            queue_depth as f64 * 100.0 / queue_capacity as f64
        };
        json!({
            "datagrams": self.datagrams.load(Ordering::Relaxed),
            "lines": self.lines.load(Ordering::Relaxed),
            "parsed": self.parsed.load(Ordering::Relaxed),
            "rejected": self.rejected.load(Ordering::Relaxed),
            "denied_sources": self.denied.load(Ordering::Relaxed),
            "queued": self.queued.load(Ordering::Relaxed),
            "written": self.written.load(Ordering::Relaxed),
            "db_errors": self.db_errors.load(Ordering::Relaxed),
            "dropped": self.dropped.load(Ordering::Relaxed),
            "spilled": self.spilled.load(Ordering::Relaxed),
            "replayed": self.replayed.load(Ordering::Relaxed),
            "spill_files_pending": crate::spill::pending_files(),
            "queue_depth": queue_depth,
            "queue_capacity": queue_capacity,
            "queue_utilization_percent": queue_utilization_percent,
            "queue_high_water": self.queue_high_water.load(Ordering::Relaxed),
            "os_udp_drops": os_udp_drops(self.udp_port.load(Ordering::Relaxed)),
            "filtered": self.filtered.load(Ordering::Relaxed),
            "user_resolved": self.user_resolved.load(Ordering::Relaxed),
            "user_ambiguous": self.user_ambiguous.load(Ordering::Relaxed),
        })
    }
}

/// Datagrams the operating system dropped before the collector could read them
/// (receive buffer full). Linux only; `None` where the OS does not expose it per socket.
pub fn os_udp_drops(port: u16) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let mut total = 0u64;
        let mut seen = false;
        for file in ["/proc/net/udp", "/proc/net/udp6"] {
            let Ok(text) = std::fs::read_to_string(file) else {
                continue;
            };
            for line in text.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                let local_port = cols
                    .get(1)
                    .and_then(|a| a.rsplit(':').next())
                    .and_then(|p| u16::from_str_radix(p, 16).ok());
                if local_port == Some(port) {
                    if let Some(d) = cols.last().and_then(|d| d.parse::<u64>().ok()) {
                        total += d;
                        seen = true;
                    }
                }
            }
        }
        seen.then_some(total)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = port;
        None
    }
}

pub type SharedMetrics = Arc<Metrics>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_queue_pressure_and_high_water() {
        let metrics = Metrics::default();
        metrics.record_queue_depth(12);
        let snapshot = metrics.snapshot(8, 20);

        assert_eq!(snapshot["queue_depth"], 8);
        assert_eq!(snapshot["queue_capacity"], 20);
        assert_eq!(snapshot["queue_utilization_percent"], 40.0);
        assert_eq!(snapshot["queue_high_water"], 12);
    }
}
