//! Prometheus counters for the control plane.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[derive(Debug, Default)]
pub struct Metrics {
    enrollments_total: AtomicU64,
    heartbeats_total: AtomicU64,
    renewals_total: AtomicU64,
    handshake_failures_total: AtomicU64,
    rejected: Mutex<BTreeMap<String, u64>>,
    rejected_handshakes: Mutex<BTreeMap<String, u64>>,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enrollment_ok(&self) {
        self.enrollments_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn heartbeat(&self) {
        self.heartbeats_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn renewal(&self) {
        self.renewals_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn rejection(&self, reason: &str) {
        *self
            .rejected
            .lock()
            .expect("metrics mutex poisoned")
            .entry(reason.to_string())
            .or_insert(0) += 1;
    }

    pub fn handshake_failure(&self, reason: &str) {
        self.handshake_failures_total
            .fetch_add(1, Ordering::Relaxed);
        *self
            .rejected_handshakes
            .lock()
            .expect("metrics mutex poisoned")
            .entry(reason.to_string())
            .or_insert(0) += 1;
    }

    pub fn enrollments_total(&self) -> u64 {
        self.enrollments_total.load(Ordering::Relaxed)
    }

    pub fn handshake_failures_total(&self) -> u64 {
        self.handshake_failures_total.load(Ordering::Relaxed)
    }

    /// Render counters plus per-node certificate expiry for Prometheus.
    pub fn render(&self, node_expiry: &[(String, i64)]) -> String {
        let now = crate::unix_now();
        let mut out = String::new();
        out.push_str("# HELP fleet_enrollments_total Successful node enrollments.\n");
        out.push_str("# TYPE fleet_enrollments_total counter\n");
        out.push_str(&format!(
            "fleet_enrollments_total {}\n",
            self.enrollments_total.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP fleet_heartbeats_total Accepted heartbeats.\n");
        out.push_str("# TYPE fleet_heartbeats_total counter\n");
        out.push_str(&format!(
            "fleet_heartbeats_total {}\n",
            self.heartbeats_total.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP fleet_renewals_total Successful certificate renewals.\n");
        out.push_str("# TYPE fleet_renewals_total counter\n");
        out.push_str(&format!(
            "fleet_renewals_total {}\n",
            self.renewals_total.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP fleet_handshake_failures_total Rejected TLS handshakes.\n");
        out.push_str("# TYPE fleet_handshake_failures_total counter\n");
        out.push_str(&format!(
            "fleet_handshake_failures_total {}\n",
            self.handshake_failures_total.load(Ordering::Relaxed)
        ));
        for (reason, count) in self.rejected.lock().expect("metrics mutex poisoned").iter() {
            out.push_str(&format!(
                "fleet_enroll_rejected_total{{reason=\"{reason}\"}} {count}\n"
            ));
        }
        for (reason, count) in self
            .rejected_handshakes
            .lock()
            .expect("metrics mutex poisoned")
            .iter()
        {
            out.push_str(&format!(
                "fleet_handshake_failures_total{{reason=\"{reason}\"}} {count}\n"
            ));
        }
        for (node, not_after) in node_expiry {
            out.push_str(&format!(
                "fleet_cert_expiry_seconds{{node=\"{node}\"}} {}\n",
                (not_after - now).max(0)
            ));
        }
        out
    }
}
