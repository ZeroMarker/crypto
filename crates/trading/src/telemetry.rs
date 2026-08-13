//! Observability (roadmap Phase 5): structured logging and a small metrics
//! registry with a Prometheus text-format exporter.
//!
//! - [`init_logging`] installs a `tracing` subscriber filtered by `RUST_LOG`
//!   (default `info`). Log lines are structured (key=value fields), so they
//!   can be scraped or piped into a log pipeline.
//! - [`global`] is the process-wide [`Metrics`] registry. Counters, gauges and
//!   histograms live in it; [`Metrics::render_prometheus`] dumps the current
//!   snapshot in Prometheus exposition format, ready for a `/metrics` scrape
//!   or a shutdown summary.
//!
//! The registry is dependency-free: no `prometheus` crate, just a few
//! `Mutex<HashMap>`s. Buckets for histograms are fixed at construction.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use tracing_subscriber::EnvFilter;

/// Install the `tracing` subscriber. Idempotent; safe to call twice.
pub fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

/// The process-wide metrics registry.
pub fn global() -> &'static Metrics {
    static METRICS: OnceLock<Metrics> = OnceLock::new();
    METRICS.get_or_init(Metrics::new)
}

/// A metric name, sanitized for Prometheus (must match `[a-zA-Z_:][a-zA-Z0-9_:]*`).
fn sanitize(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == ':' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push('_');
    }
    if !out.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_' || c == ':') {
        out.insert(0, '_');
    }
    out
}

/// Counters, gauges and histograms, keyed by name.
#[derive(Debug, Default)]
pub struct Metrics {
    counters: Mutex<HashMap<String, u64>>,
    gauges: Mutex<HashMap<String, f64>>,
    histograms: Mutex<HashMap<String, Histogram>>,
}

/// A Prometheus-style histogram with fixed buckets.
#[derive(Debug, Clone)]
pub struct Histogram {
    /// Upper bounds of the buckets (exclusive), ascending.
    buckets: Vec<f64>,
    /// Per-bucket counts, one more than `buckets` (the last is +Inf).
    counts: Vec<u64>,
    sum: f64,
    count: u64,
}

impl Histogram {
    pub fn new(bucket_upper_bounds: Vec<f64>) -> Histogram {
        let len = bucket_upper_bounds.len();
        Histogram {
            buckets: bucket_upper_bounds,
            counts: vec![0; len + 1],
            sum: 0.0,
            count: 0,
        }
    }
}

impl Metrics {
    pub fn new() -> Metrics {
        Metrics::default()
    }

    /// Increment a counter (created as 0 on first use).
    pub fn inc(&self, name: &str, by: u64) {
        *self
            .counters
            .lock()
            .unwrap()
            .entry(sanitize(name))
            .or_insert(0) += by;
    }

    /// Set a gauge to `value` (e.g. current equity, position size).
    pub fn set_gauge(&self, name: &str, value: f64) {
        self.gauges.lock().unwrap().insert(sanitize(name), value);
    }

    /// Observe a sample into a histogram, creating it on first use.
    pub fn observe(&self, name: &str, buckets: Vec<f64>, value: f64) {
        let mut hs = self.histograms.lock().unwrap();
        let h = hs
            .entry(sanitize(name))
            .or_insert_with(|| Histogram::new(buckets));
        h.count += 1;
        h.sum += value;
        let mut i = 0;
        while i < h.buckets.len() && value >= h.buckets[i] {
            i += 1;
        }
        h.counts[i] += 1;
    }

    pub fn counter(&self, name: &str) -> u64 {
        self.counters
            .lock()
            .unwrap()
            .get(&sanitize(name))
            .copied()
            .unwrap_or(0)
    }

    pub fn gauge(&self, name: &str) -> f64 {
        self.gauges
            .lock()
            .unwrap()
            .get(&sanitize(name))
            .copied()
            .unwrap_or(0.0)
    }

    /// Render the whole registry in Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        let counters = self.counters.lock().unwrap();
        for (name, value) in counters.iter() {
            out.push_str(&format!("# TYPE {name} counter\n{name} {value}\n"));
        }
        drop(counters);
        let gauges = self.gauges.lock().unwrap();
        for (name, value) in gauges.iter() {
            out.push_str(&format!("# TYPE {name} gauge\n{name} {value}\n"));
        }
        drop(gauges);
        let histograms = self.histograms.lock().unwrap();
        for (name, h) in histograms.iter() {
            out.push_str(&format!("# TYPE {name} histogram\n"));
            let mut cumulative = 0;
            for (i, b) in h.buckets.iter().enumerate() {
                cumulative += h.counts[i];
                out.push_str(&format!("{name}_bucket{{le=\"{b}\"}} {cumulative}\n"));
            }
            cumulative += h.counts[h.counts.len() - 1];
            out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {cumulative}\n"));
            out.push_str(&format!("{name}_sum {}\n", h.sum));
            out.push_str(&format!("{name}_count {}\n", h.count));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_and_gauges() {
        let m = Metrics::new();
        m.inc("trades_executed", 1);
        m.inc("trades_executed", 2);
        m.set_gauge("equity_usd", 10_250.5);
        assert_eq!(m.counter("trades_executed"), 3);
        assert_eq!(m.gauge("equity_usd"), 10_250.5);
        assert_eq!(m.counter("missing"), 0);
    }

    #[test]
    fn histogram_bucketing() {
        let m = Metrics::new();
        let buckets = vec![1.0, 5.0, 10.0];
        m.observe("request_ms", buckets.clone(), 0.5);
        m.observe("request_ms", buckets.clone(), 4.0);
        m.observe("request_ms", buckets, 99.0);
        let text = m.render_prometheus();
        assert!(text.contains("request_ms_bucket{le=\"1\"} 1"));
        assert!(text.contains("request_ms_bucket{le=\"5\"} 2"));
        assert!(text.contains("request_ms_bucket{le=\"+Inf\"} 3"));
        assert!(text.contains("request_ms_sum 103.5"));
        assert!(text.contains("request_ms_count 3"));
    }

    #[test]
    fn sanitizes_names() {
        let m = Metrics::new();
        m.inc("fetch ok", 1);
        m.inc("9bad", 1);
        assert!(m.counter("fetch ok") > 0 || m.render_prometheus().contains("fetch_ok"));
        // The rendered output must only contain valid Prometheus names.
        for line in m.render_prometheus().lines() {
            if line.starts_with('#') {
                continue;
            }
            let name = line.split_whitespace().next().unwrap();
            assert!(
                name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'),
                "metric must start with a letter: {name}"
            );
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':'),
                "metric name has invalid chars: {name}"
            );
        }
    }
}
