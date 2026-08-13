//! Market data ingestion: Binance-style klines over HTTPS (blocking).
//!
//! The client speaks the Binance Spot klines REST API
//! (`GET /api/v3/klines?symbol=…&interval=…&limit=…`), which is also served by
//! `api.binance.us` and mirrors. The base URL comes from the
//! `TRADING_API_BASE` environment variable, defaulting to
//! `https://api.binance.us` (the main `api.binance.com` endpoint is
//! geo-restricted from some networks). Tests never touch the network.
//!
//! ```no_run
//! use trading::data::DataClient;
//! let client = DataClient::new();
//! let bars = client.klines("BTCUSDT", "1h", 100)?;
//! # Ok::<(), trading::data::DataError>(())
//! ```

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::bar::Bar;
use crate::resilience::{Backoff, BreakerState, CircuitBreaker, CircuitBreakerResult};
use crate::telemetry::global;

/// Default market-data endpoint. Override with `TRADING_API_BASE`.
pub const DEFAULT_BASE: &str = "https://api.binance.us";

#[derive(Debug, thiserror::Error)]
pub enum DataError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("http {0}: {1}")]
    Http(u16, String),
    #[error("malformed kline payload: {0}")]
    Malformed(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// The circuit breaker is open: the exchange has been failing; we skip
    /// the call instead of hammering it.
    #[error("circuit open (recent failures); skipping fetch")]
    CircuitOpen,
}

impl DataError {
    /// Is this error worth retrying? Transport errors and HTTP 5xx are
    /// transient; 4xx (bad request), malformed payloads and local IO are not.
    pub fn is_transient(&self) -> bool {
        match self {
            DataError::Transport(_) => true,
            DataError::Http(code, _) => *code >= 500,
            DataError::Malformed(_) | DataError::Io(_) | DataError::Json(_) => false,
            DataError::CircuitOpen => false,
        }
    }
}

/// A blocking klines client with resilience built in: exponential backoff on
/// transient failures, a circuit breaker so a dead exchange doesn't stall
/// the live loop, and Prometheus-style metrics on every fetch.
///
/// Tuning knobs (env): `TRADING_MAX_RETRIES` (default 3), `TRADING_RETRY_BASE_MS`
/// (default 250), `TRADING_BREAKER_THRESHOLD` (default 5), `TRADING_BREAKER_TIMEOUT_MS`
/// (default 30_000).
#[derive(Debug, Clone)]
pub struct DataClient {
    agent: ureq::Agent,
    base: String,
    breaker: Arc<CircuitBreaker>,
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

impl DataClient {
    /// Create a client using `TRADING_API_BASE` (or [`DEFAULT_BASE`]).
    pub fn new() -> DataClient {
        let base = std::env::var("TRADING_API_BASE").unwrap_or_else(|_| DEFAULT_BASE.to_string());
        DataClient::with_base(&base)
    }

    /// Create a client for an explicit base URL (no trailing slash).
    pub fn with_base(base: &str) -> DataClient {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .new_agent();
        DataClient {
            agent,
            base: base.trim_end_matches('/').to_string(),
            breaker: Arc::new(CircuitBreaker::new(
                env_u32("TRADING_BREAKER_THRESHOLD", 5),
                Duration::from_millis(env_u64("TRADING_BREAKER_TIMEOUT_MS", 30_000)),
            )),
        }
    }

    /// Current breaker health (for metrics/reporting).
    pub fn breaker_state(&self) -> BreakerState {
        self.breaker.state()
    }

    /// Fetch up to `limit` completed klines (Binance caps at 1000).
    ///
    /// `symbol` is an uppercase pair like `"BTCUSDT"`; `interval` is a
    /// Binance interval string like `"1m"`, `"5m"`, `"1h"`, `"1d"`.
    pub fn klines(&self, symbol: &str, interval: &str, limit: u32) -> Result<Vec<Bar>, DataError> {
        let max_attempts = 1 + env_u32("TRADING_MAX_RETRIES", 3);
        let base_ms = env_u64("TRADING_RETRY_BASE_MS", 250);
        let mut backoff = Backoff::new(Duration::from_millis(base_ms), Duration::from_secs(5));
        let m = global();

        let mut attempts = 0u32;
        loop {
            attempts += 1;
            match self
                .breaker
                .call(|| self.klines_once(symbol, interval, limit))
            {
                Ok(bars) => {
                    m.inc("trading_fetch_success_total", 1);
                    m.set_gauge(
                        "trading_breaker_state",
                        breaker_state_gauge(self.breaker.state()),
                    );
                    tracing::debug!(symbol, interval, bars = bars.len(), "klines fetched");
                    return Ok(bars);
                }
                Err(CircuitBreakerResult::Open(_)) => {
                    m.inc("trading_fetch_rejected_total", 1);
                    tracing::warn!(symbol, "circuit open; skipping fetch");
                    return Err(DataError::CircuitOpen);
                }
                Err(CircuitBreakerResult::Failure(e)) => {
                    m.inc("trading_fetch_error_total", 1);
                    m.set_gauge(
                        "trading_breaker_state",
                        breaker_state_gauge(self.breaker.state()),
                    );
                    if !e.is_transient() || attempts >= max_attempts {
                        return Err(e);
                    }
                    let delay = backoff.next_delay();
                    tracing::warn!(
                        error = %e, retry_in_ms = delay.as_millis() as u64,
                        "transient fetch failure; retrying"
                    );
                    std::thread::sleep(delay);
                }
            }
        }
    }

    /// The single network call, without retry/breaker wrapping.
    fn klines_once(&self, symbol: &str, interval: &str, limit: u32) -> Result<Vec<Bar>, DataError> {
        let url = format!(
            "{}/api/v3/klines?symbol={}&interval={}&limit={}",
            self.base, symbol, interval, limit
        );
        let resp = self
            .agent
            .get(&url)
            .call()
            .map_err(|e| DataError::Transport(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .into_body()
            .read_to_string()
            .map_err(|e| DataError::Transport(e.to_string()))?;
        if status != 200 {
            return Err(DataError::Http(
                status.into(),
                text.chars().take(512).collect(),
            ));
        }
        let rows: Vec<Value> = serde_json::from_str(&text).map_err(DataError::Json)?;
        rows.iter().map(kline_to_bar).collect()
    }
}

/// Map breaker health onto a gauge value for Prometheus: 0 closed, 1 half-open,
/// 2 open.
fn breaker_state_gauge(s: BreakerState) -> f64 {
    match s {
        BreakerState::Closed { .. } => 0.0,
        BreakerState::HalfOpen => 1.0,
        BreakerState::Open => 2.0,
    }
}

impl Default for DataClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert one Binance kline row to a [`Bar`].
///
/// Row layout: `[open_time, open, high, low, close, volume, close_time,
/// quote_volume, trades, …]` — prices and volume arrive as decimal strings.
fn kline_to_bar(row: &Value) -> Result<Bar, DataError> {
    let arr = row
        .as_array()
        .ok_or_else(|| DataError::Malformed("kline not an array".into()))?;
    let s = |i: usize| -> Result<f64, DataError> {
        arr.get(i)
            .and_then(Value::as_str)
            .ok_or_else(|| DataError::Malformed(format!("field {i} not a string")))?
            .parse()
            .map_err(|_| DataError::Malformed(format!("field {i} not a number")))
    };
    let open_time = arr
        .first()
        .and_then(Value::as_i64)
        .ok_or_else(|| DataError::Malformed("open_time missing".into()))?;
    Ok(Bar::new(open_time, s(1)?, s(2)?, s(3)?, s(4)?, s(5)?))
}

/// Persist a bar series as JSON (the offline store for reproducible backtests).
pub fn save_bars(path: &Path, bars: &[Bar]) -> Result<(), DataError> {
    let json = serde_json::to_string_pretty(bars)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Crash-safe variant of [`save_bars`] (roadmap Phase 5 "failure drills").
///
/// Writes to a unique temp file, `fsync`s it, then atomically `rename`s it
/// over the destination. A `kill -9` at any point leaves either the old file
/// or the new file on disk — never a truncated mix. (Atomic on POSIX; on
/// Windows the rename may not be fully atomic, but the temp-file discipline
/// still prevents partial writes to the destination.)
///
/// ```
/// use trading::bar::Bar;
/// use trading::data::save_bars_atomic;
/// let p = std::env::temp_dir().join("atomic-bars.json");
/// save_bars_atomic(&p, &[Bar::new(1, 10.0, 11.0, 9.0, 10.5, 3.0)]).unwrap();
/// std::fs::remove_file(&p).ok();
/// ```
pub fn save_bars_atomic(path: &Path, bars: &[Bar]) -> Result<(), DataError> {
    let json = serde_json::to_string_pretty(bars)?;
    let (tmp, mut file) = create_temp_file(path)?;
    use std::io::Write;
    file.write_all(json.as_bytes())?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp.path, path)?;
    tmp.keep();
    sync_parent(path)?;
    Ok(())
}

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn tmp_path(path: &Path, sequence: u64) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{}.{}", std::process::id(), sequence));
    path.with_file_name(name)
}

/// Removes an incomplete temp file on every error path. After a successful
/// rename, `keep` disarms the cleanup because the temp path no longer exists.
struct TempPath {
    path: PathBuf,
    armed: bool,
}

impl TempPath {
    fn keep(mut self) {
        self.armed = false;
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn create_temp_file(path: &Path) -> Result<(TempPath, std::fs::File), DataError> {
    loop {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let tmp = TempPath {
            path: tmp_path(path, sequence),
            armed: true,
        };
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp.path)
        {
            Ok(file) => return Ok((tmp, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), DataError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), DataError> {
    Ok(())
}

/// Load a bar series saved by [`save_bars`].
pub fn load_bars(path: &Path) -> Result<Vec<Bar>, DataError> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn kline_row_parses() {
        let row = json!([
            1786503600000i64,
            "63756.47",
            "63836.08",
            "63711.48",
            "63831.71",
            "0.29077",
            1786507199999i64,
            "18542.70",
            39
        ]);
        let b = kline_to_bar(&row).unwrap();
        assert_eq!(b.open_time, 1_786_503_600_000);
        assert_eq!(b.open, 63_756.47);
        assert_eq!(b.high, 63_836.08);
        assert_eq!(b.low, 63_711.48);
        assert_eq!(b.close, 63_831.71);
        assert_eq!(b.volume, 0.29077);
    }

    #[test]
    fn malformed_row_errors() {
        let row = json!(["not-a-number"]);
        assert!(kline_to_bar(&row).is_err());
        let row = json!(123);
        assert!(kline_to_bar(&row).is_err());
    }

    #[test]
    fn save_load_roundtrip() {
        let bars = vec![Bar::new(1, 10.0, 11.0, 9.0, 10.5, 3.0)];
        let path = std::env::temp_dir().join("trading-test-bars.json");
        save_bars(&path, &bars).unwrap();
        let loaded = load_bars(&path).unwrap();
        assert_eq!(loaded, bars);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn atomic_save_swaps_and_cleans_up() {
        let path = std::env::temp_dir().join("trading-test-atomic.json");
        let bars = vec![Bar::new(1, 10.0, 11.0, 9.0, 10.5, 3.0)];
        save_bars_atomic(&path, &bars).unwrap();
        assert_eq!(load_bars(&path).unwrap(), bars);
        std::fs::remove_file(&path).ok();
    }

    /// Failure drill: a `kill -9` mid-write leaves a half-written temp file.
    /// The destination must be untouched — either the old file or the new
    /// one, never a truncated mix.
    #[test]
    fn crash_mid_write_never_corrupts_destination() {
        let path = std::env::temp_dir().join("trading-test-crash.json");
        let old = vec![Bar::new(1, 10.0, 11.0, 9.0, 10.5, 3.0)];
        save_bars_atomic(&path, &old).unwrap();

        // Simulate a crash: someone wrote a partial file to the temp path
        // (as if the process died between create() and rename()), then the
        // process restarted and re-ran the save. The destination must still
        // hold the complete old bars.
        let tmp = tmp_path(&path, TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed));
        std::fs::write(&tmp, b"{\"partial\": [").unwrap(); // truncated JSON
        let new = vec![Bar::new(2, 20.0, 21.0, 19.0, 20.5, 6.0)];
        save_bars_atomic(&path, &new).unwrap();

        // After the successful save the destination is the new file, whole.
        assert_eq!(load_bars(&path).unwrap(), new);
        // A stale temp from a crashed writer neither blocks nor gets mistaken
        // for the current writer's file.
        assert!(tmp.exists());

        // Now simulate the crash *again* without the recovery save: a partial
        // temp must not have clobbered the destination (rename never ran).
        std::fs::write(&tmp, b"corrupt").unwrap();
        assert_eq!(
            load_bars(&path).unwrap(),
            new,
            "destination must not change without a rename"
        );

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn concurrent_atomic_saves_never_share_a_temp_file() {
        let path = Arc::new(std::env::temp_dir().join(format!(
            "trading-test-concurrent-{}.json",
            std::process::id()
        )));
        let candidates: Vec<Vec<Bar>> = (0..8)
            .map(|i| vec![Bar::new(i, i as f64, i as f64, i as f64, i as f64, 1.0)])
            .collect();
        let handles: Vec<_> = candidates
            .iter()
            .cloned()
            .map(|bars| {
                let path = Arc::clone(&path);
                std::thread::spawn(move || save_bars_atomic(&path, &bars).unwrap())
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        let saved = load_bars(&path).unwrap();
        assert!(
            candidates.contains(&saved),
            "destination must contain one complete write"
        );
        std::fs::remove_file(&*path).ok();
    }

    #[test]
    fn transient_error_classification() {
        assert!(DataError::Transport("conn reset".into()).is_transient());
        assert!(DataError::Http(503, "busy".into()).is_transient());
        assert!(!DataError::Http(400, "bad".into()).is_transient());
        assert!(!DataError::Malformed("nope".into()).is_transient());
    }
}
