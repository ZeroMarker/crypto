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

use std::path::Path;
use std::time::Duration;

use serde_json::Value;

use crate::bar::Bar;

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
}

/// A blocking klines client.
#[derive(Debug, Clone)]
pub struct DataClient {
    agent: ureq::Agent,
    base: String,
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
        }
    }

    /// Fetch up to `limit` completed klines (Binance caps at 1000).
    ///
    /// `symbol` is an uppercase pair like `"BTCUSDT"`; `interval` is a
    /// Binance interval string like `"1m"`, `"5m"`, `"1h"`, `"1d"`.
    pub fn klines(&self, symbol: &str, interval: &str, limit: u32) -> Result<Vec<Bar>, DataError> {
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
}
