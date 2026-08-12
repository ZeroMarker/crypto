//! OHLCV bars: the unit of market data, plus resampling and trade
//! aggregation.

use serde::{Deserialize, Serialize};

/// One OHLCV bar: open/high/low/close prices and volume for an interval.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Bar {
    /// Open time of the bar, milliseconds since the Unix epoch.
    pub open_time: i64,
    pub open: f64,
    pub high: f64,
    pub low: f64,
    pub close: f64,
    pub volume: f64,
}

impl Bar {
    pub fn new(open_time: i64, open: f64, high: f64, low: f64, close: f64, volume: f64) -> Bar {
        Bar {
            open_time,
            open,
            high,
            low,
            close,
            volume,
        }
    }
}

/// A single executed trade: timestamp, price and quantity.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Trade {
    pub time_ms: i64,
    pub price: f64,
    pub qty: f64,
}

/// Resample a bar series into larger intervals.
///
/// Bars are grouped by `open_time / interval_ms`; the group's `open_time`
/// becomes the bucket start, and within a bucket the open is the first bar's
/// open, the close is the last bar's close, high/low are the extremes and
/// volume is summed. `interval_ms` does not need to be an exact multiple of
/// the input interval — the bucket key is plain integer division — but inputs
/// should be ordered by time.
pub fn resample(bars: &[Bar], interval_ms: i64) -> Vec<Bar> {
    let mut out: Vec<Bar> = Vec::new();
    for bar in bars {
        let key = bar.open_time.div_euclid(interval_ms) * interval_ms;
        match out.last_mut() {
            Some(last) if last.open_time == key => {
                last.high = last.high.max(bar.high);
                last.low = last.low.min(bar.low);
                last.close = bar.close;
                last.volume += bar.volume;
            }
            _ => out.push(Bar {
                open_time: key,
                open: bar.open,
                high: bar.high,
                low: bar.low,
                close: bar.close,
                volume: bar.volume,
            }),
        }
    }
    out
}

/// Aggregate raw trades into fixed-interval bars (bucket = `time / interval_ms`).
/// Inputs need not be sorted; a copy is sorted by time first so a slow
/// exchange feed can't split one bucket into two.
pub fn aggregate_trades(trades: &[Trade], interval_ms: i64) -> Vec<Bar> {
    let mut trades: Vec<Trade> = trades.to_vec();
    trades.sort_by_key(|t| t.time_ms);
    let mut out: Vec<Bar> = Vec::new();
    for t in trades {
        let key = t.time_ms.div_euclid(interval_ms) * interval_ms;
        match out.last_mut() {
            Some(last) if last.open_time == key => {
                last.high = last.high.max(t.price);
                last.low = last.low.min(t.price);
                last.close = t.price;
                last.volume += t.qty;
            }
            _ => out.push(Bar {
                open_time: key,
                open: t.price,
                high: t.price,
                low: t.price,
                close: t.price,
                volume: t.qty,
            }),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bar(t: i64, o: f64, c: f64, v: f64) -> Bar {
        Bar::new(t, o, o.max(c), o.min(c), c, v)
    }

    #[test]
    fn resample_merges_consecutive_bars() {
        // Three 1-minute bars inside the same 3-minute bucket → one bar.
        let bars = vec![
            bar(60_000, 100.0, 102.0, 1.0),
            bar(120_000, 102.0, 99.0, 2.0),
            bar(150_000, 99.0, 105.0, 3.0),
        ];
        let merged = resample(&bars, 180_000);
        assert_eq!(merged.len(), 1);
        let b = merged[0];
        assert_eq!(b.open_time, 0);
        assert_eq!(b.open, 100.0);
        assert_eq!(b.high, 105.0);
        assert_eq!(b.low, 99.0);
        assert_eq!(b.close, 105.0);
        assert_eq!(b.volume, 6.0);
    }

    #[test]
    fn resample_preserves_bucket_boundaries() {
        // Start on a 5-minute boundary, so 10 one-minute bars → exactly 2 bars.
        let t0 = 1_699_999_800_000; // 5_666_666 × 300_000
        let bars: Vec<Bar> = (0..10)
            .map(|i| {
                let t = t0 + i * 60_000;
                bar(t, 100.0 + i as f64, 101.0 + i as f64, 1.0)
            })
            .collect();
        let merged = resample(&bars, 300_000);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].open_time, 1_699_999_800_000);
        assert_eq!(merged[1].open_time, 1_700_000_100_000);
        assert_eq!(merged[0].volume, 5.0);
        assert_eq!(merged[1].volume, 5.0);
    }

    #[test]
    fn aggregate_trades_buckets_by_time() {
        let trades = vec![
            Trade {
                time_ms: 1000,
                price: 10.0,
                qty: 1.0,
            },
            Trade {
                time_ms: 2500,
                price: 12.0,
                qty: 2.0,
            },
            Trade {
                time_ms: 1500,
                price: 11.0,
                qty: 3.0,
            },
            Trade {
                time_ms: 4500,
                price: 13.0,
                qty: 1.0,
            },
        ];
        // 2-second buckets: [0..2s) and [2..4s) — the 4.5s trade lands in a
        // third bucket by itself.
        let bars = aggregate_trades(&trades, 2000);
        assert_eq!(bars.len(), 3);
        assert_eq!(bars[0].open_time, 0);
        assert_eq!(bars[0].open, 10.0);
        assert_eq!(bars[0].close, 11.0);
        assert_eq!(bars[0].high, 11.0);
        assert_eq!(bars[0].low, 10.0);
        assert_eq!(bars[0].volume, 4.0);
        assert_eq!(bars[1].open_time, 2000);
        assert_eq!(bars[1].close, 12.0);
        assert_eq!(bars[2].open_time, 4000);
        assert_eq!(bars[2].close, 13.0);
    }
}
