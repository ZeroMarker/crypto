//! Technical indicators, teaching-grade and dependency-free.
//!
//! Every indicator returns a vector aligned with its input: entries before
//! enough data exists are `None`. Values are `f64`; prices are floats because
//! indicators are *analysis*, not accounting (the broker keeps cash in `f64`
//! too — this is a teaching project, see the crate docs).

/// Simple moving average: mean of the last `period` values.
///
/// The output has `period - 1` leading `None`s.
pub fn sma(values: &[f64], period: usize) -> Vec<Option<f64>> {
    if period == 0 {
        return vec![None; values.len()];
    }
    let mut sum = 0.0;
    let mut out = Vec::with_capacity(values.len());
    for (i, &v) in values.iter().enumerate() {
        sum += v;
        if i >= period {
            sum -= values[i - period];
        }
        out.push((i + 1 >= period).then(|| sum / period as f64));
    }
    out
}

/// Exponential moving average: weighted toward recent values.
///
/// Seeded with the SMA of the first `period` values, then
/// `ema[i] = ema[i-1] + k * (value[i] - ema[i-1])` with `k = 2/(period+1)`.
/// The output has `period - 1` leading `None`s.
pub fn ema(values: &[f64], period: usize) -> Vec<Option<f64>> {
    if period == 0 {
        return vec![None; values.len()];
    }
    let k = 2.0 / (period as f64 + 1.0);
    let mut out: Vec<Option<f64>> = vec![None; values.len()];
    if values.len() < period {
        return out;
    }
    let seed: f64 = values[..period].iter().sum::<f64>() / period as f64;
    out[period - 1] = Some(seed);
    let mut prev = seed;
    for (i, &v) in values.iter().enumerate().skip(period) {
        prev += k * (v - prev);
        out[i] = Some(prev);
    }
    out
}

/// Relative Strength Index (Wilder's smoothing).
///
/// `rsi[i]` measures the speed of recent gains versus losses, scaled to
/// 0–100. Reads ≥ 70 are classically "overbought", ≤ 30 "oversold". The
/// output has `period` leading `None`s (we need `period + 1` closes).
pub fn rsi(closes: &[f64], period: usize) -> Vec<Option<f64>> {
    let mut out = vec![None; closes.len()];
    if period == 0 || closes.len() <= period {
        return out;
    }
    let mut avg_gain = 0.0;
    let mut avg_loss = 0.0;
    for i in 1..=period {
        let delta = closes[i] - closes[i - 1];
        if delta > 0.0 {
            avg_gain += delta;
        } else {
            avg_loss -= delta;
        }
    }
    avg_gain /= period as f64;
    avg_loss /= period as f64;

    let r = |gain: f64, loss: f64| -> f64 {
        if loss == 0.0 {
            return 100.0;
        }
        100.0 - 100.0 / (1.0 + gain / loss)
    };
    out[period] = Some(r(avg_gain, avg_loss));
    for i in (period + 1)..closes.len() {
        let delta = closes[i] - closes[i - 1];
        avg_gain = (avg_gain * (period as f64 - 1.0) + delta.max(0.0)) / period as f64;
        avg_loss = (avg_loss * (period as f64 - 1.0) + (-delta).max(0.0)) / period as f64;
        out[i] = Some(r(avg_gain, avg_loss));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unwrap(v: &[Option<f64>]) -> Vec<f64> {
        v.iter().map(|o| o.unwrap()).collect()
    }

    #[test]
    fn sma_hand_computed() {
        let v = [1.0, 2.0, 3.0, 4.0, 5.0];
        let s = sma(&v, 3);
        assert_eq!(s[0], None);
        assert_eq!(s[1], None);
        assert_eq!(unwrap(&s[2..]), vec![2.0, 3.0, 4.0]);
    }

    #[test]
    fn ema_converges_to_mean() {
        let v = [5.0; 10];
        let e = ema(&v, 3);
        assert_eq!(e[2], Some(5.0));
        assert_eq!(e[9], Some(5.0));
    }

    #[test]
    fn ema_respects_recent_values() {
        // Constant series then a jump: EMA should move toward the new level.
        let mut v = vec![10.0; 10];
        v.push(20.0);
        let e = ema(&v, 3);
        let before = e[9].unwrap();
        let after = e[10].unwrap();
        assert!(after > before);
        assert!(after < 20.0);
    }

    #[test]
    fn rsi_all_gains_is_100() {
        let v: Vec<f64> = (0..20).map(|i| i as f64).collect();
        let r = rsi(&v, 14);
        assert_eq!(r[14], Some(100.0));
        assert_eq!(r[19], Some(100.0));
    }

    #[test]
    fn rsi_all_losses_is_0() {
        let v: Vec<f64> = (0..20).map(|i| (20 - i) as f64).collect();
        let r = rsi(&v, 14);
        assert_eq!(r[14], Some(0.0));
    }

    #[test]
    fn rsi_alternating_is_50() {
        // Equal gains and losses → RS = 1 → RSI = 50. Wilder's smoothing then
        // oscillates tightly around 50 instead of staying exactly there.
        let mut v = vec![100.0];
        for i in 0..30 {
            let prev = *v.last().unwrap();
            v.push(prev + if i % 2 == 0 { 1.0 } else { -1.0 });
        }
        let r = rsi(&v, 14);
        assert_eq!(r[14], Some(50.0)); // seed point: simple average of the first 14 deltas
        for val in r.iter().flatten() {
            assert!(
                (40.0..60.0).contains(val),
                "rsi {val} drifted outside the 40..60 band"
            );
        }
    }
}
