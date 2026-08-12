//! Human-readable reporting for backtests: metrics plus a sparkline equity
//! curve, all dependency-free.

use crate::backtest::BacktestReport;

/// Render a `width`-character sparkline of `values` (min–max scaled).
pub fn sparkline(values: &[f64], width: usize) -> String {
    if values.is_empty() || width == 0 {
        return String::new();
    }
    let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let range = (max - min).max(f64::EPSILON);
    const BARS: &[char] = &['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    // Sample `width` evenly spaced points (last point included).
    let n = values.len();
    let mut out = String::with_capacity(width);
    for i in 0..width {
        let idx = if width == 1 {
            n - 1
        } else {
            (i * (n - 1)) / (width - 1)
        };
        let t = ((values[idx] - min) / range * (BARS.len() - 1) as f64).round() as usize;
        out.push(BARS[t.min(BARS.len() - 1)]);
    }
    out
}

/// Format a full backtest report as a printable block.
pub fn format_report(
    report: &BacktestReport,
    strategy_name: &str,
    symbol: &str,
    interval: &str,
) -> String {
    let pct = |x: f64| format!("{:.2}%", x * 100.0);
    let mut out = String::new();
    out.push_str(&format!(
        "strategy   : {strategy_name}\nsymbol     : {symbol}\ninterval   : {interval}\n\n"
    ));
    out.push_str(&format!("initial cash : {:>12.2}\n", report.initial_cash));
    out.push_str(&format!("final equity : {:>12.2}\n", report.final_equity));
    out.push_str(&format!(
        "total return : {:>12}\n",
        pct(report.total_return)
    ));
    out.push_str(&format!(
        "max drawdown : {:>12}\n",
        pct(report.max_drawdown)
    ));
    out.push_str(&format!("round trips  : {:>12}\n", report.num_trades));
    out.push_str(&format!(
        "win rate     : {:>12}\n",
        if report.num_trades == 0 {
            "n/a".to_string()
        } else {
            pct(report.win_rate)
        }
    ));
    out.push_str(&format!("sharpe (ann.) : {:>12.2}\n", report.sharpe));
    out.push_str(&format!(
        "\nequity curve ({} bars):\n{}\n",
        report.equity_curve.len(),
        sparkline(&report.equity_curve, 64)
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparkline_scales() {
        let s = sparkline(&[0.0, 100.0], 2);
        assert_eq!(s.chars().count(), 2);
        assert_eq!(s.chars().next(), Some('▁'));
        assert_eq!(s.chars().last(), Some('█'));
        assert_eq!(sparkline(&[], 10), "");
    }

    #[test]
    fn sparkline_flat_line() {
        let s = sparkline(&[5.0, 5.0, 5.0], 3);
        assert_eq!(s.chars().count(), 3);
        assert!(s.chars().all(|c| c == '▁' || c == '█' || c == '▄'));
    }
}
