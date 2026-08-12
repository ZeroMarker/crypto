//! Risk controls enforced during a backtest: position sizing and stop-loss.
//!
//! Two simple, auditable rules (roadmap Phase 4 "Risk controls"):
//!
//! 1. **Max position** — never deploy more than `max_position_frac` of
//!    current equity into a single position.
//! 2. **Stop-loss** — force-close the position when the price has fallen
//!    `stop_loss_pct` below the entry price.
//!
//! A real system would add rate limiting, max drawdown circuit breakers and
//! per-order kill switches; those are listed under Phase 5 hardening.

/// Risk parameters for a backtest (or paper session).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RiskConfig {
    /// Fraction of equity a single position may consume at entry.
    pub max_position_frac: f64,
    /// Force-close when unrealized loss from entry exceeds this fraction.
    pub stop_loss_pct: f64,
}

impl Default for RiskConfig {
    fn default() -> RiskConfig {
        RiskConfig {
            max_position_frac: 0.95,
            stop_loss_pct: 0.10,
        }
    }
}

/// Largest position (in units) affordable given `equity` and `price` under
/// the max-position fraction. Returns an exact fractional quantity (exchanges
/// trade in decimals, not whole coins).
pub fn max_position_units(equity: f64, price: f64, max_position_frac: f64) -> f64 {
    if price <= 0.0 || equity <= 0.0 || max_position_frac <= 0.0 {
        return 0.0;
    }
    equity * max_position_frac / price
}

/// True when `current` has fallen more than `stop_loss_pct` below `entry`.
pub fn stop_hit(entry_price: f64, current_price: f64, stop_loss_pct: f64) -> bool {
    entry_price > 0.0 && current_price <= entry_price * (1.0 - stop_loss_pct)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn position_units_fractional() {
        assert_eq!(max_position_units(10_000.0, 100.0, 0.95), 95.0);
        assert_eq!(max_position_units(10_000.0, 3.0, 0.5), 1_666.6666666666667);
        // High-priced asset: fractional units, not zero.
        assert!((max_position_units(10_000.0, 63_000.0, 0.95) - 0.15079).abs() < 1e-4);
        assert_eq!(max_position_units(0.0, 100.0, 0.95), 0.0);
    }

    #[test]
    fn stop_hit_boundary() {
        assert!(!stop_hit(100.0, 90.01, 0.10)); // above the stop level → no trigger
        assert!(stop_hit(100.0, 90.0, 0.10)); // at or below the stop level → trigger
        assert!(stop_hit(100.0, 89.99, 0.10));
        assert!(!stop_hit(100.0, 110.0, 0.10));
    }
}
