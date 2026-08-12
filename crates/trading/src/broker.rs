//! Paper broker: turns strategy signals into fills at bar prices.
//!
//! Orders fill immediately at the bar close, adjusted by a flat fee rate and
//! a slippage fraction — buys execute at `price × (1 + slippage)`, sells at
//! `price × (1 − slippage)`. Positions use average-cost basis for realized
//! PnL. There is no order queue, no partial fills and no shorting: this is a
//! teaching-grade simulator, not an exchange adapter.

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("insufficient cash: need {need:.2}, have {have:.2}")]
    InsufficientCash { need: f64, have: f64 },
    #[error("insufficient position: want {want:.4}, have {have:.4}")]
    InsufficientPosition { want: f64, have: f64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Side {
    Buy,
    Sell,
}

/// One executed fill.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Fill {
    pub bar_index: usize,
    pub side: Side,
    /// Execution price (already adjusted for slippage).
    pub price: f64,
    pub qty: f64,
    pub fee: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerConfig {
    pub initial_cash: f64,
    /// Fraction of notional charged as fee per fill (both sides).
    pub fee_rate: f64,
    /// Fraction added to buys / subtracted from sells.
    pub slippage: f64,
}

impl BrokerConfig {
    pub fn new(initial_cash: f64) -> BrokerConfig {
        BrokerConfig {
            initial_cash,
            fee_rate: 0.001,
            slippage: 0.0005,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Broker {
    cfg: BrokerConfig,
    cash: f64,
    position: f64,
    avg_cost: f64,
    realized_pnl: f64,
    fills: Vec<Fill>,
}

impl Broker {
    pub fn new(cfg: BrokerConfig) -> Broker {
        Broker {
            cash: cfg.initial_cash,
            position: 0.0,
            avg_cost: 0.0,
            realized_pnl: 0.0,
            fills: Vec::new(),
            cfg,
        }
    }

    pub fn cash(&self) -> f64 {
        self.cash
    }
    pub fn position(&self) -> f64 {
        self.position
    }
    pub fn realized_pnl(&self) -> f64 {
        self.realized_pnl
    }
    pub fn fills(&self) -> &[Fill] {
        &self.fills
    }

    /// Equity marked at `price`.
    pub fn equity(&self, price: f64) -> f64 {
        self.cash + self.position * price
    }

    /// Buy `qty` units at `price`. Returns the cost including fee.
    pub fn market_buy(
        &mut self,
        bar_index: usize,
        price: f64,
        qty: f64,
    ) -> Result<f64, BrokerError> {
        if qty <= 0.0 {
            return Ok(0.0);
        }
        let exec = price * (1.0 + self.cfg.slippage);
        let gross = exec * qty;
        let fee = gross * self.cfg.fee_rate;
        let total = gross + fee;
        if total > self.cash {
            return Err(BrokerError::InsufficientCash {
                need: total,
                have: self.cash,
            });
        }
        self.cash -= total;
        self.avg_cost = (self.avg_cost * self.position + gross + fee) / (self.position + qty);
        self.position += qty;
        self.fills.push(Fill {
            bar_index,
            side: Side::Buy,
            price: exec,
            qty,
            fee,
        });
        Ok(total)
    }

    /// Sell `qty` units at `price`. Returns the realized PnL of this fill.
    pub fn market_sell(
        &mut self,
        bar_index: usize,
        price: f64,
        qty: f64,
    ) -> Result<f64, BrokerError> {
        if qty <= 0.0 {
            return Ok(0.0);
        }
        if qty > self.position {
            return Err(BrokerError::InsufficientPosition {
                want: qty,
                have: self.position,
            });
        }
        let exec = price * (1.0 - self.cfg.slippage);
        let gross = exec * qty;
        let fee = gross * self.cfg.fee_rate;
        let pnl = (exec - self.avg_cost) * qty - fee;
        self.cash += gross - fee;
        self.realized_pnl += pnl;
        self.position -= qty;
        if self.position.abs() < 1e-12 {
            self.avg_cost = 0.0;
        }
        self.fills.push(Fill {
            bar_index,
            side: Side::Sell,
            price: exec,
            qty,
            fee,
        });
        Ok(pnl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buy_sell_round_trip_pnl() {
        let cfg = BrokerConfig {
            initial_cash: 10_000.0,
            fee_rate: 0.0,
            slippage: 0.0,
        };
        let mut b = Broker::new(cfg);
        b.market_buy(0, 100.0, 10.0).unwrap();
        assert_eq!(b.position(), 10.0);
        assert_eq!(b.cash(), 9_000.0);
        assert_eq!(b.equity(100.0), 10_000.0);
        // Sell at 110 → +10/unit → +100 PnL.
        let pnl = b.market_sell(1, 110.0, 10.0).unwrap();
        assert!((pnl - 100.0).abs() < 1e-9);
        assert_eq!(b.position(), 0.0);
        assert_eq!(b.cash(), 10_100.0);
    }

    #[test]
    fn fees_and_slippage_apply() {
        let cfg = BrokerConfig {
            initial_cash: 2_000.0,
            fee_rate: 0.01,
            slippage: 0.01,
        };
        let mut b = Broker::new(cfg);
        // Buy at 100 with 1% slippage → exec 101; fee 1% of 1010 = 10.1 → cash 979.9.
        b.market_buy(0, 100.0, 10.0).unwrap();
        assert!((b.cash() - 979.9).abs() < 1e-9);
        let fill = b.fills()[0];
        assert!((fill.price - 101.0).abs() < 1e-9);
        assert!((fill.fee - 10.1).abs() < 1e-9);
        // Sell at 100 with 1% slippage → exec 99; fee 0.99 → net 980.1.
        // avg_cost = (1010 + 10.1) / 10 = 102.01 → pnl = (99 − 102.01)·10 − 0.99 = −40.
        let pnl = b.market_sell(1, 100.0, 10.0).unwrap();
        assert!((pnl + 40.0).abs() < 1e-9);
        assert!((b.cash() - 1_960.0).abs() < 1e-9);
    }

    #[test]
    fn insufficient_cash_rejected() {
        let cfg = BrokerConfig {
            initial_cash: 100.0,
            fee_rate: 0.0,
            slippage: 0.0,
        };
        let mut b = Broker::new(cfg);
        assert!(matches!(
            b.market_buy(0, 100.0, 2.0),
            Err(BrokerError::InsufficientCash { .. })
        ));
        assert_eq!(b.position(), 0.0);
    }

    #[test]
    fn oversell_rejected() {
        let cfg = BrokerConfig {
            initial_cash: 1_000.0,
            fee_rate: 0.0,
            slippage: 0.0,
        };
        let mut b = Broker::new(cfg);
        b.market_buy(0, 10.0, 5.0).unwrap();
        assert!(matches!(
            b.market_sell(1, 11.0, 6.0),
            Err(BrokerError::InsufficientPosition { .. })
        ));
    }
}
