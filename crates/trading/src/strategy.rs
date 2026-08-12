//! Strategies: the interface the backtester drives, plus teaching examples.
//!
//! A strategy is pure logic: it looks at a bar and the current context and
//! emits a [`Signal`]. It holds no cash and no positions — the broker does —
//! but it may keep internal state (e.g. previous indicator values). The
//! backtester calls `on_bar` once per bar, in order, and executes the signal
//! against the paper [`crate::broker::Broker`].

use crate::bar::Bar;

/// What the strategy wants to do on a bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Do nothing.
    Hold,
    /// Open (or add to) a long position.
    Buy,
    /// Close the long position.
    Sell,
}

/// Everything a strategy may look at when deciding on `bar`.
#[derive(Debug, Clone, Copy)]
pub struct StrategyContext<'a> {
    /// Index of the current bar in the series.
    pub bar_index: usize,
    /// Units held at the *start* of the bar.
    pub position: f64,
    /// Equity (cash + position × open) at the start of the bar.
    pub equity: f64,
    /// Closes of every bar seen so far, including this one.
    pub closes: &'a [f64],
}

pub trait Strategy {
    fn name(&self) -> &str;

    /// Decide what to do on `bar`. Called once per bar in chronological order.
    fn on_bar(&mut self, bar: &Bar, ctx: &StrategyContext) -> Signal;
}

/// Buy and hold: open a position on the first bar, never close it.
#[derive(Debug, Default)]
pub struct BuyAndHold;

impl Strategy for BuyAndHold {
    fn name(&self) -> &str {
        "buy-and-hold"
    }

    fn on_bar(&mut self, _bar: &Bar, ctx: &StrategyContext) -> Signal {
        if ctx.bar_index == 0 {
            Signal::Buy
        } else {
            Signal::Hold
        }
    }
}

/// Long-only SMA crossover ("golden cross" / "death cross").
///
/// Buys when the fast SMA crosses *above* the slow SMA and sells when it
/// crosses *below*. Trades are all-in / all-out; the backtester sizes the
/// position from equity and the risk limits.
#[derive(Debug, Clone)]
pub struct SmaCrossover {
    pub fast: usize,
    pub slow: usize,
    name: String,
    prev_fast: Option<f64>,
    prev_slow: Option<f64>,
}

impl SmaCrossover {
    pub fn new(fast: usize, slow: usize) -> SmaCrossover {
        assert!(fast > 0 && slow > fast, "need 0 < fast < slow");
        SmaCrossover {
            name: format!("sma-{fast}-{slow}"),
            fast,
            slow,
            prev_fast: None,
            prev_slow: None,
        }
    }
}

impl Strategy for SmaCrossover {
    fn name(&self) -> &str {
        &self.name
    }

    fn on_bar(&mut self, _bar: &Bar, ctx: &StrategyContext) -> Signal {
        let fast = crate::indicator::sma(ctx.closes, self.fast).pop().flatten();
        let slow = crate::indicator::sma(ctx.closes, self.slow).pop().flatten();
        let signal = match (fast, slow, self.prev_fast, self.prev_slow) {
            (Some(f), Some(s), Some(pf), Some(ps)) if ctx.position == 0.0 && f > s && pf <= ps => {
                Signal::Buy
            }
            (Some(f), Some(s), Some(pf), Some(ps)) if ctx.position > 0.0 && f < s && pf >= ps => {
                Signal::Sell
            }
            _ => Signal::Hold,
        };
        self.prev_fast = fast;
        self.prev_slow = slow;
        signal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(index: usize, position: f64, closes: &[f64]) -> StrategyContext<'_> {
        StrategyContext {
            bar_index: index,
            position,
            equity: 10_000.0,
            closes,
        }
    }

    #[test]
    fn buy_and_hold_buys_once() {
        let mut s = BuyAndHold;
        let bar = Bar::new(0, 10.0, 10.0, 10.0, 10.0, 0.0);
        assert_eq!(s.on_bar(&bar, &ctx(0, 0.0, &[10.0])), Signal::Buy);
        assert_eq!(s.on_bar(&bar, &ctx(1, 10.0, &[10.0, 10.0])), Signal::Hold);
    }

    #[test]
    fn sma_crossover_buys_on_golden_cross() {
        // Flat, then a sharp rise: the fast SMA crosses above the slow SMA.
        let mut s = SmaCrossover::new(2, 4);
        let closes: Vec<f64> = vec![10.0; 6]
            .into_iter()
            .chain((0..=8).map(|i| 10.0 + 2.0 * i as f64))
            .collect();
        let mut buy_seen = false;
        let mut position = 0.0;
        for i in 0..closes.len() {
            let bar = Bar::new(i as i64, closes[i], closes[i], closes[i], closes[i], 0.0);
            let sig = s.on_bar(&bar, &ctx(i, position, &closes[..=i]));
            match sig {
                Signal::Buy => {
                    buy_seen = true;
                    position = 1.0;
                }
                Signal::Sell => position = 0.0,
                Signal::Hold => {}
            }
        }
        assert!(
            buy_seen,
            "rise after a flat stretch must produce a golden cross"
        );
    }

    #[test]
    fn sma_crossover_sells_on_death_cross() {
        // Flat → rise → fall: expect a Buy then a Sell.
        let mut s = SmaCrossover::new(2, 4);
        let closes: Vec<f64> = vec![10.0; 6]
            .into_iter()
            .chain((0..=8).map(|i| 10.0 + 2.0 * i as f64)) // 10,12,…,26
            .chain((0..=8).map(|i| 26.0 - 2.0 * i as f64)) // 26,24,…,10
            .collect();
        let mut position = 0.0;
        let mut sell_seen = false;
        for i in 0..closes.len() {
            let bar = Bar::new(i as i64, closes[i], closes[i], closes[i], closes[i], 0.0);
            let sig = s.on_bar(&bar, &ctx(i, position, &closes[..=i]));
            match sig {
                Signal::Buy => position = 1.0,
                Signal::Sell => {
                    sell_seen = true;
                    position = 0.0;
                }
                Signal::Hold => {}
            }
        }
        assert!(sell_seen, "fall after a rise must produce a death cross");
    }
}
