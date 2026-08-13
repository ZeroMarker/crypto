//! Trading / analytics: market data, OHLCV, indicators, backtesting and a
//! paper broker (roadmap Phase 4).
//!
//! The pipeline mirrors the real shape of a quant stack:
//!
//! ```text
//! exchanges ──HTTPS──▶ [data] klines ──▶ [bar] OHLCV series
//!                                              │
//!                              [indicator] ◀───┘  (sma / ema / rsi)
//!                                              │
//!                    [strategy] ──▶ [backtest] ──▶ [broker] fills
//!                                              │
//!                                     [risk] position & stop-loss limits
//!                                              │
//!                                     [report] equity curve & metrics
//! ```
//!
//! Everything is teaching-grade: prices are `f64`, fills happen at bar
//! closes with a flat fee and slippage, and there is no live order routing —
//! the [`broker`] is a paper broker. Tests use synthetic data and never hit
//! the network; only the `trade` binary in `src/bin/` talks to an exchange.
//!
//! ## Example
//!
//! ```no_run
//! use trading::bar::Bar;
//! use trading::backtest::{run, BacktestConfig};
//! use trading::broker::BrokerConfig;
//! use trading::risk::RiskConfig;
//! use trading::strategy::SmaCrossover;
//!
//! let bars: Vec<Bar> = Vec::new(); // e.g. trading::data::DataClient::new().klines("BTCUSDT", "1h", 500)?
//! let mut strategy = SmaCrossover::new(10, 30);
//! let cfg = BacktestConfig {
//!     broker: BrokerConfig::new(10_000.0),
//!     risk: RiskConfig::default(),
//! };
//! let report = run(&bars, &mut strategy, &cfg);
//! println!("{}", report.total_return);
//! ```

pub mod backtest;
pub mod bar;
pub mod broker;
pub mod data;
pub mod indicator;
pub mod report;
pub mod resilience;
pub mod risk;
pub mod strategy;
pub mod telemetry;

pub use backtest::{run, BacktestConfig, BacktestReport};
pub use bar::{aggregate_trades, resample, Bar, Trade};
pub use broker::{Broker, BrokerConfig, BrokerError, Fill, Side};
pub use indicator::{ema, rsi, sma};
pub use resilience::{
    retry_with_backoff, Backoff, BreakerState, CircuitBreaker, CircuitBreakerResult, CircuitOpen,
};
pub use risk::{max_position_units, stop_hit, RiskConfig};
pub use strategy::{BuyAndHold, Signal, SmaCrossover, Strategy, StrategyContext};
pub use telemetry::{global, init_logging, Metrics};
