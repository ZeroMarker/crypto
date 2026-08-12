# Phase 4 — Trading / analytics app

Implemented in `crates/trading` (M3 done). A market data, backtesting and
paper-trading stack, teaching-grade and dependency-light (blocking HTTPS,
no async runtime).

## Architecture

```text
exchanges ──HTTPS──▶ [data] klines ──▶ [bar] OHLCV series
                                              │
                              [indicator] ◀───┘  (sma / ema / rsi)
                                              │
                    [strategy] ──▶ [backtest] ──▶ [broker] fills
                                              │
                                     [risk] position & stop-loss limits
                                              │
                                     [report] equity curve & metrics
```

## Module map (`crates/trading/src/`)

| Module | Concern |
|---|---|
| `data.rs` | Binance-style klines over HTTPS (`DataClient`), JSON save/load |
| `bar.rs` | `Bar` OHLCV, resampling, trade aggregation |
| `indicator.rs` | SMA, EMA, RSI (Wilder) — aligned `Option`-padded vectors |
| `strategy.rs` | `Strategy` trait, `SmaCrossover`, `BuyAndHold` |
| `backtest.rs` | event-driven loop: stop-loss at open, signal at close, equity curve, max drawdown, annualized Sharpe |
| `broker.rs` | paper broker: fees, slippage, average-cost basis, realized PnL |
| `risk.rs` | max position fraction, stop-loss trigger |
| `report.rs` | metrics + sparkline equity curve |
| `bin/trade.rs` | CLI: `fetch`, `backtest`, `live` |

## CLI

```bash
# Fetch and cache klines (offline backtests are reproducible)
trade fetch BTCUSDT 1h 500 --out btc.json

# Backtest the SMA crossover (fast 10 / slow 30) on cached data
trade backtest --data btc.json --fast 10 --slow 30 --cash 10000

# Or backtest straight from the exchange
trade backtest --symbol BTCUSDT --interval 1h --limit 500

# Paper-trade live: poll, act on each completed bar, print the account
trade live BTCUSDT 1h --fast 10 --slow 30 --cash 10000
```

Market data defaults to `https://api.binance.us` (the `api.binance.com`
endpoint is geo-restricted from some networks); set `TRADING_API_BASE` to
point at any Binance-compatible klines mirror.

## Design notes

- **Fills** happen at the bar close with a flat fee + slippage; buys execute
  at `price × (1 + slippage)`, sells at `price × (1 − slippage)`.
- **Positions** are fractional (exchanges trade decimals, not whole coins),
  sized by `equity × max_position_frac / price`.
- **Risk** runs before the strategy each bar: the stop-loss is checked at the
  bar *open* so a gap can't slip past yesterday's close.
- **Reproducibility**: backtests are pure functions of (bars, config) — no
  randomness. `trade fetch --out` saves the input for later replay.
- Prices and cash are `f64`: this is analysis-grade plumbing, not accounting;
  Phase 5 hardening covers what a real-money system needs (exact integer
  amounts, rate limiting, audits, fault drills).

## Done-when (roadmap)

- Backtests are reproducible (recorded data, no RNG). ✅
- The paper bot runs a strategy live without crashing on reconnects
  (`trade live` polls with retry/backoff). ✅
- PnL, drawdown, and order fills are queryable (report metrics + broker
  `fills()`). ✅

## Next

[Phase 5 — Production hardening](06-hardening.md) makes it safe for real funds:
secret handling, `cargo audit`/fuzzing, `tracing` observability, resilience
drills.
