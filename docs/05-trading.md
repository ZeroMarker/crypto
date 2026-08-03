# Phase 4 — Trading / analytics app

Not yet implemented. This phase uses the crypto plumbing for a market data,
backtesting, and execution stack.

## Architecture

```text
exchanges ──WS/HTTP──▶ market data feed ──▶ OHLCV aggregation
                                                │
                              indicators (ta) ◀─┘
                                                │
                         backtest engine ──▶ strategy
                                                │
                        execution/paper broker ◀┘
                                                │
                                        position & PnL ledger
```

## Suggested crate map

| Concern | Crate |
|---|---|
| HTTP/WS | `reqwest`, `tokio-tungstenite` |
| Time series | `sqlx` + Postgres, or `redb` for embedded |
| Indicators | `ta`, `candle` |
| Async | `tokio` |
| Logging | `tracing` |
| Config | `figment` / env vars |

## Building blocks

```rust
// Sketch: an OHLCV bar and a simple moving average.
#[derive(Clone)]
struct Bar { open: f64, high: f64, low: f64, close: f64, volume: f64 }

fn sma(closes: &[f64], period: usize) -> Option<f64> {
    if closes.len() < period { return None; }
    Some(closes[closes.len() - period..].iter().sum::<f64>() / period as f64)
}
```

## Paper-trading milestone

- Ingest live order books + trades from a sandbox exchange.
- Run a backtested strategy on real-time bars.
- Track positions and PnL without real capital.

## Done-when

- Backtests are reproducible (seeded RNG, recorded data).
- The paper bot runs a strategy live without crashing on reconnects.
- PnL, drawdown, and order fills are queryable.

## Next

[Phase 5 — Production hardening](06-hardening.md) makes it safe for real funds.
