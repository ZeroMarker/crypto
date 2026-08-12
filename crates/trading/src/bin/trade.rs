//! `trade` — market data, backtesting and paper trading from the command
//! line (roadmap Phase 4 "Dashboard/CLI").
//!
//! Subcommands:
//!
//! ```text
//! trade fetch <SYMBOL> <INTERVAL> <LIMIT> [--out FILE.json]
//! trade backtest [--data FILE.json | --symbol BTCUSDT --interval 1h --limit 500]
//!                [--fast N] [--slow N] [--cash X] [--fee R] [--slippage R]
//!                [--stop R] [--maxpos R]
//! trade live <SYMBOL> <INTERVAL> [--fast N] [--slow N] [--cash X]
//! ```
//!
//! Market data comes from the Binance-style klines API (see
//! [`trading::data`]); point `TRADING_API_BASE` elsewhere to use a mirror.
//! `backtest --data` is fully offline and reproducible.

use std::path::PathBuf;

use trading::backtest::{run, BacktestConfig};
use trading::broker::BrokerConfig;
use trading::data::{load_bars, save_bars, DataClient};
use trading::report::format_report;
use trading::risk::RiskConfig;
use trading::strategy::{SmaCrossover, Strategy};

fn usage() -> ! {
    eprintln!(
        "usage:\n  trade fetch <SYMBOL> <INTERVAL> <LIMIT> [--out FILE.json]\n  \
         trade backtest [--data FILE.json | --symbol S --interval I --limit N] [--fast N] [--slow N] \
         [--cash X] [--fee R] [--slippage R] [--stop R] [--maxpos R]\n  \
         trade live <SYMBOL> <INTERVAL> [--fast N] [--slow N] [--cash X]"
    );
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    match args[0].as_str() {
        "fetch" => cmd_fetch(&args[1..]),
        "backtest" => cmd_backtest(&args[1..]),
        "live" => cmd_live(&args[1..]),
        _ => usage(),
    }
}

/// Parse `--key value` pairs into a map.
fn flags(args: &[String]) -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    let mut it = args.iter();
    while let Some(k) = it.next() {
        if let Some(name) = k.strip_prefix("--") {
            let value = it.next().cloned().unwrap_or_default();
            m.insert(name.to_string(), value);
        }
    }
    m
}

fn get<'a>(m: &'a std::collections::HashMap<String, String>, key: &str) -> Option<&'a str> {
    m.get(key).map(|s| s.as_str())
}

fn parse_f64(m: &std::collections::HashMap<String, String>, key: &str, default: f64) -> f64 {
    get(m, key).and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn parse_usize(m: &std::collections::HashMap<String, String>, key: &str, default: usize) -> usize {
    get(m, key).and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn cmd_fetch(args: &[String]) {
    if args.len() < 3 {
        usage();
    }
    let symbol = args[0].to_uppercase();
    let interval = args[1].clone();
    let limit: u32 = args[2].parse().unwrap_or(500);
    let out = args
        .iter()
        .position(|a| a == "--out")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from);

    let client = DataClient::new();
    match client.klines(&symbol, &interval, limit) {
        Ok(bars) => match &out {
            Some(path) => {
                save_bars(path, &bars).expect("save bars");
                println!("saved {} bars to {}", bars.len(), path.display());
            }
            None => {
                let first = bars.first().map(|b| b.open_time).unwrap_or(0);
                let last = bars.last().map(|b| b.open_time).unwrap_or(0);
                println!(
                    "fetched {} {interval} bars for {symbol} ({first}..{last})",
                    bars.len()
                );
            }
        },
        Err(e) => {
            eprintln!("fetch failed: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_backtest(args: &[String]) {
    let m = flags(args);
    let symbol = get(&m, "symbol").unwrap_or("BTCUSDT").to_string();
    let interval = get(&m, "interval").unwrap_or("1h").to_string();

    let bars = match get(&m, "data") {
        Some(path) => load_bars(PathBuf::from(path).as_path()).expect("load bars"),
        None => {
            let limit: u32 = parse_usize(&m, "limit", 500) as u32;
            DataClient::new()
                .klines(&symbol, &interval, limit)
                .expect("fetch bars")
        }
    };
    if bars.len() < 2 {
        eprintln!("need at least 2 bars, got {}", bars.len());
        std::process::exit(1);
    }

    let fast = parse_usize(&m, "fast", 10);
    let slow = parse_usize(&m, "slow", 30);
    if slow <= fast {
        eprintln!("--slow must be greater than --fast");
        std::process::exit(2);
    }
    let cfg = BacktestConfig {
        broker: BrokerConfig {
            initial_cash: parse_f64(&m, "cash", 10_000.0),
            fee_rate: parse_f64(&m, "fee", 0.001),
            slippage: parse_f64(&m, "slippage", 0.0005),
        },
        risk: RiskConfig {
            max_position_frac: parse_f64(&m, "maxpos", 0.95),
            stop_loss_pct: parse_f64(&m, "stop", 0.10),
        },
    };

    let mut strategy = SmaCrossover::new(fast, slow);
    let report = run(&bars, &mut strategy, &cfg);
    print!(
        "{}",
        format_report(&report, strategy.name(), &symbol, &interval)
    );
}

/// Poll the exchange, drive the SMA strategy on each newly completed bar and
/// print the paper account state. Ctrl-C stops the loop.
fn cmd_live(args: &[String]) {
    if args.len() < 2 {
        usage();
    }
    let symbol = args[0].to_uppercase();
    let interval = args[1].clone();
    let m = flags(&args[2..]);
    let fast = parse_usize(&m, "fast", 10);
    let slow = parse_usize(&m, "slow", 30);
    let cash = parse_f64(&m, "cash", 10_000.0);
    let poll_secs = interval_seconds(&interval).max(5);

    let client = DataClient::new();
    let mut strategy = SmaCrossover::new(fast, slow);
    let mut broker = trading::broker::Broker::new(BrokerConfig::new(cash));
    let mut closes: Vec<f64> = Vec::new();
    let mut last_time: i64 = 0;
    let limit: u32 = (slow + 100).max(200) as u32;
    let mut entry_price: Option<f64> = None;

    println!("paper trading {symbol} {interval} (sma {fast}/{slow}) — Ctrl-C to stop");
    loop {
        match client.klines(&symbol, &interval, limit) {
            Ok(bars) => {
                // The last kline is the in-progress bar; act only on completed ones.
                let completed = bars.len().saturating_sub(1);
                for bar in &bars[..completed] {
                    if bar.open_time <= last_time {
                        continue;
                    }
                    last_time = bar.open_time;
                    closes.push(bar.close);

                    // Stop-loss at the bar open.
                    if let (Some(entry), true) = (entry_price, broker.position() > 0.0) {
                        if trading::risk::stop_hit(entry, bar.open, 0.10) {
                            broker
                                .market_sell(usize::MAX, bar.open, broker.position())
                                .ok();
                            entry_price = None;
                            println!("  stop-loss hit at {:.2}", bar.open);
                        }
                    }

                    let idx = closes.len() - 1;
                    let ctx = trading::strategy::StrategyContext {
                        bar_index: idx,
                        position: broker.position(),
                        equity: broker.equity(bar.open),
                        closes: &closes,
                    };
                    match strategy.on_bar(bar, &ctx) {
                        trading::strategy::Signal::Buy if broker.position() == 0.0 => {
                            let qty = trading::risk::max_position_units(
                                broker.equity(bar.close),
                                bar.close,
                                0.95,
                            );
                            if qty > 0.0 && broker.market_buy(idx, bar.close, qty).is_ok() {
                                entry_price = Some(bar.close);
                                println!("  BUY  {qty:.4} @ {:.2}", bar.close);
                            }
                        }
                        trading::strategy::Signal::Sell if broker.position() > 0.0 => {
                            let qty = broker.position();
                            broker.market_sell(idx, bar.close, qty).ok();
                            entry_price = None;
                            println!("  SELL {qty:.4} @ {:.2}", bar.close);
                        }
                        _ => {}
                    }
                }
                println!(
                    "[{}] equity={:.2} cash={:.2} pos={:.4} realized={:.2}",
                    format_time(bars.last().map(|b| b.open_time).unwrap_or(0)),
                    broker.equity(bars.last().map(|b| b.close).unwrap_or(0.0)),
                    broker.cash(),
                    broker.position(),
                    broker.realized_pnl(),
                );
            }
            Err(e) => eprintln!("fetch failed: {e} — retrying in {poll_secs}s"),
        }
        std::thread::sleep(std::time::Duration::from_secs(poll_secs));
    }
}

/// "1m" → 60, "5m" → 300, "1h" → 3600, "1d" → 86400.
fn interval_seconds(interval: &str) -> u64 {
    let (num, unit) = interval.split_at(interval.len() - 1);
    let n: u64 = num.parse().unwrap_or(1);
    match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => n * 60,
    }
}

/// Format a millis epoch as YYYY-MM-DD HH:MM (UTC), using the
/// civil-from-days algorithm (no external date dependency).
fn format_time(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hh, mm) = (rem / 3600, (rem % 3600) / 60);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_parsing() {
        assert_eq!(interval_seconds("1m"), 60);
        assert_eq!(interval_seconds("5m"), 300);
        assert_eq!(interval_seconds("1h"), 3600);
        assert_eq!(interval_seconds("1d"), 86_400);
    }

    #[test]
    fn flags_parsing() {
        let args: Vec<String> = vec![
            "--fast".into(),
            "5".into(),
            "--cash".into(),
            "1234.5".into(),
        ];
        let m = flags(&args);
        assert_eq!(get(&m, "fast"), Some("5"));
        assert_eq!(get(&m, "cash"), Some("1234.5"));
        assert_eq!(get(&m, "nope"), None);
    }

    #[test]
    fn time_formatting() {
        // 2026-08-12 00:00:00 UTC
        assert_eq!(format_time(1_786_492_800_000), "2026-08-12 00:00");
        assert_eq!(format_time(0), "1970-01-01 00:00");
    }
}
