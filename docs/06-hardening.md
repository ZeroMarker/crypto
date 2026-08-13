# Phase 5 — Production hardening

Partially implemented across `wallet`, `chain`, and `trading`. The current
baseline improves failure behavior and automated verification, but it is not a
claim that the workspace is ready to custody real funds.

## Checklist

1. **Secret handling**
   - [x] Keys can remain in the AEAD-encrypted Ethereum v3 keystore from Phase
     1 instead of config files.
   - [x] `wallet::secrets::SecretBytes` zeroizes memory on drop and redacts its
     `Debug` representation.
   - [x] `wallet::secrets::load_signing_key` loads a key from
     `WALLET_PRIVATE_KEY` or a permission-checked `WALLET_KEY_FILE` without
     logging key material.
   - [ ] Integrate an external secrets manager and hardware-backed signer.

2. **Dependency and code audit**

   GitHub Actions runs the following on pushes to `main` and pull requests:

   ```sh
   cargo fmt --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   cargo audit
   ```

   - [x] RustSec scans `Cargo.lock` in CI.
   - [x] `proptest` covers transaction/RLP, wallet and chain invariants.
   - [x] Deterministic fuzz-style tests feed arbitrary bytes into RLP,
     transaction, keystore and block parsers.
   - [ ] Add `cargo deny` license/advisory policy.
   - [ ] Add persistent `cargo-fuzz` targets and a scheduled fuzzing budget.

3. **Observability**
   - [x] `trading::telemetry::init_logging` configures structured `tracing`
     output using `RUST_LOG` (default `info`).
   - [x] The in-process registry supports counters, gauges and histograms and
     renders Prometheus text exposition.
   - [x] The live paper trader records fetch/trade/equity metrics and prints a
     final metrics snapshot during graceful shutdown.
   - [ ] Expose a long-lived scrape endpoint and define alerting rules.

4. **Resilience**
   - [x] `trading::resilience` provides exponential backoff with full jitter,
     bounded retry and a thread-safe circuit breaker.
   - [x] `DataClient` retries transient transport/5xx/429 failures and protects
     exchange calls with the circuit breaker.
   - [x] The live CLI handles Ctrl-C, finishes its current iteration, and emits
     a final account/metrics summary.
   - [x] `save_bars_atomic` writes, syncs and atomically renames a unique
     temporary file so the destination is never partially replaced.
   - [ ] Handle SIGTERM and add persistent reconnecting WebSocket feeds.

5. **Failure drills**
   - [x] Interrupted-write tests verify that partial temporary files cannot
     corrupt the last complete market-data snapshot.
   - [x] Concurrent writers use distinct temporary files and leave one complete
     snapshot at the destination.
   - [x] `BlockChain::with_future_skew` rejects blocks timestamped beyond a
     configured local-clock tolerance.
   - [x] Retry/circuit-breaker tests cover transient failures, open-state fast
     failure and half-open recovery.
   - [ ] Exercise real process `kill -9` and network partitions in an
     integration-test harness.
   - [ ] Add replay protection and idempotent order/broadcast keys.

## Done-when

The baseline CI currently passes formatting, strict Clippy, all workspace
tests, and RustSec auditing. Phase 5 is complete only when the remaining
production integrations and process/network fault drills pass without funds or
state corruption.
