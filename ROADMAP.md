# Rust for Crypto — Roadmap

A phased plan for building crypto/blockchain/trading software in Rust. Each
phase has a concrete deliverable and a "done when" check. Implemented phases
link to their guide in [`docs/`](docs/).

## Phase 0 — Foundation
Goal: get a clean Rust workspace you can build on. **Done** — see
[docs/01-foundation.md](docs/01-foundation.md).

- [x] `cargo new` workspace layout (`crates/` for libs, `bin/` for executables)
- [x] Pin Rust toolchain (`rust-toolchain.toml`)
- [x] CI: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`
- [x] Benchmarks harness (`criterion`) wired in

Done when: `cargo test` and `cargo clippy -D warnings` pass cleanly on CI.

## Phase 1 — Cryptography primitives
Goal: understand and re-implement (or wrap) the primitives crypto apps depend
on. **Implemented in `crates/crypto-core`** — see
[docs/02-cryptography.md](docs/02-cryptography.md).

- [x] Hashing: SHA-256, Keccak-256 (used by Ethereum), RIPEMD-160
- [x] HMAC / HKDF for key derivation
- [x] Authenticated encryption (AEAD): AES-GCM, ChaCha20-Poly1305
- [x] Digital signatures: ECDSA (secp256k1), Ed25519
- [x] Key management: keystore format (Ethereum v3 JSON keystore, Web3
      Secret Storage)
- [x] BIP-39 mnemonic → seed → BIP-32 HD wallet derivation

Recommended crates: `sha2`, `sha3`, `hmac`, `hkdf`, `aes-gcm`, `chacha20poly1305`, `k256`, `ed25519-dalek`, `bip39`, `hdwallet`/custom BIP-32.

Done when: a test signs a message and verifies it round-trip; a mnemonic derives the same address as a reference implementation.

## Phase 2 — Transaction & wallet layer
Goal: produce and broadcast real transactions. **Key derivation, keystore,
and Ethereum tx build/sign/parse implemented in `crates/wallet`** — see
[docs/03-transactions-wallet.md](docs/03-transactions-wallet.md).

- [x] Build/parse transactions: legacy EIP-155, typed EIP-2930 + EIP-1559
      (RLP encoding, `from_raw` decoding)
- [x] Sign with Phase 1 keys; canonical serialization (RLP for EVM),
      ecrecover sender recovery
- [x] Fee estimation and nonce/sequence management (JSON-RPC `feeHistory`,
      pending nonce, in `crates/wallet/src/rpc.rs`)
- [x] Node client over JSON-RPC (read state, broadcast tx, wait for receipt)
- [x] Address derivation from pubkey (checksums, bech32)

Done when: a signed transaction is accepted on a testnet (Sepolia / testnet3).

## Phase 3 — Blockchain node / ledger
Goal: go beyond being a client — understand the ledger itself. **Ledger core
implemented in `crates/chain`** — see
[docs/04-blockchain-node.md](docs/04-blockchain-node.md).

- [x] Simple chain with Proof-of-Work (difficulty target, headers, merkle root)
- [x] Merkle tree + SPV proofs
- [x] Mempool, block validation, reorg handling
- [x] P2P layer for syncing blocks (dependency-free TCP sync in
      `crates/chain/src/p2p.rs`: handshake, pull, reorg, announce)
- [x] EVM execution (teaching-grade interpreter in `crates/chain/src/evm.rs`:
      stack, memory, storage, jumps, CALL/CREATE, gas)

Done when: two nodes sync a chain over P2P and agree on the same canonical tip.

## Phase 4 — Trading / analytics app
Goal: turn the plumbing into a useful application. **Implemented in
`crates/trading`** — see
[docs/05-trading.md](docs/05-trading.md).

- [x] Market data ingestion (HTTPS klines client in `data.rs`, Binance-style
      REST, endpoint overridable via `TRADING_API_BASE`)
- [x] OHLCV aggregation + storage (`bar.rs`: resampling, trade aggregation,
      JSON persistence for reproducible offline backtests)
- [x] Indicators & backtesting engine (`indicator.rs` SMA/EMA/RSI,
      `backtest.rs` event-driven loop with equity curve, drawdown, Sharpe)
- [x] Execution: paper broker (`broker.rs`: fees, slippage, avg-cost basis,
      fills at bar close)
- [x] Risk controls (`risk.rs`: max position fraction, stop-loss)
- [x] Dashboard/CLI (`src/bin/trade.rs`: `fetch` / `backtest` / `live` paper
      trading loop with report + sparkline)

Done when: a paper-trading bot runs a backtested strategy live against a sandbox exchange.

## Phase 5 — Production hardening
Goal: ship something safe enough for real funds (or real money). **In progress** —
see [docs/06-hardening.md](docs/06-hardening.md).

- [x] Secret handling baseline: zeroized buffers plus env/permission-checked
      file loading, with redacted debug output
- [ ] Secret handling production integrations: external secrets manager and
      hardware wallet or secure enclave
- [x] Audit baseline: RustSec `cargo audit` in CI, parser property tests and
      deterministic fuzz-style tests
- [ ] Audit policy: `cargo deny` and persistent `cargo-fuzz` targets
- [x] Observability baseline: structured `tracing` logs and Prometheus-format
      counters, gauges and histograms
- [ ] Observability operations: scrape endpoint and alerting rules
- [x] Resilience baseline: transient-error retries with jittered backoff,
      circuit breaker, atomic persistence and graceful Ctrl-C shutdown
- [ ] Resilience operations: SIGTERM handling and persistent reconnecting feeds
- [x] Failure drills: interrupted-write safety and future clock-skew rejection
- [ ] Failure drills: real network partitions, replay protection and idempotent
      order/broadcast keys

Done when: a fault-injected test run completes with no funds/state corruption,
operational alerts are wired, and dependency/policy audits pass.

---

## Cross-cutting choices (decide early)
- **Async runtime**: Tokio (default) vs async-std
- **Error handling**: `thiserror` + `anyhow`
- **Config**: `config`/`figment` + env override
- **DB**: SQLite for dev, Postgres for prod, or `redb`/`sled` for embedded
- **Testing**: property-based (`proptest`), golden vectors from official test suites

## Suggested crate map
| Concern          | Crate(s)                                          |
|------------------|---------------------------------------------------|
| Hashing          | `sha2`, `sha3`, `ripemd`                          |
| Signatures       | `k256` (secp256k1), `ed25519-dalek`, `elliptic-curve` |
| Wallet           | `bip39`, custom BIP-32/44, `serde` for keystores   |
| EVM              | `revm`, `alloy`                                   |
| RPC/WS           | `alloy` (Ethereum), `reqwest` + `tokio-tungstenite` |
| P2P              | `libp2p`                                           |
| Trading          | `binance`/`ccxt` wrappers, `chrono` + `candle`/`ta` |
| Storage          | `sqlx`, `sqlite`, `candle` (arrays)               |
| Misc             | `serde`, `serde_json`, `tracing`, `thiserror`     |

## Milestones (suggested order)
1. **M1 — Keys & wallet** (Phases 0–2): offline signer CLI + testnet broadcast. ✅ `crypto-core` + `wallet` done.
2. **M2 — Chain understanding** (Phase 3): small POW chain + EVM exec. ✅ `chain` complete: merkle/SPV, PoW, validation, reorg, mempool, P2P sync, EVM interpreter.
3. **M3 — Trading bot** (Phase 4): backtester + paper trader. ✅ `trading` crate: klines, OHLCV, indicators, backtest, paper broker, risk, `trade` CLI.
4. **M4 — Hardened** (Phase 5): audits, fuzzing, telemetry and fault drills.
   🚧 baseline implemented; production integrations and drills remain.

Start at M1. Everything before it is dependency; everything after is polish.
