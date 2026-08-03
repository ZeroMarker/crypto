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
- [ ] Benchmarks harness (`criterion`) wired in

Done when: `cargo test` and `cargo clippy -D warnings` pass cleanly on CI.

## Phase 1 — Cryptography primitives
Goal: understand and re-implement (or wrap) the primitives crypto apps depend
on. **Implemented in `crates/crypto-core`** — see
[docs/02-cryptography.md](docs/02-cryptography.md).

- [x] Hashing: SHA-256, Keccak-256 (used by Ethereum), RIPEMD-160
- [x] HMAC / HKDF for key derivation
- [x] Authenticated encryption (AEAD): AES-GCM, ChaCha20-Poly1305
- [x] Digital signatures: ECDSA (secp256k1), Ed25519
- [ ] Key management: keystore format (e.g. Ethereum's v3 JSON keystore)
- [x] BIP-39 mnemonic → seed → BIP-32 HD wallet derivation

Recommended crates: `sha2`, `sha3`, `hmac`, `hkdf`, `aes-gcm`, `chacha20poly1305`, `k256`, `ed25519-dalek`, `bip39`, `hdwallet`/custom BIP-32.

Done when: a test signs a message and verifies it round-trip; a mnemonic derives the same address as a reference implementation.

## Phase 2 — Transaction & wallet layer
Goal: produce and broadcast real transactions. **Key derivation implemented in
`crates/wallet`** — see
[docs/03-transactions-wallet.md](docs/03-transactions-wallet.md).

- [x] Build/parse transactions: Bitcoin, Ethereum (typed EIP-1559), maybe Solana
- [x] Sign with Phase 1 keys; canonical serialization (RLP for EVM)
- [ ] Fee estimation and nonce/sequence management
- [ ] Node client over JSON-RPC (read state, broadcast tx, wait for receipt)
- [x] Address derivation from pubkey (checksums, bech32)

Done when: a signed transaction is accepted on a testnet (Sepolia / testnet3).

## Phase 3 — Blockchain node / ledger
Goal: go beyond being a client — understand the ledger itself. **Ledger core
implemented in `crates/chain`** — see
[docs/04-blockchain-node.md](docs/04-blockchain-node.md).

- [x] Simple chain with Proof-of-Work (difficulty target, headers, merkle root)
- [x] Merkle tree + SPV proofs
- [x] Mempool, block validation, reorg handling
- [ ] P2P layer for syncing blocks (libp2p)
- [ ] EVM execution with `revm`

Done when: two nodes sync a chain over P2P and agree on the same canonical tip.

## Phase 4 — Trading / analytics app
Goal: turn the plumbing into a useful application. **Planned** — see
[docs/05-trading.md](docs/05-trading.md).

- [ ] Market data ingestion (WebSocket/HTTP): order books, trades, candles
- [ ] OHLCV aggregation + storage (time-series DB, e.g. `sqlx` + Postgres)
- [ ] Indicators & backtesting engine (`tick`-based, portfolio metrics)
- [ ] Execution: order placement, fills, position/PnL tracking
- [ ] Risk controls: max position, stop-loss, rate limiting
- [ ] Dashboard/CLI or TUI to monitor live state

Done when: a paper-trading bot runs a backtested strategy live against a sandbox exchange.

## Phase 5 — Production hardening
Goal: ship something safe enough for real funds (or real money). **Planned** —
see [docs/06-hardening.md](docs/06-hardening.md).

- [ ] Secret handling: env/`secrets` mgmt, no keys in logs, hardware wallet or secure enclave option
- [ ] Audit: dependency auditing (`cargo audit`), fuzzing (`cargo-fuzz`) on parsers
- [ ] Observability: structured logs (`tracing`), metrics, alerting
- [ ] Resilience: reconnect/backoff, circuit breakers, graceful shutdown
- [ ] Failure drills: kill -9, network partition, clock skew, replay protection

Done when: a test-run passes with injected faults and no funds/state corruption.

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
1. **M1 — Keys & wallet** (Phases 0–2): offline signer CLI + testnet broadcast. *First win.* ✅ `crypto-core` + `wallet` done.
2. **M2 — Chain understanding** (Phase 3): small POW chain + EVM exec. 🚧 `chain` ledger core done (merkle/SPV, PoW, validation, reorg, mempool); P2P + EVM open.
3. **M3 — Trading bot** (Phase 4): backtester + paper trader.
4. **M4 — Hardened** (Phase 5): audits, fuzzing, fault drills.

Start at M1. Everything before it is dependency; everything after is polish.
