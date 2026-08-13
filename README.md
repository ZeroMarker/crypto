# Rust for Crypto

A workspace for learning and building cryptography, wallets, and blockchain
software in Rust. Follows the [roadmap](ROADMAP.md).

## Crate status

| Phase | Crate | Status |
|---|---|---|
| 1 — Primitives | [`crypto-core`](crates/crypto-core) | ✅ implemented |
| 2 — Wallet | [`wallet`](crates/wallet) | ✅ implemented (keystore, tx signing, JSON-RPC) |
| 3 — Node/ledger | [`chain`](crates/chain) | ✅ implemented (P2P sync + EVM) |
| 4 — Trading app | [`trading`](crates/trading) | ✅ implemented (backtest + paper trader) |
| 5 — Hardening | Cross-cutting | 🚧 in progress (secrets, audit, telemetry, resilience, fault tests) |

## What's implemented

- **Hashing**: SHA-256, SHA3-256, Keccak-256 (Ethereum), RIPEMD-160, HMAC-SHA256
- **Signatures**: ECDSA over secp256k1 (sign/verify, Ethereum `r‖s‖v` format,
  key recovery / `ecrecover`)
- **AEAD**: AES-256-GCM and ChaCha20-Poly1305 with AAD binding
- **KDFs**: HKDF-SHA256 (RFC 5869), PBKDF2-HMAC-SHA256 (RFC 8018),
  constant-time comparisons
- **Wallet**: BIP-39 mnemonic → seed, BIP-32 HD derivation (full `m/44'/...'`
  paths), Ethereum (EIP-55) + Bitcoin address derivation, Ethereum v3 JSON
  keystore (password-encrypted private keys)
- **Transactions**: RLP encoding, legacy (EIP-155) + typed (EIP-2930/1559)
  transaction build/sign/parse, ecrecover sender recovery — pinned against
  the official EIP-155 vector
- **Chain**: merkle roots + SPV proofs, compact-bits PoW, block validation,
  longest-chain reorgs, UTXO-backed mempool, dependency-free P2P block sync,
  teaching-grade EVM interpreter (stack, memory, storage, CALL/CREATE, gas)
- **Trading**: Binance-style klines client, OHLCV resampling + trade
  aggregation, SMA/EMA/RSI indicators, event-driven backtester (drawdown,
  Sharpe), paper broker (fees/slippage), risk controls, and a `trade` CLI
  (`fetch` / `backtest` / `live` paper trading)
- **Hardening**: zeroized secret loading from environment or permission-checked
  files, parser property/fuzz tests, structured logs, Prometheus-format metrics,
  retry/backoff and circuit breakers, graceful Ctrl-C shutdown, atomic market
  data writes, and future-timestamp rejection
- **CI**: pinned Rust 1.96.0 with formatting, strict Clippy, workspace tests, and
  RustSec dependency auditing on every push to `main` and every pull request

All primitives validated against official test vectors (NIST, RFC 4231, BIP-39,
BIP-32); the chain is validated against Bitcoin block 100000 and the genesis
merkle root.

## Quick start

```sh
cargo test --workspace
cargo run -p crypto-core --example hashes
cargo run -p crypto-core --example signing
cargo run -p wallet --example mnemonic_to_address
cargo run -p wallet --example keystore
cargo run -p wallet --example sign_transaction
cargo run -p chain --example demo
cargo run -p trading --bin trade -- fetch BTCUSDT 1h --limit 200 --out bars.json
cargo run -p trading --bin trade -- backtest --data bars.json --fast 20 --slow 50
```

## Docs

- [01 — Foundation](docs/01-foundation.md)
- [02 — Cryptography primitives](docs/02-cryptography.md)
- [03 — Transactions & wallet](docs/03-transactions-wallet.md)
- [04 — Blockchain node](docs/04-blockchain-node.md)
- [05 — Trading app](docs/05-trading.md)
- [06 — Production hardening](docs/06-hardening.md)

## Layout

```
crates/
├── crypto-core/   # hash, sign, aead + examples
├── wallet/        # bip39, bip32, addresses, tx signing, JSON-RPC + examples
├── chain/         # merkle/spv, pow, chain, mempool, p2p, evm + examples
└── trading/       # klines, indicators, backtest, paper broker, risk, `trade` CLI
docs/              # per-phase guides
ROADMAP.md         # the plan
```
