# Rust for Crypto

A workspace for learning and building cryptography, wallets, and blockchain
software in Rust. Follows the [roadmap](ROADMAP.md).

## Crate status

| Phase | Crate | Status |
|---|---|---|
| 1 — Primitives | [`crypto-core`](crates/crypto-core) | ✅ implemented |
| 2 — Wallet | [`wallet`](crates/wallet) | ✅ implemented (incl. v3 keystore) |
| 3 — Node/ledger | [`chain`](crates/chain) | ✅ ledger core |
| 4 — Trading app | — | ⏳ planned |
| 5 — Hardening | — | ⏳ planned |

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
- **Chain**: merkle roots + SPV proofs, compact-bits PoW, block validation,
  longest-chain reorgs, UTXO-backed mempool

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
cargo run -p chain --example demo
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
├── wallet/        # bip39, bip32, addresses + examples
└── chain/         # merkle/spv, pow, chain, mempool + examples
docs/              # per-phase guides
ROADMAP.md         # the plan
```
