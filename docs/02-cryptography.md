# Phase 1 — Cryptography primitives

Implemented in `crates/crypto-core`. Thin, documented wrappers around
well-audited crates (`RustCrypto`) so callers have one consistent API surface.

## Hash functions

| Function | Digest size | Used for |
|---|---|---|
| `hash::sha256` | 32 B | Bitcoin tx hashing, checksums |
| `hash::sha3_256` | 32 B | NIST SHA-3 (standards compliant) |
| `hash::keccak256` | 32 B | **Ethereum** addresses, tx payloads, EIP-191 |
| `hash::ripemd160` | 20 B | Bitcoin `HASH160` = RIPEMD160(SHA256(pk)) |
| `hash::hmac_sha256` | 32 B | HMAC; building block for HKDF/TOTP |

> ⚠️ Keccak-256 is **not** SHA3-256. Ethereum's `keccak256` pre-dates the NIST
> standard. Use the right one or signatures/addresses will silently mismatch.

```rust
use crypto_core::hash::{sha256, keccak256, ripemd160, hmac_sha256};
use hex::ToHex;

let digest = sha256(b"Rust for crypto");
println!("{}", digest.encode_hex::<String>());
```

## Signatures (ECDSA over secp256k1)

`sign::sign_digest` produces `r || s || v` (Ethereum "raw" 65-byte format).
`v` is the recovery id — required for `ecrecover` on-chain and used by Ethereum
wallets to reconstruct the address from a signature.

```rust
use crypto_core::hash::keccak256;
use crypto_core::sign::{keypair_from_seed, sign_digest, verify_digest, signature_to_hex};

let (sk, pk) = keypair_from_seed(&[42u8; 32]);
let digest = keccak256(b"transfer 100 USDC to 0x1234");
let sig = sign_digest(&sk, &digest);
assert!(verify_digest(&pk, &digest, &sig));
println!("0x{}", signature_to_hex(&sig));
```

### Why sign a *digest*, not a message?

secp256k1 signs 256-bit values. In practice you hash a message/typed-data with
Keccak-256 (Ethereum) or SHA-256 (Bitcoin) and sign that digest. Hashing before
signing also prevents key-recovery attacks when a nonce is reused.

## AEAD encryption

`aead::Ciphertext` bundles a random nonce with `ciphertext || tag`, so a
nonce can never be lost. AAD binds the ciphertext to some identifier (e.g. the
address it belongs to); tampering with the AAD fails authentication.

| Cipher | When to prefer |
|---|---|
| `aes_gcm` (AES-256-GCM) | Hardware with AES-NI |
| `chacha` (ChaCha20-Poly1305) | Software-only (cloud VMs), side-channel friendlier |

```rust
use crypto_core::aead::{encrypt_aes_gcm, decrypt_aes_gcm};

let key = [7u8; 32];
let ct = encrypt_aes_gcm(&key, b"private data", b"address-0x1234").unwrap();
let pt = decrypt_aes_gcm(&key, &ct, b"address-0x1234").unwrap();
assert_eq!(pt, b"private data");
```

> ⚠️ **Nonce discipline.** Never reuse a nonce under the same key. The
> `Ciphertext` type keeps the nonce alongside the data so this is hard to get
> wrong. For production, generate nonces with a CSPRNG (or a counter), not the
> deterministic placeholder in this crate.

## Tests

`crypto-core` is validated against official vectors:
- SHA-256 "abc" (NIST), Keccak-256 empty (Ethereum), SHA3-256 "abc" (NIST),
  RIPEMD-160 "abc" (ISO), HMAC-SHA256 RFC 4231 case 1.
- AEAD round-trips plus tamper/wrong-key/wrong-AAD rejection.

```sh
cargo test -p crypto-core
```

## Next

[Phase 2 — Transactions & wallet](03-transactions-wallet.md) is implemented in
`crates/wallet`.
