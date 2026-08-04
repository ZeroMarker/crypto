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
wallets to reconstruct the address from a signature. `s` is always the
canonical low-s form (EIP-2), and `v` is adjusted to match, so
`recover_verifying_key` round-trips the signer's public key exactly.

```rust
use crypto_core::hash::keccak256;
use crypto_core::sign::{keypair_from_seed, sign_digest, verify_digest, recover_verifying_key, signature_to_hex};

let (sk, pk) = keypair_from_seed(&[42u8; 32]);
let digest = keccak256(b"transfer 100 USDC to 0x1234");
let sig = sign_digest(&sk, &digest);
assert!(verify_digest(&pk, &digest, &sig));
assert_eq!(recover_verifying_key(&digest, &sig).unwrap(), pk); // ecrecover
println!("0x{}", signature_to_hex(&sig));
```

### Why sign a *digest*, not a message?

secp256k1 signs 256-bit values. In practice you hash a message/typed-data with
Keccak-256 (Ethereum) or SHA-256 (Bitcoin) and sign that digest. Hashing before
signing also prevents key-recovery attacks when a nonce is reused.

## Key derivation (HKDF-SHA256, RFC 5869)

`kdf::hkdf_sha256(ikm, salt, info, len)` stretches a weak secret into
arbitrary-length key material, optionally bound to a salt and application
context. Deriving with different `info` values gives independent keys — e.g.
split one master secret into separate encryption and MAC keys.

```rust
use crypto_core::kdf::hkdf_sha256;

let master = b"a not-very-strong passphrase";
let enc_key = hkdf_sha256(master, b"random-salt", b"wallet-encryption", 32).unwrap();
let mac_key = hkdf_sha256(master, b"random-salt", b"wallet-mac", 32).unwrap();
assert_ne!(enc_key, mac_key);
```

Validated against RFC 5869 test cases 1 and 3.

## Password-based derivation (PBKDF2-HMAC-SHA256, RFC 8018)

`kdf::pbkdf2_sha256(password, salt, iterations, len)` stretches a
low-entropy password into a key. Brute force costs `iterations` HMAC rounds
per guess, so high counts (e.g. 262144, the keystore default) make offline
guessing expensive. `salt` must be unique per password.

```rust
use crypto_core::kdf::pbkdf2_sha256;

let dk = pbkdf2_sha256(b"password", b"salt", 262144, 32).unwrap();
```

HKDF and PBKDF2 are the two sides of key derivation: HKDF *extracts* entropy
from a strong secret, PBKDF2 *stretches* a weak one (a password) against
brute force. PBKDF2 also seeds BIP-39 mnemonics and the Ethereum v3 keystore
(see [docs/03-transactions-wallet.md](03-transactions-wallet.md)). Validated
against RFC 7914 §11 vectors.

## Constant-time comparison

`ct::ct_eq` / `ct::ct_eq_slices` compare secrets (digests, HMAC tags, AEAD
keys) without leaking *where* they differ. Never use `==` on untrusted
secrets — a byte-wise short-circuit is a timing oracle.

```rust
use crypto_core::ct::ct_eq;

assert!(ct_eq(&[1u8; 32], &[1u8; 32]));
assert!(!ct_eq(&[1u8; 32], &[2u8; 32]));
```

## AEAD encryption

`aead::Ciphertext` bundles a fresh random 12-byte nonce (from the OS CSPRNG)
with `ciphertext || tag`, so a nonce can never be lost or reused by accident.
AAD binds the ciphertext to some identifier (e.g. the address it belongs to);
tampering with the AAD fails authentication.

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

> ⚠️ **Nonce discipline.** Reusing a `(key, nonce)` pair is fatal for AEAD:
> an attacker can recover the keystream and forge tags. The random-nonce API
> makes this the default, but if you must pass explicit nonces
> (`encrypt_aes_gcm_with_nonce`), never reuse one with the same key.

## Tests

`crypto-core` is validated against official vectors:
- SHA-256 "abc" (NIST), Keccak-256 empty (Ethereum), SHA3-256 "abc" (NIST),
  RIPEMD-160 "abc" (ISO), HMAC-SHA256 RFC 4231 case 1.
- HKDF-SHA256 RFC 5869 cases 1 and 3; PBKDF2-HMAC-SHA256 RFC 7914 §11.
- AES-256-GCM NIST CAVP vector; ChaCha20-Poly1305 RFC 8439 §2.8.2 vector.
- ECDSA sign/verify/recover round-trips; AEAD tamper/wrong-key/wrong-AAD
  rejection; nonce-randomness (same plaintext ⇒ unrelated ciphertexts).

```sh
cargo test -p crypto-core
```

## Next

[Phase 2 — Transactions & wallet](03-transactions-wallet.md) is implemented in
`crates/wallet`.
