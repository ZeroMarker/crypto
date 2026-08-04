# Phase 2 — Transactions & wallet

Implemented in `crates/wallet`. Derives keys and addresses from a BIP-39
mnemonic down to a concrete signing key.

## Derivation chain

```text
mnemonic ──(PBKDF2, BIP-39)──▶ seed ──(HMAC-SHA512, BIP-32)──▶ master xprv
    ──(BIP-44 path)──▶ account key ──▶ address
```

- **BIP-39**: 12-word mnemonic → 64-byte seed (with optional passphrase).
- **BIP-32**: HD key tree; `k` = secp256k1 scalar, `chain_code` = mixing entropy.
- **BIP-44**: standard path `m/44'/coin'/account'/change/index`. Coin type
  `60` = Ethereum, `0` = Bitcoin.

```rust
use wallet::{Mnemonic, Account};

let mnemonic = Mnemonic::generate()?;
let account = Account::from_mnemonic(&mnemonic, 0)?;
println!("address: {}", account.address());
```

## Parse an existing mnemonic

```rust
use wallet::{Mnemonic, Account};

let mnemonic = Mnemonic::parse(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
)?;
let acct = Account::from_mnemonic(&mnemonic, 0)?;
```

## Arbitrary BIP-32 paths

Bitcoin (coin type 0) versus Ethereum (coin type 60) just differ in the path:

```rust
use wallet::{Account, Mnemonic};

let m = Mnemonic::parse("...")?;
let btc = Account::from_path(&m, "m/44'/0'/0'/0/0")?;   // Bitcoin
let eth = Account::from_path(&m, "m/44'/60'/0'/0/0")?;  // Ethereum
```

## Address formats

| Network | Algorithm |
|---|---|
| Ethereum | `0x` + last 20 bytes of `keccak256(uncompressed_pubkey[1..])` |
| Bitcoin (P2PKH) | base58check(`0x00 \|\| RIPEMD160(SHA256(compressed_pk))`) |

Both are implemented in `wallet::address_from_public_key` and
`wallet::bitcoin_address_from_public_key`.

## Keystores (Ethereum v3, Web3 Secret Storage)

`wallet::keystore::Keystore` stores a private key encrypted under a password
in the exact JSON format geth / MyEtherWallet / MetaMask use on disk
(`~/.ethereum/keystore/`).

```rust
use wallet::keystore::Keystore;

let key = [0x7a; 32];
let ks = Keystore::encrypt(&key, "correct horse battery staple")?;
let json = ks.to_json()?;                 // write this to disk / backup
let parsed = Keystore::from_json(&json)?; // read it back
assert_eq!(parsed.decrypt("correct horse battery staple")?, key);
```

How the format works:

```text
 dk = PBKDF2-HMAC-SHA256(password, salt, c=262144, dklen=32)
 key       = dk[0..16]              (AES-128 key)
 ciphertext = AES-128-CTR(key, iv, private_key)
 mac       = keccak256(dk[16..32] ‖ ciphertext)
```

- The `mac` authenticates the derived key *and* the ciphertext, and is
  verified in constant time **before** decryption — a wrong password yields
  no key material. Tampering with any field is rejected.
- Salt, IV, and the keystore `id` (UUIDv4) are drawn from the OS CSPRNG;
  `KeystoreOptions` pins them for reproducible golden vectors.
- The canonical ethereumjs test vector (password `testpassword` → key
  `7a28b5ba...`) is round-tripped byte-for-byte in the test suite.

```sh
cargo run -p wallet --example keystore
```

## Security notes

- The mnemonic is the master secret. Anyone who holds it controls every derived
  address. Store it **offline, encrypted** (`aead` from Phase 1).
- `Mnemonic`'s `Debug` impl redacts the phrase so it never leaks into logs.
- BIP-39 passphrases are deprecated for new wallets but supported for migration
  via `to_seed_with_passphrase`.

## Tests

Validated against official vectors:
- BIP-39 vector 1 (`abandon...about` + `TREZOR` → seed `c55257c3...`).
- BIP-32 vector 1 (seed `00010203...0f`) master key, `m/0'`, and the full
  chain `m/0'/1/2'/2/1000000000` (keys decoded from the official xprv strings).

```sh
cargo test -p wallet
cargo run -p wallet --example mnemonic_to_address
```

## Next

[Phase 3 — Blockchain node / ledger](04-blockchain-node.md) goes beyond being a
client and implements the ledger itself.
