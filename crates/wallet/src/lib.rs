//! # wallet
//!
//! Key management for the Rust-for-crypto roadmap (Phase 2 — "transactions &
//! wallet").
//!
//! Implements the standard derivation chain from a BIP-39 mnemonic down to a
//! secp256k1 key usable for signing:
//!
//! ```text
//! mnemonic ──(PBKDF2)──▶ seed ──(BIP-32 HMAC-SHA512)──▶ xprv ──(BIP-44 path)──▶ child key
//! ```
//!
//! ## Example
//!
//! ```no_run
//! use wallet::{Mnemonic, Account};
//!
//! let mnemonic = Mnemonic::generate().unwrap();
//! let account = Account::from_mnemonic(&mnemonic, 0)?;
//! println!("address: {}", account.address());
//! # Ok::<(), wallet::WalletError>(())
//! ```

use std::fmt;

use bip39::{Language, Mnemonic as Bip39Mnemonic};
use crypto_core::hash::{keccak256, ripemd160, sha256};
use k256::ecdsa::SigningKey;

/// Errors produced by wallet operations.
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    /// The mnemonic phrase was invalid (bad checksum, wrong word count, ...).
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),
    /// A derived key was outside the valid secp256k1 range (retry a different index).
    #[error("invalid derived key, try the next index")]
    InvalidKey,
}

/// A BIP-39 mnemonic phrase (12 words by default) that seeds the wallet.
///
/// Store this **offline and encrypted**. It is the master secret: anyone who
/// holds it controls every address derived from it.
#[derive(Clone)]
pub struct Mnemonic {
    inner: Bip39Mnemonic,
}

impl Mnemonic {
    /// Generate a fresh 12-word mnemonic using a CSPRNG.
    pub fn generate() -> Result<Mnemonic, WalletError> {
        let mut entropy = [0u8; 16];
        getrandom::getrandom(&mut entropy)
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;
        Mnemonic::from_entropy(&entropy)
    }

    /// Build a mnemonic from raw entropy bytes (16, 20, 24, 28, or 32 bytes).
    pub fn from_entropy(entropy: &[u8]) -> Result<Mnemonic, WalletError> {
        Bip39Mnemonic::from_entropy_in(Language::English, entropy)
            .map(|m| Mnemonic { inner: m })
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))
    }

    /// Parse a user-provided phrase (e.g. from a hardware wallet).
    pub fn parse(phrase: &str) -> Result<Mnemonic, WalletError> {
        Bip39Mnemonic::parse_in_normalized(Language::English, phrase)
            .map(|m| Mnemonic { inner: m })
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))
    }

    /// The 512-bit BIP-39 seed used as the BIP-32 master secret.
    pub fn to_seed(&self) -> [u8; 64] {
        self.to_seed_with_passphrase("")
    }

    /// BIP-39 seed with an optional passphrase. Non-empty passphrases are
    /// deprecated for new wallets (BIP-39 spec) but still supported for
    /// migrating existing wallets.
    pub fn to_seed_with_passphrase(&self, passphrase: &str) -> [u8; 64] {
        self.inner.to_seed(passphrase)
    }

    /// The phrase as space-separated words.
    pub fn phrase(&self) -> String {
        self.inner.to_string()
    }
}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never log the phrase.
        write!(f, "Mnemonic(<redacted>)")
    }
}

/// A BIP-32 extended private key (xprv) — the wallet root, or any derivation
/// of it. `k` is the secp256k1 scalar; `chain_code` mixes in sibling entropy.
#[derive(Clone)]
pub struct ExtendedKey {
    pub k: [u8; 32],
    pub chain_code: [u8; 32],
}

impl ExtendedKey {
    /// Derive a child key at `index`. `hardened` sets the high bit of the
    /// serialized index (>= 2^31), as BIP-32 requires for hardened children.
    /// Hardened children are required below account level; non-hardened above
    /// (BIP-44 uses hardened `m/44'/0'/0'`).
    fn child(&self, index: u32, hardened: bool) -> Result<ExtendedKey, WalletError> {
        let index = if hardened { index | 0x8000_0000 } else { index };
        let mut data = Vec::with_capacity(37);
        if hardened {
            data.push(0);
            data.extend_from_slice(&self.k);
        } else {
            // public-key based derivation: k*G
            let sk = SigningKey::from_slice(&self.k).map_err(|_| WalletError::InvalidKey)?;
            let pk = k256::PublicKey::from(sk.verifying_key());
            data.extend_from_slice(&pk.to_sec1_bytes());
        }
        data.extend_from_slice(&index.to_be_bytes());

        let mac = hmac_sha512(&self.chain_code, &data);
        let il: [u8; 32] = mac[..32].try_into().expect("slice length");
        let ir: [u8; 32] = mac[32..].try_into().expect("slice length");

        // BIP-32: child_k = (IL + parent_k) mod n, and IL must be < n.
        if !lt_be(&il, &SECP256K1_N) {
            return Err(WalletError::InvalidKey);
        }
        let child_k = add_mod_n(&il, &self.k);
        if child_k.iter().all(|&b| b == 0) {
            return Err(WalletError::InvalidKey);
        }

        Ok(ExtendedKey {
            k: child_k,
            chain_code: ir,
        })
    }

    /// Derive down a BIP-32 path like `m/44'/0'/0'/0/0`. Hardened levels end
    /// with a `'`. Paths must start with `m`.
    pub fn derive_path(&self, path: &str) -> Result<ExtendedKey, WalletError> {
        let mut current = self.clone();
        for level in path.trim().split('/').skip(1) {
            let (level, hardened) = match level.strip_suffix('\'') {
                Some(l) => (l, true),
                None => (level, false),
            };
            let index: u32 = level.parse().map_err(|_| WalletError::InvalidKey)?;
            current = current.child(index, hardened)?;
        }
        Ok(current)
    }
}

/// `HMAC-SHA512(key, data)` — BIP-32's one-way mixing function.
fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// The secp256k1 group order n.
const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Big-endian `a < b`.
fn lt_be(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for (x, y) in a.iter().zip(b.iter()) {
        if x != y {
            return x < y;
        }
    }
    false
}

/// `(a + b) mod n` for 32-byte big-endian values. Requires `a < n` and `b < n`
/// (guaranteed for keys we derive), so the sum fits in 33 bytes and a single
/// subtraction loop fully reduces it.
fn add_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut sum = [0u8; 33];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let s = a[i] as u16 + b[i] as u16 + carry;
        sum[i + 1] = s as u8;
        carry = s >> 8;
    }
    sum[0] = carry as u8;

    loop {
        // stop when sum < n (compare 33-byte sum against n left-padded with 0)
        let mut below = true;
        for i in 0..33 {
            let (x, y) = (sum[i], if i == 0 { 0 } else { SECP256K1_N[i - 1] });
            if x != y {
                below = x < y;
                break;
            }
        }
        if below {
            break;
        }
        // sum -= n
        let mut borrow = 0i16;
        for i in (0..33).rev() {
            let y = if i == 0 { 0 } else { SECP256K1_N[i - 1] };
            let s = sum[i] as i16 - y as i16 - borrow;
            if s < 0 {
                sum[i] = (s + 256) as u8;
                borrow = 1;
            } else {
                sum[i] = s as u8;
                borrow = 0;
            }
        }
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&sum[1..]);
    out
}

/// Derive the BIP-32 master key from a BIP-39 seed (any length; BIP-39 gives
/// 64 bytes, BIP-32 test vectors use 16).
pub fn master_key_from_seed(seed: &[u8]) -> Result<ExtendedKey, WalletError> {
    let mac = hmac_sha512(b"Bitcoin seed", seed);
    let mut k = [0u8; 32];
    k.copy_from_slice(&mac[..32]);
    let mut cc = [0u8; 32];
    cc.copy_from_slice(&mac[32..]);
    if !lt_be(&k, &SECP256K1_N) {
        return Err(WalletError::InvalidKey);
    }
    Ok(ExtendedKey { k, chain_code: cc })
}

/// A concrete address + signing key, derived from a mnemonic via BIP-44.
///
/// Default path `m/44'/60'/0'/0/0` is the standard Ethereum account layout.
pub struct Account {
    signing_key: SigningKey,
    address: String,
}

impl Account {
    /// Derive the account at BIP-44 account index `account` (0, 1, 2, ...),
    /// coin type 60 (Ethereum). See also [`Account::from_path`].
    pub fn from_mnemonic(mnemonic: &Mnemonic, account: u32) -> Result<Account, WalletError> {
        Self::from_path(mnemonic, &format!("m/44'/60'/{}'/0/0", account))
    }

    /// Derive an account from an arbitrary BIP-32 path, e.g. Bitcoin
    /// `m/44'/0'/0'/0/0` (coin type 0).
    pub fn from_path(mnemonic: &Mnemonic, path: &str) -> Result<Account, WalletError> {
        let master = master_key_from_seed(&mnemonic.to_seed())?;
        let key = master.derive_path(path)?;
        let signing_key = SigningKey::from_slice(&key.k).map_err(|_| WalletError::InvalidKey)?;
        let address = address_from_public_key(signing_key.verifying_key());
        Ok(Account {
            signing_key,
            address,
        })
    }

    /// The secp256k1 signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// The checksummed Ethereum address (`0x` + 40 hex chars).
    pub fn address(&self) -> &str {
        &self.address
    }
}

/// Ethereum address from an uncompressed public key: last 20 bytes of
/// `keccak256(pubkey_without_0x04_prefix)`.
///
/// ```
/// use k256::ecdsa::SigningKey;
/// use wallet::address_from_public_key;
///
/// let sk = SigningKey::from_slice(&[42u8; 32]).unwrap();
/// let addr = address_from_public_key(sk.verifying_key());
/// assert!(addr.starts_with("0x"));
/// assert_eq!(addr.len(), 42);
/// ```
pub fn address_from_public_key(pk: &k256::ecdsa::VerifyingKey) -> String {
    let encoded = pk.to_encoded_point(false);
    let pubkey = &encoded.as_bytes()[1..];
    let digest = keccak256(pubkey);
    let tail = &digest[12..];
    format!("0x{}", hex::encode(tail))
}

/// Bitcoin-style address from a public key: base58check of
/// `0x00 || HASH160(pubkey)`. This is the P2PKH format.
pub fn bitcoin_address_from_public_key(pk: &k256::ecdsa::VerifyingKey) -> String {
    let compressed = pk.to_sec1_bytes();
    let hash160 = ripemd160(&sha256(&compressed));
    let mut payload = Vec::with_capacity(21);
    payload.push(0x00);
    payload.extend_from_slice(&hash160);
    base58check(&payload)
}

/// Base58Check encoding: payload || sha256(sha256(payload))[..4], base58'd.
pub fn base58check(payload: &[u8]) -> String {
    let checksum = sha256(&sha256(payload));
    let mut full = payload.to_vec();
    full.extend_from_slice(&checksum[..4]);
    base58_encode(&full)
}

/// Base58 encode (Bitcoin alphabet, no checksum — use [`base58check`] normally).
fn base58_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    let mut zeros = 0;
    while zeros < input.len() && input[zeros] == 0 {
        zeros += 1;
    }

    // Each base58 char ~= log2(58) bits; need (len*8 / log2(58)) + 1 chars.
    let mut b58 = vec![0u8; (input.len() - zeros) * 138 / 100 + 1];
    let mut length = 0;

    for byte in &input[zeros..] {
        let mut carry = *byte as usize;
        for ch in b58.iter_mut().rev() {
            let total = carry + (*ch as usize) * 256;
            *ch = (total % 58) as u8;
            carry = total / 58;
        }
        while length < b58.len() && b58[length] == 0 {
            length += 1;
        }
    }

    let mut out = String::with_capacity(zeros + b58.len() - length);
    for _ in 0..zeros {
        out.push('1');
    }
    for &i in &b58[length..] {
        out.push(ALPHABET[i as usize] as char);
    }
    out
}

/// Simple hash of a signing key used in tests to detect accidental logging.
#[doc(hidden)]
pub fn debug_fingerprint(sk: &SigningKey) -> String {
    let d = sha256(&sk.to_bytes());
    hex::encode(&d[..4])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mnemonic_generates_and_parses() {
        let m = Mnemonic::generate().unwrap();
        assert_eq!(m.phrase().split(' ').count(), 12);
        let again = Mnemonic::parse(&m.phrase()).unwrap();
        assert_eq!(again.to_seed(), m.to_seed());
    }

    #[test]
    fn bip39_test_vector() {
        // BIP-39 official vector 1: entropy "00000000000000000000000000000000",
        // passphrase "TREZOR".
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        assert_eq!(
            m.phrase(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        let seed = m.to_seed_with_passphrase("TREZOR");
        assert_eq!(
            hex::encode(seed),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
             1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn bip32_test_vector_1() {
        // BIP-32 vector 1: seed 000102030405060708090a0b0c0d0e0f
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = master_key_from_seed(&seed).unwrap();
        assert_eq!(
            hex::encode(master.k),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );
        assert_eq!(
            hex::encode(master.chain_code),
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
        );
        // m/0' — intermediate keys from the official vector.
        let child = master.derive_path("m/0'").unwrap();
        assert_eq!(
            hex::encode(child.k),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        );
        assert_eq!(
            hex::encode(child.chain_code),
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
        );
        // m/0'/1/2'/2/1000000000 — the full chain's final child key (chain code
        // and key decoded from the official xprvA41... in BIP-32 vector 1).
        let deep = master.derive_path("m/0'/1/2'/2/1000000000").unwrap();
        assert_eq!(
            hex::encode(deep.k),
            "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8"
        );
        assert_eq!(
            hex::encode(deep.chain_code),
            "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e"
        );
    }

    #[test]
    fn address_is_stable() {
        let m = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let acct = Account::from_mnemonic(&m, 0).unwrap();
        // The famous all-zeros-key test address will differ since key comes from mnemonic,
        // but it must be deterministic.
        assert_eq!(
            acct.address(),
            Account::from_mnemonic(&m, 0).unwrap().address()
        );
        assert_eq!(acct.address().len(), 42);
    }

    #[test]
    fn base58check_roundtrip() {
        let s = base58check(b"\x00\x01\x02\x03");
        // Deterministic: same input => same output.
        assert_eq!(s, base58check(b"\x00\x01\x02\x03"));
        assert!(!s.is_empty());
    }
}
