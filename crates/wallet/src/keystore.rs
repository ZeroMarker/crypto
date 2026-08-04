//! Ethereum v3 keystore — the *Web3 Secret Storage Definition*.
//!
//! A standard, portable JSON file that stores a secp256k1 private key
//! encrypted under a human password. This is the file format geth,
//! MyEtherWallet, MetaMask, and every other Ethereum wallet write to disk
//! (`~/.ethereum/keystore/UTC--<timestamp>--<address>`).
//!
//! Layout of the encryption (matching the spec):
//!
//! ```text
//! dk = PBKDF2-HMAC-SHA256(password, salt, c, dklen=32)
//! key       = dk[0..16]            (AES-128 key)
//! mac_input = dk[16..32] ‖ ciphertext
//! mac       = keccak256(mac_input)
//! ciphertext = AES-128-CTR(key, iv, private_key)
//! ```
//!
//! A keystore is only as strong as the password (PBKDF2 makes each guess cost
//! `c` HMAC rounds), so the file itself can live on disk or be backed up
//! anywhere. The `mac` is verified **before** any decryption happens, in
//! constant time, so a wrong password never yields key material.
//!
//! ```
//! use wallet::keystore::Keystore;
//!
//! let key = [0x7a; 32];
//! let ks = Keystore::encrypt(&key, "correct horse battery staple").unwrap();
//! let json = ks.to_json().unwrap();
//! let parsed = Keystore::from_json(&json).unwrap();
//! assert_eq!(parsed.decrypt("correct horse battery staple").unwrap(), key);
//! // Wrong password fails cleanly:
//! assert!(parsed.decrypt("wrong password").is_err());
//! ```

use serde::{Deserialize, Serialize};

use crypto_core::ct::ct_eq_slices;
use crypto_core::hash::keccak256;
use crypto_core::kdf::{pbkdf2_sha256, KdfError};

/// Errors from keystore encryption/decryption.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    /// The JSON had a shape we don't understand (missing fields, bad hex).
    #[error("malformed keystore: {0}")]
    Malformed(String),
    /// `version != 3` — this implementation only reads v3 keystores.
    #[error("unsupported keystore version {0} (expected 3)")]
    UnsupportedVersion(u8),
    /// `crypto.cipher` was not `aes-128-ctr`.
    #[error("unsupported cipher {0:?} (expected \"aes-128-ctr\")")]
    UnsupportedCipher(String),
    /// `crypto.kdf` was not `pbkdf2`.
    #[error("unsupported kdf {0:?} (expected \"pbkdf2\")")]
    UnsupportedKdf(String),
    /// `crypto.kdfparams.prf` was not `hmac-sha256`.
    #[error("unsupported prf {0:?} (expected \"hmac-sha256\")")]
    UnsupportedPrf(String),
    /// The MAC check failed — wrong password, or the file was tampered with.
    #[error("wrong password or corrupted keystore")]
    InvalidPassword,
    /// The derived key length is not 32 bytes (this implementation).
    #[error("unsupported dklen {0} (expected 32)")]
    UnsupportedDkLen(u32),
    /// Underlying KDF failure (e.g. zero iterations).
    #[error("kdf: {0}")]
    Kdf(#[from] KdfError),
}

/// Tunable parameters for [`Keystore::encrypt`]. All fields are optional;
/// `None` picks a secure random value.
#[derive(Debug, Clone)]
pub struct KeystoreOptions {
    /// PBKDF2 iteration count. Default 262144 (the value used by geth /
    /// ethereumjs and the recommended minimum for the format).
    pub iterations: u32,
    /// Fixed salt (32 bytes) — for tests and reproducibility. Random by
    /// default.
    pub salt: Option<[u8; 32]>,
    /// Fixed AES-CTR IV (16 bytes) — for tests and reproducibility. Random by
    /// default.
    pub iv: Option<[u8; 16]>,
    /// Optional `address` field (checksummed `0x...`). Omitted by default.
    pub address: Option<String>,
    /// Optional `id` field (a UUIDv4). Random by default.
    pub id: Option<String>,
}

impl Default for KeystoreOptions {
    fn default() -> Self {
        KeystoreOptions {
            iterations: 262_144,
            salt: None,
            iv: None,
            address: None,
            id: None,
        }
    }
}

/// A complete Web3 Secret Storage (keystore v3) file.
///
/// Serialized/deserialized with serde, so it round-trips to the exact JSON
/// shape the ecosystem expects. `version` is always 3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keystore {
    /// Checksummed address the key belongs to (optional in the format).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The encrypted key material.
    pub crypto: Crypto,
    /// UUIDv4 identifying this keystore file.
    pub id: String,
    /// Format version; must be 3.
    pub version: u8,
}

/// `crypto` object: cipher, KDF, and authentication data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Crypto {
    /// Always `"aes-128-ctr"`.
    pub cipher: String,
    /// IV for the AES-CTR stream.
    pub cipherparams: CipherParams,
    /// Hex-encrypted private key.
    pub ciphertext: String,
    /// Always `"pbkdf2"` in this implementation.
    pub kdf: String,
    /// KDF parameters (iteration count, salt, ...).
    pub kdfparams: KdfParams,
    /// `keccak256(dk[16..32] ‖ ciphertext)` — authenticates both the derived
    /// key and the ciphertext.
    pub mac: String,
}

/// AES-128-CTR parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CipherParams {
    /// 16-byte IV as hex.
    pub iv: String,
}

/// PBKDF2 parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Iteration count (e.g. 262144).
    pub c: u32,
    /// Derived key length in bytes (32).
    pub dklen: u32,
    /// Always `"hmac-sha256"`.
    pub prf: String,
    /// Salt as hex (32 bytes).
    pub salt: String,
}

impl Keystore {
    /// Encrypt a 32-byte private key under `password`, with default
    /// parameters (262144 PBKDF2 iterations, random salt/IV/id).
    pub fn encrypt(private_key: &[u8; 32], password: &str) -> Result<Keystore, KeystoreError> {
        Self::encrypt_with_options(private_key, password, &KeystoreOptions::default())
    }

    /// Encrypt with explicit KDF/cipher parameters (see [`KeystoreOptions`]).
    ///
    /// `salt` and `iv` are normally random; explicit values are for golden
    /// vectors and reproducible tests. Never reuse a salt+IV across keystores
    /// derived from the same password.
    pub fn encrypt_with_options(
        private_key: &[u8; 32],
        password: &str,
        options: &KeystoreOptions,
    ) -> Result<Keystore, KeystoreError> {
        let salt = match options.salt {
            Some(s) => s,
            None => random_bytes(),
        };
        let iv = match options.iv {
            Some(iv) => iv,
            None => random_bytes(),
        };

        // 1. Stretch the password into a 32-byte derived key.
        let dk = pbkdf2_sha256(password.as_bytes(), &salt, options.iterations, 32)?;

        // 2. AES-128-CTR encrypt the private key under dk[0..16].
        let mut ciphertext = *private_key;
        aes128_ctr(&mut ciphertext, &dk[..16], &iv);

        // 3. MAC = keccak256(dk[16..32] ‖ ciphertext): binds the derived key
        //    to the ciphertext so tampering with either is detected.
        let mac_input = [&dk[16..], &ciphertext[..]].concat();
        let mac = keccak256(&mac_input);

        Ok(Keystore {
            address: options.address.clone(),
            crypto: Crypto {
                cipher: "aes-128-ctr".to_string(),
                cipherparams: CipherParams {
                    iv: hex::encode(iv),
                },
                ciphertext: hex::encode(ciphertext),
                kdf: "pbkdf2".to_string(),
                kdfparams: KdfParams {
                    c: options.iterations,
                    dklen: 32,
                    prf: "hmac-sha256".to_string(),
                    salt: hex::encode(salt),
                },
                mac: hex::encode(mac),
            },
            id: options.id.clone().unwrap_or_else(uuid_v4),
            version: 3,
        })
    }

    /// Decrypt the private key. Verifies the MAC in constant time *before*
    /// running the cipher, so a wrong password never produces (partially)
    /// decrypted key material.
    pub fn decrypt(&self, password: &str) -> Result<[u8; 32], KeystoreError> {
        if self.version != 3 {
            return Err(KeystoreError::UnsupportedVersion(self.version));
        }
        if self.crypto.cipher != "aes-128-ctr" {
            return Err(KeystoreError::UnsupportedCipher(self.crypto.cipher.clone()));
        }
        if self.crypto.kdf != "pbkdf2" {
            return Err(KeystoreError::UnsupportedKdf(self.crypto.kdf.clone()));
        }
        if self.crypto.kdfparams.prf != "hmac-sha256" {
            return Err(KeystoreError::UnsupportedPrf(
                self.crypto.kdfparams.prf.clone(),
            ));
        }
        if self.crypto.kdfparams.dklen != 32 {
            return Err(KeystoreError::UnsupportedDkLen(self.crypto.kdfparams.dklen));
        }

        let salt = decode_hex(&self.crypto.kdfparams.salt)?;
        let iv = decode_hex(&self.crypto.cipherparams.iv)?;
        let ciphertext = decode_hex(&self.crypto.ciphertext)?;
        let expected_mac = decode_hex(&self.crypto.mac)?;
        if salt.len() != 32 || iv.len() != 16 || ciphertext.len() != 32 || expected_mac.len() != 32
        {
            return Err(KeystoreError::Malformed(
                "salt (32), iv (16), ciphertext (32) and mac (32) must match their sizes".into(),
            ));
        }

        // Derive + authenticate before any decryption.
        let dk = pbkdf2_sha256(password.as_bytes(), &salt, self.crypto.kdfparams.c, 32)?;
        let mac_input = [&dk[16..], &ciphertext[..]].concat();
        let mac = keccak256(&mac_input);
        if !ct_eq_slices(&mac, &expected_mac) {
            return Err(KeystoreError::InvalidPassword);
        }

        // CTR is symmetric: decrypting is applying the keystream again.
        let mut key = [0u8; 32];
        key.copy_from_slice(&ciphertext);
        aes128_ctr(&mut key, &dk[..16], &iv);
        Ok(key)
    }

    /// Serialize to the exact JSON representation used on disk.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Parse a keystore from JSON.
    pub fn from_json(json: &str) -> Result<Keystore, KeystoreError> {
        serde_json::from_str(json).map_err(|e| KeystoreError::Malformed(e.to_string()))
    }
}

/// Draw 16 (or 32) random bytes from the OS CSPRNG.
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).expect("OS CSPRNG must be available");
    buf
}

/// A random RFC 4122 v4 UUID string, as the keystore `id` field expects.
fn uuid_v4() -> String {
    let mut b = random_bytes::<16>();
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

/// AES-128 in CTR mode: `buf` is both input and output (in place, symmetric).
fn aes128_ctr(buf: &mut [u8], key: &[u8], iv: &[u8]) {
    use aes::Aes128;
    use cipher::{KeyIvInit, StreamCipher};
    use ctr::Ctr128BE;

    let mut cipher = Ctr128BE::<Aes128>::new(key.into(), iv.into());
    cipher.apply_keystream(buf);
}

/// Decode a lowercase/uppercase hex string into bytes.
fn decode_hex(s: &str) -> Result<Vec<u8>, KeystoreError> {
    hex::decode(s).map_err(|e| KeystoreError::Malformed(format!("bad hex in {s:?}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical ethereumjs-wallet test keystore: password "testpassword"
    /// protecting the well-known key `7a28b5ba...`. Every field is pinned, so
    /// any drift in PBKDF2 / AES-CTR / keccak / MAC ordering is caught.
    const VECTOR_JSON: &str = r#"{
      "crypto": {
        "cipher": "aes-128-ctr",
        "cipherparams": {
          "iv": "6087dab2f9fdbbfaddc31a909735c1e6"
        },
        "ciphertext": "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
        "kdf": "pbkdf2",
        "kdfparams": {
          "c": 262144,
          "dklen": 32,
          "prf": "hmac-sha256",
          "salt": "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
        },
        "mac": "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
      },
      "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
      "version": 3
    }"#;

    fn vector_key() -> [u8; 32] {
        hex::decode("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn decrypts_canonical_ethereumjs_vector() {
        let ks = Keystore::from_json(VECTOR_JSON).unwrap();
        assert_eq!(ks.version, 3);
        assert_eq!(ks.decrypt("testpassword").unwrap(), vector_key());
        // Wrong password must be rejected via the MAC, not the cipher.
        assert!(matches!(
            ks.decrypt("not-the-password"),
            Err(KeystoreError::InvalidPassword)
        ));
    }

    #[test]
    fn encrypt_reproduces_canonical_vector() {
        // Re-encrypting the vector's key with its exact salt/IV/iterations
        // must reproduce ciphertext + MAC byte-for-byte. This pins the whole
        // pipeline (PBKDF2 → key split → AES-128-CTR → keccak MAC).
        let opts = KeystoreOptions {
            iterations: 262_144,
            salt: Some(
                hex::decode("ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
            iv: Some(
                hex::decode("6087dab2f9fdbbfaddc31a909735c1e6")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
            id: Some("3198bc9c-6672-5ab3-d995-4942343ae5b6".to_string()),
            address: None,
        };
        let ks = Keystore::encrypt_with_options(&vector_key(), "testpassword", &opts).unwrap();
        assert_eq!(
            ks.crypto.ciphertext,
            "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46"
        );
        assert_eq!(
            ks.crypto.mac,
            "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
        );
        // And it decrypts back under the same password.
        assert_eq!(ks.decrypt("testpassword").unwrap(), vector_key());
    }

    #[test]
    fn roundtrip_with_default_random_parameters() {
        let key = [0x55u8; 32];
        let ks = Keystore::encrypt(&key, "correct horse battery staple").unwrap();
        let json = ks.to_json().unwrap();
        let parsed = Keystore::from_json(&json).unwrap();
        assert_eq!(parsed, ks);
        assert_eq!(parsed.decrypt("correct horse battery staple").unwrap(), key);
        assert!(parsed.decrypt("wrong").is_err());

        // Random salt + IV: two encryptions of the same key must differ.
        let other = Keystore::encrypt(&key, "correct horse battery staple").unwrap();
        assert_ne!(other.crypto.kdfparams.salt, ks.crypto.kdfparams.salt);
        assert_ne!(other.crypto.cipherparams.iv, ks.crypto.cipherparams.iv);
        assert_ne!(other.id, ks.id);
    }

    #[test]
    fn rejects_nonstandard_parameters() {
        let key = [0x11u8; 32];
        let ks = Keystore::encrypt(&key, "pw").unwrap();

        // version must be 3.
        let mut v2 = ks.clone();
        v2.version = 2;
        assert!(matches!(
            v2.decrypt("pw"),
            Err(KeystoreError::UnsupportedVersion(2))
        ));

        // cipher must be aes-128-ctr.
        let mut bad_cipher = ks.clone();
        bad_crypto(&mut bad_cipher).cipher = "aes-128-cbc".into();
        assert!(matches!(
            bad_cipher.decrypt("pw"),
            Err(KeystoreError::UnsupportedCipher(_))
        ));

        // kdf must be pbkdf2.
        let mut bad_kdf = ks.clone();
        bad_crypto(&mut bad_kdf).kdf = "scrypt".into();
        assert!(matches!(
            bad_kdf.decrypt("pw"),
            Err(KeystoreError::UnsupportedKdf(_))
        ));

        // prf must be hmac-sha256.
        let mut bad_prf = ks.clone();
        bad_crypto(&mut bad_prf).kdfparams.prf = "hmac-sha1".into();
        assert!(matches!(
            bad_prf.decrypt("pw"),
            Err(KeystoreError::UnsupportedPrf(_))
        ));

        // dklen must be 32.
        let mut bad_dk = ks.clone();
        bad_crypto(&mut bad_dk).kdfparams.dklen = 64;
        assert!(matches!(
            bad_dk.decrypt("pw"),
            Err(KeystoreError::UnsupportedDkLen(64))
        ));
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let key = [0x22u8; 32];
        let mut ks = Keystore::encrypt(&key, "pw").unwrap();
        // Flip one hex digit of the ciphertext: the MAC must catch it.
        let bytes = hex::decode(&ks.crypto.ciphertext).unwrap();
        let mut tampered = bytes;
        tampered[0] ^= 1;
        bad_crypto(&mut ks).ciphertext = hex::encode(tampered);
        assert!(matches!(
            ks.decrypt("pw"),
            Err(KeystoreError::InvalidPassword)
        ));
    }

    fn bad_crypto(ks: &mut Keystore) -> &mut Crypto {
        &mut ks.crypto
    }
}
