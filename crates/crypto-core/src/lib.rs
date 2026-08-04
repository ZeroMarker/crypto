//! # crypto-core
//!
//! Reusable cryptography primitives for the Rust-for-crypto roadmap (Phase 1).
//!
//! Provides thin, documented wrappers around well-audited crates so the rest of
//! the workspace (and your own code) has one consistent API surface:
//!
//! - **Hashing**: SHA-256, Keccak-256, RIPEMD-160
//! - **MACs**: HMAC-SHA256
//! - **Signatures**: ECDSA (secp256k1) sign/verify with DER serialization
//! - **AEAD**: AES-256-GCM and ChaCha20-Poly1305 with random nonces
//!
//! ## Example
//!
//! ```no_run
//! use crypto_core::hash;
//! use hex::ToHex;
//!
//! let digest = hash::sha256(b"hello world");
//! println!("{}", digest.encode_hex::<String>());
//! ```

/// Hashes and message digests.
///
/// All functions return a `[u8; N]` fixed-size digest. Callers should compare
/// digests with constant-time comparison (e.g. `subtle` / `ring`), never `==`
/// on untrusted data.
pub mod hash {
    use sha2::{Digest, Sha256};

    /// SHA-256 digest of `data`. 32 bytes.
    ///
    /// ```
    /// use crypto_core::hash::sha256;
    /// use hex::ToHex;
    ///
    /// // NIST vector for "abc"
    /// assert_eq!(
    ///     sha256(b"abc").encode_hex::<String>(),
    ///     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    /// );
    /// ```
    pub fn sha256(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    /// Keccak-256 digest of `data` (the variant Ethereum uses). 32 bytes.
    ///
    /// This is **not** the NIST SHA3-256 (`sha3-256`); Ethereum's `keccak256`
    /// pre-dates the NIST standard. Use `keccak256` for EVM address/payload
    /// hashing and `sha3_256` for standards-compliant SHA3.
    ///
    /// ```
    /// use crypto_core::hash::keccak256;
    /// use hex::ToHex;
    ///
    /// assert_eq!(
    ///     keccak256(b"").encode_hex::<String>(),
    ///     "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    /// );
    /// ```
    pub fn keccak256(data: &[u8]) -> [u8; 32] {
        use sha3::{Digest, Keccak256};
        Keccak256::digest(data).into()
    }

    /// NIST SHA3-256 digest of `data`. 32 bytes.
    ///
    /// ```
    /// use crypto_core::hash::sha3_256;
    /// use hex::ToHex;
    ///
    /// assert_eq!(
    ///     sha3_256(b"abc").encode_hex::<String>(),
    ///     "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    /// );
    /// ```
    pub fn sha3_256(data: &[u8]) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        Sha3_256::digest(data).into()
    }

    /// RIPEMD-160 digest of `data`. 20 bytes. Used by Bitcoin for address
    /// checksums (`HASH160` = RIPEMD160(SHA256(pubkey))).
    ///
    /// ```
    /// use crypto_core::hash::ripemd160;
    /// use hex::ToHex;
    ///
    /// assert_eq!(
    ///     ripemd160(b"abc").encode_hex::<String>(),
    ///     "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
    /// );
    /// ```
    pub fn ripemd160(data: &[u8]) -> [u8; 20] {
        use ripemd::{Digest, Ripemd160};
        Ripemd160::digest(data).into()
    }

    /// `HASH256` = SHA-256 applied twice — Bitcoin's work hash and merkle
    /// tree hash. 32 bytes.
    ///
    /// ```
    /// use crypto_core::hash::hash256;
    /// use hex::ToHex;
    ///
    /// assert_eq!(
    ///     hash256(b"").encode_hex::<String>(),
    ///     "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
    /// );
    /// ```
    pub fn hash256(data: &[u8]) -> [u8; 32] {
        sha256(&sha256(data))
    }

    /// HMAC-SHA256 keyed MAC of `data` under `key`. 32 bytes.
    ///
    /// Used as a building block for HKDF, TOTP, and webhook signing.
    ///
    /// ```
    /// use crypto_core::hash::hmac_sha256;
    /// use hex::ToHex;
    ///
    /// // RFC 4231 test case 1
    /// let key = b"\x0b".repeat(20);
    /// let data = b"Hi There";
    /// assert_eq!(
    ///     hmac_sha256(&key, data).encode_hex::<String>(),
    ///     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    /// );
    /// ```
    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }
}

/// Constant-time helpers for comparing secrets and digests.
///
/// `==` on `[u8]` short-circuits on the first differing byte, leaking *where*
/// the inputs differ through timing. That is enough to recover passwords,
/// HMAC tags, or AEAD keys one byte at a time over many measurements. All
/// comparisons here take time proportional to the length of the inputs only.
pub mod ct {
    /// Constant-time equality for fixed-size byte arrays.
    ///
    /// ```
    /// use crypto_core::ct::{ct_eq, ct_eq_slices};
    ///
    /// assert!(ct_eq(&[1u8, 2, 3], &[1u8, 2, 3]));
    /// assert!(!ct_eq(&[1u8, 2, 3], &[1u8, 2, 4]));
    /// // Different lengths always compare unequal (no timing signal about
    /// // *where* they differ):
    /// assert!(!ct_eq_slices(&[1u8, 2, 3], &[1u8, 2]));
    /// ```
    pub fn ct_eq<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
        subtle::ConstantTimeEq::ct_eq(a.as_slice(), b.as_slice()).into()
    }

    /// Constant-time equality for (possibly different-length) byte slices.
    pub fn ct_eq_slices(a: &[u8], b: &[u8]) -> bool {
        subtle::ConstantTimeEq::ct_eq(a, b).into()
    }
}

/// Key derivation.
///
/// HKDF-SHA256 (RFC 5869) turns a possibly-weak input key material into
/// arbitrarily long, cryptographically strong keying material, optionally
/// bound to a salt and application context (`info`). Used for:
///
/// - deriving per-device keys from a master secret
/// - deriving a session key from an ECDH shared secret
/// - splitting one key into separate encryption/MAC keys
pub mod kdf {
    use crate::hash::hmac_sha256;

    /// Errors from key derivation (HKDF / PBKDF2).
    #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
    pub enum KdfError {
        /// The requested output length exceeds the KDF's limit (255 * 32 bytes
        /// for HKDF, (2^32 - 1) * 32 bytes for PBKDF2).
        #[error("requested output length {0} exceeds the KDF limit")]
        OutputTooLong(usize),
        /// PBKDF2 requires at least one iteration.
        #[error("iteration count must be >= 1")]
        ZeroIterations,
    }

    /// HKDF-SHA256 (RFC 5869).
    ///
    /// - `ikm` — input key material (the secret you're stretching).
    /// - `salt` — optional; an empty slice uses `HashLen` zeros as the salt
    ///   (valid per the RFC). A random salt makes output key material
    ///   independent of the ikm's statistical structure.
    /// - `info` — optional application context; binds the output to its use,
    ///   so keys for different purposes never collide.
    /// - `out_len` — number of output bytes (1..=255*32).
    ///
    /// ```
    /// use crypto_core::kdf::hkdf_sha256;
    /// use hex::ToHex;
    ///
    /// // RFC 5869 test case 1
    /// let ikm = hex::decode("0b" .repeat(22)).unwrap();
    /// let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    /// let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    /// let okm = hkdf_sha256(&ikm, &salt, &info, 42).unwrap();
    /// assert_eq!(
    ///     okm.encode_hex::<String>(),
    ///     "3cb25f25faacd57a90434f64d0362f2a\
    ///      2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
    ///      34007208d5b887185865"
    /// );
    /// ```
    pub fn hkdf_sha256(
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        out_len: usize,
    ) -> Result<Vec<u8>, KdfError> {
        if out_len > 255 * 32 {
            return Err(KdfError::OutputTooLong(out_len));
        }

        // Extract: PRK = HMAC-SHA256(salt, IKM). An empty salt is replaced by
        // 32 zero bytes (the RFC's "HashLen zeroes").
        let prk = hmac_sha256(if salt.is_empty() { &[0u8; 32] } else { salt }, ikm);

        // Expand: T(0) = empty, T(i) = HMAC(PRK, T(i-1) || info || i), with a
        // single-byte block counter capped at 255 by the length check above.
        // (u16 so the counter never overflows at the 255*32 boundary.)
        let mut out = Vec::with_capacity(out_len);
        let mut t = Vec::new(); // T(i-1)
        let mut counter = 1u16;
        while out.len() < out_len {
            t.extend_from_slice(info);
            t.push(counter as u8);
            t = hmac_sha256(&prk, &t).to_vec();
            let take = (out_len - out.len()).min(t.len());
            out.extend_from_slice(&t[..take]);
            counter += 1;
        }
        Ok(out)
    }

    /// PBKDF2-HMAC-SHA256 (RFC 8018 §5.2).
    ///
    /// Password-based key derivation: stretches a low-entropy password into a
    /// `dk_len`-byte key. Each guess costs `iterations` HMAC-SHA256 rounds, so
    /// brute force is deliberately expensive. `salt` should be unique per
    /// password (random for new keys, stored alongside the derived key).
    ///
    /// Used by the Ethereum v3 keystore format and BIP-39 seeds.
    ///
    /// ```
    /// use crypto_core::kdf::pbkdf2_sha256;
    /// use hex::ToHex;
    ///
    /// // RFC 7914 §11 test vector (PBKDF2-HMAC-SHA256)
    /// let dk = pbkdf2_sha256(b"password", b"salt", 1, 32).unwrap();
    /// assert_eq!(
    ///     dk.encode_hex::<String>(),
    ///     "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    /// );
    /// ```
    pub fn pbkdf2_sha256(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        dk_len: usize,
    ) -> Result<Vec<u8>, KdfError> {
        if iterations == 0 {
            return Err(KdfError::ZeroIterations);
        }
        if dk_len > (u32::MAX as usize) * 32 {
            return Err(KdfError::OutputTooLong(dk_len));
        }

        // DK = T_1 || T_2 || ... || T_l, one 32-byte block per counter value.
        // T_i = U_1 XOR U_2 XOR ... XOR U_c, where U_1 = PRF(P, S || INT(i))
        // and U_j = PRF(P, U_{j-1}) with INT(i) a 4-byte big-endian counter.
        let blocks = dk_len.div_ceil(32);
        let mut out = Vec::with_capacity(blocks * 32);
        for block in 1..=blocks as u32 {
            let mut u = Vec::with_capacity(salt.len() + 4);
            u.extend_from_slice(salt);
            u.extend_from_slice(&block.to_be_bytes());
            u = hmac_sha256(password, &u).to_vec();
            let mut t = u.clone();
            for _ in 1..iterations {
                u = hmac_sha256(password, &u).to_vec();
                for (x, y) in t.iter_mut().zip(u.iter()) {
                    *x ^= *y;
                }
            }
            out.extend_from_slice(&t);
        }
        out.truncate(dk_len);
        Ok(out)
    }
}

/// Authenticated encryption with associated data (AEAD).
///
/// Nonce generation is the one place AEAD fails catastrophically: reusing a
/// `(key, nonce)` pair lets an attacker recover the keystream and forge tags.
/// Every encryption here therefore draws a fresh 12-byte nonce from the OS
/// CSPRNG (`getrandom`), so the same plaintext encrypted twice produces two
/// unrelated ciphertexts. If you need reproducible ciphertexts (golden test
/// vectors), use the explicit-`nonce` variants and never reuse a nonce with
/// the same key in production.
pub mod aead {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce as AesNonce};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChachaNonce};

    /// A nonce + ciphertext + tag bundle ready for storage.
    ///
    /// The nonce is randomly generated by [`encrypt_aes_gcm`] /
    /// [`encrypt_chacha`] and must never be reused with the same key.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Ciphertext {
        pub nonce: Vec<u8>,
        pub data: Vec<u8>,
    }

    /// Draw 12 random bytes from the OS CSPRNG.
    fn random_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).expect("OS CSPRNG must be available");
        nonce
    }

    /// AES-256-GCM encrypt with a fresh random 12-byte nonce. `aad` is
    /// authenticated but not encrypted (e.g. the address the ciphertext
    /// belongs to).
    ///
    /// ```
    /// use crypto_core::aead::{decrypt_aes_gcm, encrypt_aes_gcm};
    ///
    /// let key = [7u8; 32];
    /// let ct = encrypt_aes_gcm(&key, b"private data", b"address-0x1234").unwrap();
    /// let pt = decrypt_aes_gcm(&key, &ct, b"address-0x1234").unwrap();
    /// assert_eq!(pt, b"private data");
    /// ```
    pub fn encrypt_aes_gcm(
        key: &[u8; 32],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Ciphertext, aes_gcm::Error> {
        encrypt_aes_gcm_with_nonce(key, random_nonce(), plaintext, aad)
    }

    /// AES-256-GCM encrypt under an explicit nonce. **Tests/vectors only**:
    /// reusing a nonce with the same key is fatal for GCM.
    pub fn encrypt_aes_gcm_with_nonce(
        key: &[u8; 32],
        nonce: [u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Ciphertext, aes_gcm::Error> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        // aes-gcm's allocating encrypt() returns ciphertext+tag; the nonce is
        // kept separately in `Ciphertext.nonce`.
        let out = cipher.encrypt(
            AesNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )?;
        Ok(Ciphertext {
            nonce: nonce.to_vec(),
            data: out,
        })
    }

    /// Decrypt a [`Ciphertext`] produced by [`encrypt_aes_gcm`]. Returns an
    /// error if the tag fails to verify (tampered data / wrong key).
    pub fn decrypt_aes_gcm(
        key: &[u8; 32],
        ct: &Ciphertext,
        aad: &[u8],
    ) -> Result<Vec<u8>, aes_gcm::Error> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        cipher.decrypt(
            AesNonce::from_slice(&ct.nonce),
            Payload { msg: &ct.data, aad },
        )
    }

    /// ChaCha20-Poly1305 encrypt with a fresh random 12-byte nonce.
    ///
    /// Preferred over AES-GCM on hardware without AES-NI (common on cloud VMs).
    pub fn encrypt_chacha(
        key: &[u8; 32],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Ciphertext, chacha20poly1305::aead::Error> {
        encrypt_chacha_with_nonce(key, random_nonce(), plaintext, aad)
    }

    /// ChaCha20-Poly1305 encrypt under an explicit nonce. **Tests/vectors
    /// only**: nonce reuse with the same key destroys confidentiality.
    pub fn encrypt_chacha_with_nonce(
        key: &[u8; 32],
        nonce: [u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Ciphertext, chacha20poly1305::aead::Error> {
        let cipher = ChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
        let out = cipher.encrypt(
            ChachaNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )?;
        Ok(Ciphertext {
            nonce: nonce.to_vec(),
            data: out,
        })
    }

    /// Decrypt a [`Ciphertext`] produced by [`encrypt_chacha`].
    pub fn decrypt_chacha(
        key: &[u8; 32],
        ct: &Ciphertext,
        aad: &[u8],
    ) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
        let cipher = ChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
        cipher.decrypt(
            ChachaNonce::from_slice(&ct.nonce),
            Payload { msg: &ct.data, aad },
        )
    }
}

/// Digital signatures.
pub mod sign {
    use hex::ToHex;
    use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};

    /// An ECDSA signature over secp256k1, serialized as 65-byte `r || s || v`
    /// (Ethereum "raw" format) or 64-byte `r || s` (compact). Keep `v` for
    /// Ethereum-style recovery; drop it for Bitcoin.
    ///
    /// `s` is always normalized to the low half of the curve order
    /// (EIP-2 canonical form), and `v` is the recovery id consistent with
    /// that normalization, so [`recover_verifying_key`] round-trips.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SignatureData {
        pub r: [u8; 32],
        pub s: [u8; 32],
        pub v: u8,
    }

    /// Generate a fresh secp256k1 key pair from `seed` (32 bytes).
    ///
    /// ```
    /// use crypto_core::sign::{sign_digest, verify_digest};
    ///
    /// let (sk, pk) = crypto_core::sign::keypair_from_seed(&[42u8; 32]);
    /// let sig = sign_digest(&sk, &[9u8; 32]);
    /// assert!(verify_digest(&pk, &[9u8; 32], &sig));
    /// ```
    pub fn keypair_from_seed(seed: &[u8; 32]) -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_slice(seed).expect("valid scalar");
        let pk = VerifyingKey::from(&sk);
        (sk, pk)
    }

    /// Sign a 32-byte digest (the thing you hash with [`crate::hash::sha256`]
    /// or [`crate::hash::keccak256`] first). Returns `r || s || v` with `s` in
    /// canonical low-`s` form (EIP-2) and `v` matching, so the signature can
    /// be recovered back to the public key.
    pub fn sign_digest(sk: &SigningKey, digest: &[u8; 32]) -> SignatureData {
        // `sign_prehash_recoverable` already normalizes `s` to the low half of
        // the curve order and returns the `RecoveryId` consistent with that
        // normalization, so no manual low-`s` fix-up is needed.
        let (sig, recovery_id) = sk.sign_prehash_recoverable(digest).expect("sign");
        SignatureData {
            r: sig.r().to_bytes().into(),
            s: sig.s().to_bytes().into(),
            v: recovery_id.to_byte(),
        }
    }

    /// Verify `sig` against `digest` and public key. Constant-time against the
    /// public key; use on-chain-recovered values from trusted input.
    pub fn verify_digest(pk: &VerifyingKey, digest: &[u8; 32], sig: &SignatureData) -> bool {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&sig.r);
        bytes[32..].copy_from_slice(&sig.s);
        match Signature::try_from(bytes.as_slice()) {
            Ok(s) => pk.verify_prehash(digest, &s).is_ok(),
            Err(_) => false,
        }
    }

    /// Recover the signer's public key from a digest and `r || s || v`
    /// signature (Ethereum-style). Returns `None` for malformed signatures or
    /// an out-of-range `v`.
    ///
    /// ```
    /// use crypto_core::sign::recover_verifying_key;
    ///
    /// let (sk, pk) = crypto_core::sign::keypair_from_seed(&[5u8; 32]);
    /// let sig = crypto_core::sign::sign_digest(&sk, &[9u8; 32]);
    /// let recovered = recover_verifying_key(&[9u8; 32], &sig).unwrap();
    /// assert_eq!(recovered, pk);
    /// ```
    pub fn recover_verifying_key(digest: &[u8; 32], sig: &SignatureData) -> Option<VerifyingKey> {
        let id = RecoveryId::from_byte(sig.v)?;
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&sig.r);
        bytes[32..].copy_from_slice(&sig.s);
        let s = Signature::try_from(bytes.as_slice()).ok()?;
        VerifyingKey::recover_from_prehash(digest, &s, id).ok()
    }

    /// Convert a `SignatureData` to its hex form `0x..` (64 bytes, no `v`).
    ///
    /// ```
    /// use crypto_core::sign::{signature_to_hex, SignatureData};
    /// let sig = SignatureData { r: [1; 32], s: [2; 32], v: 0 };
    /// assert_eq!(signature_to_hex(&sig).len(), 2 + 128);
    /// ```
    pub fn signature_to_hex(sig: &SignatureData) -> String {
        let mut out = sig.r.to_vec();
        out.extend_from_slice(&sig.s);
        format!("0x{}", out.encode_hex::<String>())
    }
}

#[cfg(test)]
mod tests {
    use crate::ct::ct_eq;
    use crate::hash::hmac_sha256;
    use crate::kdf::{hkdf_sha256, pbkdf2_sha256, KdfError};

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(&[1u8; 8], &[1u8; 8]));
        assert!(!ct_eq(&[1u8; 8], &[2u8; 8]));
        // A single differing trailing byte must be caught.
        assert!(!ct_eq(&[1u8, 2, 3, 4], &[1u8, 2, 3, 5]));
    }

    #[test]
    fn hkdf_rfc5869_case_1() {
        // RFC 5869 test case 1: SHA-256, 42-byte OKM.
        let ikm = b"\x0b".repeat(22);
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let okm = hkdf_sha256(&ikm, &salt, &info, 42).unwrap();
        assert_eq!(
            hex::encode(&okm),
            "3cb25f25faacd57a90434f64d0362f2a\
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
        );
    }

    #[test]
    fn hkdf_rfc5869_case_3_no_salt_no_info() {
        // RFC 5869 test case 3: empty salt and info (exercise the
        // zero-salt fallback and long output > one block).
        let ikm = b"\x0b".repeat(22);
        let okm = hkdf_sha256(&ikm, &[], &[], 42).unwrap();
        assert_eq!(
            hex::encode(&okm),
            "8da4e775a563c18f715f802a063c5a31\
             b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn hkdf_rejects_overlong_output() {
        assert!(hkdf_sha256(b"ikm", b"", b"", 255 * 32 + 1).is_err());
        assert!(hkdf_sha256(b"ikm", b"", b"", 255 * 32).is_ok());
    }

    #[test]
    fn pbkdf2_rfc7914_vectors() {
        // RFC 7914 §11: PBKDF2-HMAC-SHA256 vectors.
        assert_eq!(
            hex::encode(pbkdf2_sha256(b"password", b"salt", 1, 32).unwrap()),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
        assert_eq!(
            hex::encode(pbkdf2_sha256(b"password", b"salt", 2, 32).unwrap()),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        );
        assert_eq!(
            hex::encode(pbkdf2_sha256(b"password", b"salt", 4096, 32).unwrap()),
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
        );
    }

    #[test]
    fn pbkdf2_multi_block_and_errors() {
        // 64-byte output exercises the T_1 || T_2 block concatenation.
        let dk = pbkdf2_sha256(b"password", b"salt", 1, 64).unwrap();
        assert_eq!(dk.len(), 64);
        // The first 32 bytes are the RFC vector above (deterministic blocks).
        assert_eq!(
            hex::encode(&dk[..32]),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
        // Zero iterations are rejected, not silently accepted.
        assert!(matches!(
            pbkdf2_sha256(b"password", b"salt", 0, 32),
            Err(KdfError::ZeroIterations)
        ));
        // 32-byte truncation of a longer derivation.
        assert_eq!(
            pbkdf2_sha256(b"password", b"salt", 1, 16).unwrap(),
            &pbkdf2_sha256(b"password", b"salt", 1, 32).unwrap()[..16]
        );
    }

    #[test]
    fn hkdf_splits_one_key_into_two_independent_ones() {
        // Deriving for different `info` contexts must give unrelated keys:
        // the real reason to bind keys to their purpose.
        let master = hmac_sha256(b"master", b"seed");
        let enc = hkdf_sha256(&master, b"salt", b"encryption", 32).unwrap();
        let mac = hkdf_sha256(&master, b"salt", b"mac", 32).unwrap();
        assert_ne!(enc, mac);
        // And the derivation is deterministic.
        assert_eq!(
            enc,
            hkdf_sha256(&master, b"salt", b"encryption", 32).unwrap()
        );
    }
}
