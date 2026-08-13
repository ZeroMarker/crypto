//! Secret handling (roadmap Phase 5): load key material without ever logging
//! it, and wipe it from memory on drop.
//!
//! Sources, in priority order:
//!
//! 1. `WALLET_PRIVATE_KEY` — a hex secp256k1 private key in the environment.
//! 2. `WALLET_KEY_FILE` — a path to a file containing the hex key. The file
//!    must be private to the owner: group/world-readable files are rejected
//!    (`0o077` mask), matching OpenSSH's key-file hygiene.
//!
//! The returned `SigningKey` lives in the [`SecretBytes`] buffer until it is
//! copied into the `k256` key, at which point the buffer is zeroized. The
//! `k256` `SigningKey` itself is not zeroized on drop (upstream limitation),
//! so callers should treat it as short-lived and not clone it around.
//!
//! ```no_run
//! // WALLET_PRIVATE_KEY="...hex..." (or WALLET_KEY_FILE=...)
//! let key = wallet::secrets::load_signing_key().unwrap();
//! ```

use std::fmt;
use std::fs;
use std::path::Path;

use k256::ecdsa::SigningKey;
use zeroize::Zeroize;

/// A byte buffer that is zeroized on drop and never printed.
///
/// The `Debug` impl renders `<redacted>` instead of the contents, so logging
/// a structure that contains one of these cannot leak the secret.
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    /// Wrap a byte buffer. Prefer building buffers via [`SecretBytes::from_hex`]
    /// so the plaintext never sits in a second, non-zeroizing allocation.
    pub fn new(bytes: Vec<u8>) -> SecretBytes {
        SecretBytes { inner: bytes }
    }

    /// Parse a hex string (with or without a `0x` prefix) into a
    /// [`SecretBytes`].
    pub fn from_hex(hex_str: &str) -> Result<SecretBytes, SecretError> {
        let clean = hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim());
        let bytes = hex::decode(clean).map_err(|e| SecretError::BadHex(e.to_string()))?;
        Ok(SecretBytes::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// True when the wrapped buffer is exactly 32 bytes (a secp256k1 scalar).
    pub fn is_key_len(&self) -> bool {
        self.inner.len() == 32
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes({} bytes, <redacted>)", self.inner.len())
    }
}

/// Errors from loading key material.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("no key source found: set WALLET_PRIVATE_KEY (hex) or WALLET_KEY_FILE (path)")]
    NoSource,
    #[error("bad hex in key source: {0}")]
    BadHex(String),
    #[error("key must be exactly 32 bytes, got {0}")]
    BadLength(usize),
    #[error("key file {0}: {1}")]
    KeyFile(String, String),
    #[error("key file {0} is readable by group or others (mode {1:o}); chmod 600")]
    InsecurePermissions(String, u32),
    #[error("invalid secp256k1 key: {0}")]
    InvalidKey(String),
}

/// Load the secp256k1 signing key from `WALLET_PRIVATE_KEY` or
/// `WALLET_KEY_FILE`.
///
/// Returns [`SecretError::NoSource`] when neither is set — a call with no
/// configured secret is a hard error, so a wallet never silently signs with
/// a placeholder key.
pub fn load_signing_key() -> Result<SigningKey, SecretError> {
    let secret = if let Ok(hex_str) = std::env::var("WALLET_PRIVATE_KEY") {
        SecretBytes::from_hex(&hex_str)?
    } else if let Ok(path) = std::env::var("WALLET_KEY_FILE") {
        load_key_file(Path::new(&path))?
    } else {
        return Err(SecretError::NoSource);
    };

    if !secret.is_key_len() {
        return Err(SecretError::BadLength(secret.as_bytes().len()));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(secret.as_bytes());
    drop(secret); // zeroized here
    let sk =
        SigningKey::from_slice(&key_bytes).map_err(|e| SecretError::InvalidKey(e.to_string()))?;
    key_bytes.zeroize();
    Ok(sk)
}

/// Read a hex key from a file, rejecting files that are readable by group or
/// other users (mode & 0o077 != 0). Symlinks are followed; the permission
/// check applies to the target.
fn load_key_file(path: &Path) -> Result<SecretBytes, SecretError> {
    let meta = fs::metadata(path)
        .map_err(|e| SecretError::KeyFile(path.display().to_string(), e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = meta.mode();
        if mode & 0o077 != 0 {
            return Err(SecretError::InsecurePermissions(
                path.display().to_string(),
                mode,
            ));
        }
    }
    let text = fs::read_to_string(path)
        .map_err(|e| SecretError::KeyFile(path.display().to_string(), e.to_string()))?;
    SecretBytes::from_hex(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret_env(key: &str, value: &str) -> guard::EnvGuard {
        guard::EnvGuard::set(key, value)
    }

    mod guard {
        pub struct EnvGuard(String);
        impl EnvGuard {
            pub fn set(key: &str, value: &str) -> EnvGuard {
                std::env::set_var(key, value);
                EnvGuard(key.to_string())
            }
        }
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                std::env::remove_var(&self.0);
            }
        }
    }

    #[test]
    fn debug_redacts_contents() {
        let s = SecretBytes::from_hex("0123456789abcdef").unwrap();
        let printed = format!("{s:?}");
        assert!(!printed.contains("0123456789abcdef"));
        assert!(printed.contains("redacted"));
    }

    #[test]
    fn loads_hex_with_and_without_prefix() {
        let with = SecretBytes::from_hex("0xdeadbeef").unwrap();
        let without = SecretBytes::from_hex("deadbeef").unwrap();
        assert_eq!(with.as_bytes(), without.as_bytes());
        assert_eq!(with.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn rejects_bad_hex() {
        assert!(matches!(
            SecretBytes::from_hex("zzz"),
            Err(SecretError::BadHex(_))
        ));
    }

    #[test]
    fn loads_from_env_and_signs() {
        let _g = secret_env("WALLET_PRIVATE_KEY", &hex::encode([0x11u8; 32]));
        let sk = load_signing_key().unwrap();
        // Same key as k256 sees it: the well-known 0x11*32 scalar.
        let expected = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        assert_eq!(sk.to_bytes().as_slice(), expected.to_bytes().as_slice());
    }

    #[test]
    fn no_source_is_a_hard_error() {
        // Both sources absent => NoSource, never a placeholder key.
        struct Unset;
        impl Drop for Unset {
            fn drop(&mut self) {
                std::env::remove_var("WALLET_PRIVATE_KEY");
                std::env::remove_var("WALLET_KEY_FILE");
            }
        }
        std::env::remove_var("WALLET_PRIVATE_KEY");
        std::env::remove_var("WALLET_KEY_FILE");
        let _guard = Unset;
        assert!(matches!(load_signing_key(), Err(SecretError::NoSource)));
    }

    #[test]
    fn rejects_wrong_length() {
        let _g = secret_env("WALLET_PRIVATE_KEY", "abcd"); // 2 bytes
        assert!(matches!(load_signing_key(), Err(SecretError::BadLength(2))));
    }

    #[test]
    fn rejects_insecure_file_permissions() {
        let dir = std::env::temp_dir().join(format!("wallet-secrets-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key.hex");
        fs::write(&path, hex::encode([0x22u8; 32])).unwrap();

        // Mode 0644 (world-readable) must be rejected.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            let _g = secret_env("WALLET_KEY_FILE", path.to_str().unwrap());
            assert!(matches!(
                load_signing_key(),
                Err(SecretError::InsecurePermissions(_, mode)) if mode & 0o077 != 0
            ));

            // Mode 0600 (owner-only) must be accepted.
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let sk = load_signing_key().unwrap();
            let expected = SigningKey::from_slice(&[0x22u8; 32]).unwrap();
            assert_eq!(sk.to_bytes().as_slice(), expected.to_bytes().as_slice());
        }

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_key_file_errors() {
        let _g = secret_env("WALLET_KEY_FILE", "/nonexistent/definitely-missing-key.hex");
        assert!(matches!(
            load_signing_key(),
            Err(SecretError::KeyFile(_, _))
        ));
    }
}
