//! Proof-of-work: compact-bits difficulty and header mining/validation.
//!
//! Bitcoin packs a 256-bit target into 4 bytes: `bits = (exponent << 24) |
//! mantissa`, where `target = mantissa << (8 * (exponent - 3))`. A header is
//! valid when its work hash, interpreted as a big-endian integer, is strictly
//! less than the target.

use crate::block::BlockHeader;

/// Errors from parsing difficulty bits.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DifficultyError {
    #[error("exponent too large: {0}")]
    ExponentTooLarge(u8),
    #[error("negative or zero target")]
    ZeroTarget,
}

/// A 256-bit proof-of-work target, big-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    bytes: [u8; 32],
}

impl Target {
    /// Decode Bitcoin compact bits into a target.
    ///
    /// `0x1d00ffff` is the difficulty-1 target: `0x00ffff << (8 * (29-3))`.
    ///
    /// ```
    /// use chain::{Target, compute_target};
    ///
    /// let t = compute_target(0x1d00ffff).unwrap();
    /// assert_eq!(
    ///     t.to_hex(),
    ///     "00000000ffff0000000000000000000000000000000000000000000000000000"
    /// );
    /// ```
    pub fn from_compact(bits: u32) -> Result<Target, DifficultyError> {
        let exponent = (bits >> 24) as u8;
        let mantissa = bits & 0x007f_ffff; // sign bit stripped; positive targets only

        if exponent > 32 {
            return Err(DifficultyError::ExponentTooLarge(exponent));
        }
        if mantissa == 0 {
            return Err(DifficultyError::ZeroTarget);
        }

        if exponent < 3 {
            // value shrinks: target = mantissa >> (8 * (3 - exponent))
            let value = mantissa >> (8 * (3 - exponent));
            if value == 0 {
                return Err(DifficultyError::ZeroTarget);
            }
            let mut bytes = [0u8; 32];
            let n = if exponent == 2 { 2 } else { 1 };
            for i in 0..n {
                bytes[31 - i] = ((value >> (8 * i)) & 0xff) as u8;
            }
            return Ok(Target { bytes });
        }

        // value occupies the top `exponent` bytes: mantissa first, then zeros.
        let mut bytes = [0u8; 32];
        let start = 32 - exponent as usize;
        bytes[start] = ((mantissa >> 16) & 0xff) as u8;
        bytes[start + 1] = ((mantissa >> 8) & 0xff) as u8;
        bytes[start + 2] = (mantissa & 0xff) as u8;
        Ok(Target { bytes })
    }

    /// Whether a block hash satisfies this target (hash < target, big-endian).
    pub fn is_met_by(&self, hash: &[u8; 32]) -> bool {
        for (a, b) in hash.iter().zip(self.bytes.iter()) {
            match a.cmp(b) {
                std::cmp::Ordering::Less => return true,
                std::cmp::Ordering::Greater => return false,
                std::cmp::Ordering::Equal => {}
            }
        }
        false
    }

    /// Hex of the big-endian target bytes.
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Convenience: decode compact bits into a [`Target`].
pub fn compute_target(bits: u32) -> Result<Target, DifficultyError> {
    Target::from_compact(bits)
}

/// The header work hash (same as [`BlockHeader::hash`]).
pub fn header_hash(header: &BlockHeader) -> [u8; 32] {
    header.hash()
}

/// Mine a header: increment `nonce` until the hash meets `target`.
/// Returns whether a solution was found and the number of attempts.
///
/// The example uses an almost-trivial target (`0x20ffffff` ≈ 2^255) so it
/// terminates quickly; real targets are far below this.
///
/// ```
/// use chain::{BlockHeader, compute_target, mine};
///
/// let target = compute_target(0x207fffff).unwrap();
/// let mut h = BlockHeader {
///     prev_hash: [0u8; 32],
///     merkle_root: [1u8; 32],
///     timestamp: 0,
///     bits: 0x207fffff,
///     nonce: 0,
/// };
/// let (mined, attempts) = mine(&mut h, &target, 1_000_000);
/// assert!(mined);
/// assert!(target.is_met_by(&h.hash()));
/// assert!(attempts <= 1_000_000);
/// ```
pub fn mine(header: &mut BlockHeader, target: &Target, max_attempts: u64) -> (bool, u64) {
    for attempt in 0..max_attempts {
        header.nonce = attempt;
        if target.is_met_by(&header.hash()) {
            return (true, attempt + 1);
        }
    }
    (false, max_attempts)
}
