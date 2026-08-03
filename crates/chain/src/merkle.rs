//! Merkle tree roots and SPV membership proofs.
//!
//! The tree is Bitcoin-style: leaves are txids, each internal node is the
//! [`crypto_core::hash::hash256`] of its two children, and when a level has an
//! odd count the final node is duplicated (hashed with itself) before pairing.

use crypto_core::hash::hash256;

/// The 32-byte zero hash, used to mark the root of an empty tree.
pub const ZERO_HASH: [u8; 32] = [0u8; 32];

/// Compute the merkle root over `txids`. An empty list yields [`ZERO_HASH`];
/// a single txid yields that txid unchanged (matching Bitcoin).
///
/// ```
/// use chain::{merkle_root, ZERO_HASH};
///
/// assert_eq!(merkle_root(&[]), ZERO_HASH);
/// let tx = [7u8; 32];
/// assert_eq!(merkle_root(&[tx]), tx);
///
/// // Two txs: root = hash256(tx1 || tx2).
/// let a = [1u8; 32];
/// let b = [2u8; 32];
/// assert_eq!(
///     merkle_root(&[a, b]),
///     chain::hash256(&[a, b].concat())
/// );
/// ```
pub fn merkle_root(txids: &[[u8; 32]]) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = txids.to_vec();
    if level.is_empty() {
        return ZERO_HASH;
    }
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().unwrap();
            level.push(last);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pair[0]);
            buf[32..].copy_from_slice(&pair[1]);
            next.push(hash256(&buf));
        }
        level = next;
    }
    level[0]
}

/// A merkle branch proving a txid is a leaf of a tree. Each step records the
/// sibling hash and whether the current node sits on the right side (so the
/// verifier knows whether to prepend or append the sibling).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    pub steps: Vec<Step>,
}

/// One level of a merkle proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// The sibling hash at this level.
    pub sibling: [u8; 32],
    /// True if the node we are tracking is the right child.
    pub on_right: bool,
}

impl MerkleProof {
    /// Build a proof for `index` within `txids`.
    pub fn new(txids: &[[u8; 32]], index: usize) -> Option<MerkleProof> {
        if index >= txids.len() {
            return None;
        }
        let mut level: Vec<[u8; 32]> = txids.to_vec();
        let mut steps = Vec::new();
        let mut pos = index;

        while level.len() > 1 {
            if level.len() % 2 == 1 {
                level.push(*level.last().unwrap());
            }
            let sibling_index = pos ^ 1;
            let on_right = pos % 2 == 1;
            let sibling = level[sibling_index];
            steps.push(Step { sibling, on_right });

            let mut next = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks_exact(2) {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&pair[0]);
                buf[32..].copy_from_slice(&pair[1]);
                next.push(hash256(&buf));
            }
            pos /= 2;
            level = next;
        }
        Some(MerkleProof { steps })
    }

    /// Reconstruct the root from a leaf txid and this proof.
    pub fn root(&self, txid: [u8; 32]) -> [u8; 32] {
        let mut node = txid;
        for step in &self.steps {
            let mut buf = [0u8; 64];
            if step.on_right {
                buf[..32].copy_from_slice(&step.sibling);
                buf[32..].copy_from_slice(&node);
            } else {
                buf[..32].copy_from_slice(&node);
                buf[32..].copy_from_slice(&step.sibling);
            }
            node = hash256(&buf);
        }
        node
    }

    /// Verify `txid` is a member of the tree with `root`. Cost is
    /// `O(log n)` hashes — the whole point of SPV.
    ///
    /// ```
    /// use chain::{MerkleProof, merkle_root};
    ///
    /// let txids: Vec<[u8; 32]> = (0..16u8).map(|i| [i; 32]).collect();
    /// let root = merkle_root(&txids);
    /// let proof = MerkleProof::new(&txids, 5).unwrap();
    /// assert!(proof.verify(txids[5], root));
    /// assert!(!proof.verify([0xff; 32], root));
    /// ```
    pub fn verify(&self, txid: [u8; 32], root: [u8; 32]) -> bool {
        self.root(txid) == root
    }
}

/// Convenience for tests / docs: verify a proof without constructing
/// [`MerkleProof`] explicitly.
pub fn verify_proof(txid: [u8; 32], root: [u8; 32], proof: &MerkleProof) -> bool {
    proof.verify(txid, root)
}
