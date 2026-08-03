//! # chain
//!
//! A small proof-of-work blockchain for the Rust-for-crypto roadmap (Phase 3 —
//! "blockchain node / ledger"). Implements the parts that make a ledger a
//! ledger:
//!
//! - [`merkle`]: Merkle tree roots and SPV (simplified-payment-verification)
//!   membership proofs
//! - [`block`]: transaction, header, and block types
//! - [`pow`]: compact-bits difficulty targets, mining, and header validation
//! - [`chain`]: append-only store with full block validation and longest-chain
//!   reorg handling
//! - [`mempool`]: a UTXO-set-backed transaction pool that rejects double
//!   spends and stays consistent with confirmed blocks
//!
//! This is a *teaching* chain: the wire formats are intentionally minimal and
//! documented, not byte-compatible with Bitcoin or Ethereum.

pub mod block;
pub mod chain;
pub mod mempool;
pub mod merkle;
pub mod pow;

pub use block::{Block, BlockHeader, OutPoint, Transaction, TxIn, TxOut};
pub use chain::{make_genesis, BlockChain, ChainError, SubmitOutcome};
pub use mempool::{Mempool, MempoolError, UtxoSet};
pub use merkle::{merkle_root, verify_proof, MerkleProof, ZERO_HASH};
pub use pow::{compute_target, header_hash, mine, DifficultyError, Target};

/// Re-export of the double-SHA256 hash for convenience.
pub use crypto_core::hash::hash256;
