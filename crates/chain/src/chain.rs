//! Block store with validation and longest-chain reorg handling.
//!
//! Nodes keep every block they've seen (even side branches); the *active*
//! chain is the branch with the most blocks. When a longer branch arrives we
//! switch the active head, which is what makes the chain eventually consistent.

use std::collections::HashMap;

use crate::block::{Block, BlockHeader};
use crate::pow::Target;

/// Result of submitting a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// New active tip; the chain grew by one (or a reorg happened).
    Accepted { new_height: u64 },
    /// Valid block on a side branch, shorter than the active tip.
    Orphan { height: u64 },
    /// Duplicate of an already-known block.
    Duplicate,
}

/// Errors from block validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error("genesis already set")]
    GenesisAlreadySet,
    #[error("prev_hash {0:?} is not a known block")]
    UnknownParent([u8; 32]),
    #[error("block merkle root does not match its transactions")]
    MerkleMismatch,
    #[error("proof of work not satisfied")]
    InvalidPow,
    #[error("block height {0} does not follow parent height {1}")]
    BadHeight(u64, u64),
    #[error("timestamp not strictly greater than parent: {0} <= {1}")]
    BadTimestamp(u32, u32),
    /// Clock-skew drill: the block is stamped too far in the future
    /// (`timestamp > now + tolerance`).
    #[error("timestamp {0} is more than {1}s ahead of local time")]
    FutureTimestamp(u32, u32),
}

/// An in-memory blockchain. Holds all seen blocks plus the active chain.
///
/// Blocks reference their parent by hash; `blocks` stores everything and
/// `active_head` points at the longest valid chain.
#[derive(Debug, Clone)]
pub struct BlockChain {
    blocks: HashMap<[u8; 32], Block>,
    height: HashMap<[u8; 32], u64>,
    active_head: [u8; 32],
    /// Maximum seconds a block may be stamped ahead of local time (clock-skew
    /// protection). `None` disables the check.
    max_future_skew: Option<u32>,
}

impl BlockChain {
    /// A chain starting from the given genesis block. The genesis header must
    /// have `prev_hash == [0; 32]` and satisfy its own PoW.
    pub fn new(genesis: Block) -> Result<BlockChain, ChainError> {
        validate_structure(&genesis)?;
        if genesis.header.prev_hash != [0u8; 32] {
            return Err(ChainError::UnknownParent([0u8; 32]));
        }
        let genesis_hash = genesis.hash();
        let mut blocks = HashMap::new();
        let mut height = HashMap::new();
        blocks.insert(genesis_hash, genesis);
        height.insert(genesis_hash, 0);
        Ok(BlockChain {
            blocks,
            height,
            active_head: genesis_hash,
            max_future_skew: None,
        })
    }

    /// Enable clock-skew protection: reject blocks stamped more than `skew`
    /// seconds ahead of local time (roadmap Phase 5 "clock skew" drill).
    /// `None` (the default) accepts any future timestamp.
    pub fn with_future_skew(mut self, skew: u32) -> BlockChain {
        self.max_future_skew = Some(skew);
        self
    }

    pub fn active_tip(&self) -> [u8; 32] {
        self.active_head
    }

    pub fn active_height(&self) -> u64 {
        self.height[&self.active_head]
    }

    pub fn block(&self, hash: &[u8; 32]) -> Option<&Block> {
        self.blocks.get(hash)
    }

    pub fn height_of(&self, hash: &[u8; 32]) -> Option<u64> {
        self.height.get(hash).copied()
    }

    /// Validate and store a block, possibly switching the active chain.
    pub fn submit(&mut self, block: Block) -> Result<SubmitOutcome, ChainError> {
        let hash = block.hash();
        if self.blocks.contains_key(&hash) {
            tracing::debug!(block = ?hex::encode(hash), "duplicate block");
            return Ok(SubmitOutcome::Duplicate);
        }

        validate_structure(&block)?;

        let prev = block.header.prev_hash;
        let prev_height = self
            .height
            .get(&prev)
            .copied()
            .ok_or(ChainError::UnknownParent(prev))?;

        let parent = &self.blocks[&prev];
        if block.header.timestamp <= parent.header.timestamp {
            tracing::warn!(
                block = ?hex::encode(hash),
                ts = block.header.timestamp,
                parent_ts = parent.header.timestamp,
                "rejected: timestamp not newer than parent (clock skew or reorg)"
            );
            return Err(ChainError::BadTimestamp(
                block.header.timestamp,
                parent.header.timestamp,
            ));
        }

        // Clock-skew protection: reject blocks stamped unreasonably far in
        // the future. A broken or malicious peer's clock drift must not push
        // our tip forward.
        if let Some(skew) = self.max_future_skew {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            if block.header.timestamp > now.saturating_add(skew) {
                tracing::warn!(
                    block = ?hex::encode(hash),
                    ts = block.header.timestamp,
                    now, skew,
                    "rejected: timestamp too far in the future (clock skew)"
                );
                return Err(ChainError::FutureTimestamp(block.header.timestamp, skew));
            }
        }

        let height = prev_height + 1;
        self.blocks.insert(hash, block);
        self.height.insert(hash, height);

        let old_active_height = self.active_height();
        if height > old_active_height {
            self.active_head = hash;
            tracing::info!(height, block = ?hex::encode(hash), "accepted: new active tip");
            return Ok(SubmitOutcome::Accepted { new_height: height });
        }
        tracing::debug!(height, "accepted: side branch (orphan)");
        Ok(SubmitOutcome::Orphan { height })
    }

    /// Blocks on the active chain from `from_height` (inclusive) to the tip.
    pub fn active_chain(&self, from_height: u64) -> Vec<&Block> {
        let mut out = Vec::new();
        let mut cur = self.active_head;
        while let Some(height) = self.height_of(&cur) {
            if height < from_height {
                break;
            }
            out.push(&self.blocks[&cur]);
            cur = self.blocks[&cur].header.prev_hash;
            if cur == [0u8; 32] {
                break; // reached genesis's parent
            }
        }
        out.reverse();
        out
    }
}

/// Structural validation that doesn't depend on chain state: merkle root
/// commitment and proof-of-work.
pub fn validate_structure(block: &Block) -> Result<(), ChainError> {
    if block.computed_merkle_root() != block.header.merkle_root {
        return Err(ChainError::MerkleMismatch);
    }
    let target = Target::from_compact(block.header.bits).map_err(|_| ChainError::InvalidPow)?;
    if !target.is_met_by(&block.hash()) {
        return Err(ChainError::InvalidPow);
    }
    Ok(())
}

/// A convenient genesis: one coinbase transaction paying an arbitrary
/// script, mined against `bits`.
pub fn make_genesis(coinbase_script: [u8; 20], bits: u32) -> Block {
    let tx = crate::block::Transaction {
        inputs: vec![],
        outputs: vec![crate::block::TxOut {
            value: 50_0000_0000,
            script_pubkey: coinbase_script,
        }],
    };
    let mut header = BlockHeader {
        prev_hash: [0u8; 32],
        merkle_root: crate::merkle::merkle_root(&[tx.txid()]),
        timestamp: 1_234_567_890,
        bits,
        nonce: 0,
    };
    let target = Target::from_compact(bits).expect("genesis bits");
    let (found, _) = crate::pow::mine(&mut header, &target, 10_000_000);
    assert!(found, "could not mine genesis");
    Block {
        header,
        txs: vec![tx],
    }
}
