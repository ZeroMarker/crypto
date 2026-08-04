//! Transactions, headers, and blocks.
//!
//! Wire formats are deliberately minimal for a teaching chain, but the
//! structure mirrors Bitcoin: a transaction spends previous [`OutPoint`]s and
//! creates new outputs; a block packages transactions under a header whose
//! merkle root commits to them.

use crate::merkle::merkle_root;
use crypto_core::hash::hash256;

/// A reference to a previously-created output: `(txid, output_index)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub index: u32,
}

/// One unspent output created by a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: [u8; 20],
}

/// A transaction input: an outpoint plus a signature placeholder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxIn {
    pub prev_out: OutPoint,
    /// 32 bytes of "signature" (kept opaque here; real systems use ECDSA).
    pub signature: [u8; 32],
}

/// A coinbase transaction creates new money; `is_coinbase` is derived from
/// having no inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
}

impl Transaction {
    /// Canonical txid = `hash256(serialization)`.
    ///
    /// The serialization is defined by this crate: one byte `0x00` for
    /// coinbase or `0x01` for normal, then inputs, then outputs.
    pub fn txid(&self) -> [u8; 32] {
        hash256(&self.serialize())
    }

    /// The byte serialization that defines the txid.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 8 * (self.inputs.len() + self.outputs.len()));
        out.push(if self.is_coinbase() { 0x00 } else { 0x01 });
        out.push(self.inputs.len() as u8);
        for txin in &self.inputs {
            out.extend_from_slice(&txin.prev_out.txid);
            out.extend_from_slice(&txin.prev_out.index.to_le_bytes());
            out.extend_from_slice(&txin.signature);
        }
        out.push(self.outputs.len() as u8);
        for txout in &self.outputs {
            out.extend_from_slice(&txout.value.to_le_bytes());
            out.extend_from_slice(&txout.script_pubkey);
        }
        out
    }

    pub fn is_coinbase(&self) -> bool {
        self.inputs.is_empty()
    }
}

/// A 80-byte header: previous hash, merkle root, time, compact bits
/// (difficulty), and nonce. The work hash commits to all of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    pub prev_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u32,
    /// Compact difficulty bits (see [`crate::pow`]).
    pub bits: u32,
    pub nonce: u64,
}

impl BlockHeader {
    /// `hash256` over the header fields (prev ‖ merkle ‖ time ‖ bits ‖ nonce).
    ///
    /// All 8 bytes of `nonce` are serialized, so a header is uniquely
    /// identified by its hash even for nonces beyond `u32::MAX`.
    pub fn hash(&self) -> [u8; 32] {
        let mut buf = [0u8; 80];
        buf[..32].copy_from_slice(&self.prev_hash);
        buf[32..64].copy_from_slice(&self.merkle_root);
        buf[64..68].copy_from_slice(&self.timestamp.to_le_bytes());
        buf[68..72].copy_from_slice(&self.bits.to_le_bytes());
        buf[72..80].copy_from_slice(&self.nonce.to_le_bytes());
        hash256(&buf)
    }
}

/// A block: header plus its transactions. The header's merkle root must
/// commit to `txs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Transaction>,
}

impl Block {
    pub fn hash(&self) -> [u8; 32] {
        self.header.hash()
    }

    /// The merkle root committed to by this block's header.
    pub fn computed_merkle_root(&self) -> [u8; 32] {
        let txids: Vec<[u8; 32]> = self.txs.iter().map(Transaction::txid).collect();
        merkle_root(&txids)
    }
}
