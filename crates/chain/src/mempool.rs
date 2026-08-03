//! A transaction pool backed by a UTXO set.
//!
//! The mempool accepts transactions that spend currently-unspent outputs,
//! rejects double spends, and keeps the UTXO set in sync as blocks confirm
//! (and reorgs un-confirm) transactions.

use std::collections::{HashMap, HashSet};

use crate::block::{Block, OutPoint, Transaction, TxOut};

/// Errors from validating a transaction against the UTXO set.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MempoolError {
    #[error("input {txid:?}:{index} does not exist in the UTXO set")]
    UnknownOutpoint { txid: [u8; 32], index: u32 },
    #[error("double spend: outpoint {txid:?}:{index} already spent")]
    DoubleSpend { txid: [u8; 32], index: u32 },
    #[error("spends more than it creates: {spent} > {created}")]
    InsufficientFunds { spent: u64, created: u64 },
    #[error("coinbase outputs are not spendable")]
    CoinbaseSpend,
    #[error("transaction already in the mempool")]
    Duplicate,
    #[error("coinbase transaction cannot be in the mempool")]
    CoinbaseNotInMempool,
}

/// The set of unspent transaction outputs a node knows about.
///
/// `values` remembers the amount of every outpoint ever seen so that a reorg
/// can restore spent outputs without losing their value.
#[derive(Debug, Clone, Default)]
pub struct UtxoSet {
    /// Outpoints that are currently spendable.
    unspent: HashSet<OutPoint>,
    /// Value of every outpoint the node has ever seen.
    values: HashMap<OutPoint, u64>,
    /// Outpoints created by coinbase transactions (immature money).
    coinbase: HashSet<OutPoint>,
    /// Outpoints already claimed by a mempool transaction (pending spends).
    spent: HashSet<OutPoint>,
}

impl UtxoSet {
    pub fn contains(&self, outpoint: &OutPoint) -> bool {
        self.unspent.contains(outpoint)
    }

    pub fn value(&self, outpoint: &OutPoint) -> Option<u64> {
        self.values.get(outpoint).copied()
    }

    /// Directly credit an output (used to seed balances in tests).
    pub fn credit(&mut self, outpoint: OutPoint, value: u64, is_coinbase: bool) {
        self.values.insert(outpoint, value);
        self.unspent.insert(outpoint);
        if is_coinbase {
            self.coinbase.insert(outpoint);
        }
    }
}

/// A pending-transaction pool over a [`UtxoSet`].
#[derive(Debug, Clone, Default)]
pub struct Mempool {
    utxo: UtxoSet,
    txs: HashMap<[u8; 32], Transaction>,
}

impl Mempool {
    pub fn new() -> Mempool {
        Mempool::default()
    }

    /// The UTXO set the pool reasons about (seed it with the coinbase outputs
    /// of confirmed blocks before use).
    pub fn utxo_mut(&mut self) -> &mut UtxoSet {
        &mut self.utxo
    }

    pub fn utxo(&self) -> &UtxoSet {
        &self.utxo
    }

    pub fn contains(&self, txid: &[u8; 32]) -> bool {
        self.txs.contains_key(txid)
    }

    pub fn get(&self, txid: &[u8; 32]) -> Option<&Transaction> {
        self.txs.get(txid)
    }

    /// Try to add `tx` to the pool. Validates every input against the UTXO
    /// set and the value sum. On success the inputs are marked spent.
    pub fn submit(&mut self, tx: &Transaction) -> Result<(), MempoolError> {
        if tx.is_coinbase() {
            return Err(MempoolError::CoinbaseNotInMempool);
        }
        let txid = tx.txid();
        if self.txs.contains_key(&txid) {
            return Err(MempoolError::Duplicate);
        }

        let mut spent_total = 0u64;
        for txin in &tx.inputs {
            let op = txin.prev_out;
            if !self.utxo.unspent.contains(&op) {
                return Err(MempoolError::UnknownOutpoint {
                    txid: op.txid,
                    index: op.index,
                });
            }
            if self.utxo.coinbase.contains(&op) {
                return Err(MempoolError::CoinbaseSpend);
            }
            if self.utxo.spent.contains(&op) {
                return Err(MempoolError::DoubleSpend {
                    txid: op.txid,
                    index: op.index,
                });
            }
            spent_total += self.utxo.values[&op];
        }

        let created_total: u64 = tx.outputs.iter().map(|o| o.value).sum();
        if spent_total < created_total {
            return Err(MempoolError::InsufficientFunds {
                spent: spent_total,
                created: created_total,
            });
        }

        for txin in &tx.inputs {
            self.utxo.spent.insert(txin.prev_out);
        }
        self.txs.insert(txid, tx.clone());
        Ok(())
    }

    /// Apply a mined block: remove spent outpoints, add created ones, and drop
    /// the block's transactions from the pool.
    pub fn apply_block(&mut self, block: &Block) {
        for tx in &block.txs {
            if !tx.is_coinbase() {
                for txin in &tx.inputs {
                    self.utxo.unspent.remove(&txin.prev_out);
                    self.utxo.spent.insert(txin.prev_out);
                }
            }
            let txid = tx.txid();
            self.txs.remove(&txid);
            for (i, out) in tx.outputs.iter().enumerate() {
                let op = OutPoint {
                    txid,
                    index: i as u32,
                };
                self.utxo.values.insert(op, out.value);
                self.utxo.unspent.insert(op);
                if tx.is_coinbase() {
                    self.utxo.coinbase.insert(op);
                }
            }
        }
    }

    /// Roll back a reorged-out block: restore its spent inputs and remove the
    /// outputs it created. The reverse of [`apply_block`].
    pub fn rollback_block(&mut self, block: &Block) {
        for tx in &block.txs {
            let txid = tx.txid();
            for i in 0..tx.outputs.len() {
                let op = OutPoint {
                    txid,
                    index: i as u32,
                };
                self.utxo.unspent.remove(&op);
                self.utxo.values.remove(&op);
                self.utxo.coinbase.remove(&op);
            }
        }
        for tx in &block.txs {
            if !tx.is_coinbase() {
                for txin in &tx.inputs {
                    self.utxo.spent.remove(&txin.prev_out);
                    // The value is still known from when it was created.
                    self.utxo.unspent.insert(txin.prev_out);
                }
            }
        }
    }

    /// Number of pending transactions.
    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }
}

impl UtxoSet {
    /// Outpoints currently unspent (used by tests).
    pub fn unspent_count(&self) -> usize {
        self.unspent.len()
    }
}

/// A transaction that pays `to` from a set of outpoints, returning any excess
/// to `change`. Used by tests to build realistic transactions.
pub fn build_payment(
    inputs: &[(OutPoint, u64)],
    to: [u8; 20],
    amount: u64,
    change: [u8; 20],
) -> Result<Transaction, MempoolError> {
    let total: u64 = inputs.iter().map(|(_, v)| *v).sum();
    if total < amount {
        return Err(MempoolError::InsufficientFunds {
            spent: total,
            created: amount,
        });
    }
    let mut tx = Transaction {
        inputs: inputs
            .iter()
            .map(|(op, _)| crate::block::TxIn {
                prev_out: *op,
                signature: [1u8; 32],
            })
            .collect(),
        outputs: vec![TxOut {
            value: amount,
            script_pubkey: to,
        }],
    };
    if total > amount {
        tx.outputs.push(TxOut {
            value: total - amount,
            script_pubkey: change,
        });
    }
    Ok(tx)
}
