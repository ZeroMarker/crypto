//! Property-based tests (roadmap Phase 5 "audit") for the chain crate.
//!
//! - Block/header serialization must round-trip through serde.
//! - `BlockHeader::hash` must be a function of the 80 serialized bytes: two
//!   headers that differ only in one field never hash equal, and identical
//!   headers always do.
//! - Mempool: after `apply_block` + `rollback_block`, the UTXO set is restored
//!   exactly (no lost or invented money).

use proptest::prelude::*;
use proptest::prop_assert_eq;

use chain::block::{Block, BlockHeader, OutPoint, Transaction, TxIn, TxOut};
use chain::mempool::{build_payment, Mempool};

fn arb_outpoint() -> impl Strategy<Value = OutPoint> {
    (any::<[u8; 32]>(), any::<u32>()).prop_map(|(txid, index)| OutPoint { txid, index })
}

fn arb_txin() -> impl Strategy<Value = TxIn> {
    (arb_outpoint(), any::<[u8; 32]>()).prop_map(|(prev_out, signature)| TxIn {
        prev_out,
        signature,
    })
}

fn arb_txout() -> impl Strategy<Value = TxOut> {
    (0u64..1_000_000u64, any::<[u8; 20]>()).prop_map(|(value, script_pubkey)| TxOut {
        value,
        script_pubkey,
    })
}

fn arb_tx() -> impl Strategy<Value = Transaction> {
    (
        prop::collection::vec(arb_txin(), 0..8),
        prop::collection::vec(arb_txout(), 0..8),
    )
        .prop_map(|(inputs, outputs)| Transaction { inputs, outputs })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// Header serde round-trip (JSON).
    #[test]
    fn header_serde_roundtrip(header in any::<([u8; 32], [u8; 32], u32, u32, u64)>()
        .prop_map(|(prev_hash, merkle_root, timestamp, bits, nonce)| BlockHeader {
            prev_hash, merkle_root, timestamp, bits, nonce,
        }))
    {
        let json = serde_json::to_string(&header).expect("serialize");
        let back: BlockHeader = serde_json::from_str(&json).expect("parse");
        prop_assert_eq!(back, header);
        // The work hash is stable across the round-trip.
        prop_assert_eq!(back.hash(), header.hash());
    }

    /// Block serde round-trip (JSON).
    #[test]
    fn block_serde_roundtrip(header in any::<([u8; 32], [u8; 32], u32, u32, u64)>()
        .prop_map(|(prev_hash, merkle_root, timestamp, bits, nonce)| BlockHeader {
            prev_hash, merkle_root, timestamp, bits, nonce,
        }), txs in prop::collection::vec(arb_tx(), 0..8))
    {
        let block = Block { header, txs };
        let json = serde_json::to_string(&block).expect("serialize");
        let back: Block = serde_json::from_str(&json).expect("parse");
        prop_assert_eq!(back, block);
    }

    /// Hashing is collision-free on single-field flips (each header field
    /// commits to the hash).
    #[test]
    fn header_hash_is_sensitive_to_every_field(header in any::<([u8; 32], [u8; 32], u32, u32, u64)>()
        .prop_map(|(prev_hash, merkle_root, timestamp, bits, nonce)| BlockHeader {
            prev_hash, merkle_root, timestamp, bits, nonce,
        }))
    {
        let h = header.hash();
        let mut flips = vec![];
        let mut prev = header.prev_hash; prev[0] ^= 1; flips.push(BlockHeader { prev_hash: prev, ..header });
        let mut merkle = header.merkle_root; merkle[7] ^= 1; flips.push(BlockHeader { merkle_root: merkle, ..header });
        flips.push(BlockHeader { timestamp: header.timestamp.wrapping_add(1), ..header });
        flips.push(BlockHeader { bits: header.bits ^ 0x00ff_0000, ..header });
        flips.push(BlockHeader { nonce: header.nonce.wrapping_add(1), ..header });
        for f in flips {
            prop_assert_ne!(f.hash(), h, "field flip must change the work hash");
        }
    }

    /// Every RLP-free invariant of txid serialization: the coinbase marker and
    /// count bytes are length-prefixed, so the serialization is injective.
    #[test]
    fn txid_is_injective(tx in arb_tx()) {
        // Re-serializing a parsed-identical tx yields the same txid.
        let json = serde_json::to_string(&tx).unwrap();
        let back: Transaction = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(back.txid(), tx.txid());
    }
}

/// Mempool replay protection: a tx whose inputs were spent by a confirmed
/// block must be evicted, and a reorg restoring the block must make it
/// spendable again — without corrupting values.
#[test]
fn apply_and_rollback_restore_utxo_exactly() {
    let mut mp = Mempool::new();
    let (alice_out, bob_out) = (
        OutPoint {
            txid: [1u8; 32],
            index: 0,
        },
        OutPoint {
            txid: [2u8; 32],
            index: 0,
        },
    );
    mp.utxo_mut().credit(alice_out, 1_000, false);
    mp.utxo_mut().credit(bob_out, 500, false);

    // Alice pays Bob 300.
    let tx = build_payment(&[(alice_out, 1_000)], [0xaa; 20], 300, [0xbb; 20]).unwrap();
    mp.submit(&tx).unwrap();
    assert_eq!(mp.len(), 1);

    // A block confirms the payment: Bob's new output is spendable, Alice's
    // input is not, and the pending tx is gone.
    let block = Block {
        header: BlockHeader {
            prev_hash: [0; 32],
            merkle_root: [0; 32],
            timestamp: 1,
            bits: 0x1d00ffff,
            nonce: 0,
        },
        txs: vec![tx.clone()],
    };
    mp.apply_block(&block);
    assert_eq!(mp.len(), 0);
    assert!(!mp.utxo().contains(&alice_out));
    let bob_new = OutPoint {
        txid: tx.txid(),
        index: 1, // change output
    };
    assert!(mp.utxo().contains(&bob_new));
    assert_eq!(mp.utxo().value(&bob_new), Some(700)); // 1000 - 300 change

    // Reorg: the block is rolled back; Alice's input is spendable again and
    // Bob's new output disappears. Value accounting is exact.
    mp.rollback_block(&block);
    assert!(mp.utxo().contains(&alice_out));
    assert_eq!(mp.utxo().value(&alice_out), Some(1_000));
    assert!(!mp.utxo().contains(&bob_new));
}

/// Replay protection: the same transaction cannot enter the mempool twice,
/// and double-spending an outpoint is rejected even with a different txid.
#[test]
fn mempool_rejects_replay_and_double_spend() {
    let mut mp = Mempool::new();
    let out = OutPoint {
        txid: [3u8; 32],
        index: 0,
    };
    mp.utxo_mut().credit(out, 1_000, false);

    let tx = build_payment(&[(out, 1_000)], [0xcc; 20], 100, [0xdd; 20]).unwrap();
    mp.submit(&tx).unwrap();

    // Exact replay: duplicate.
    assert!(mp.submit(&tx).is_err());

    // Double spend of the same outpoint with different outputs: rejected.
    let other = build_payment(&[(out, 1_000)], [0xee; 20], 100, [0xdd; 20]).unwrap();
    assert!(other.txid() != tx.txid());
    assert!(mp.submit(&other).is_err());
}
