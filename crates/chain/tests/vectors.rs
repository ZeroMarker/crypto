//! Integration tests against real Bitcoin data and self-consistent chain
//! scenarios.

use chain::block::{Block, BlockHeader, OutPoint, Transaction, TxIn, TxOut};
use chain::mempool::{build_payment, Mempool};
use chain::merkle::{merkle_root, MerkleProof};
use chain::pow::Target;
use chain::{compute_target, make_genesis, mine, BlockChain};

fn txids_from_hex_displays(hexes: &[&str]) -> Vec<[u8; 32]> {
    // Bitcoin displays hashes in little-endian ("reverse byte") order; our
    // chain stores raw big-endian bytes. Reverse before use.
    hexes
        .iter()
        .map(|h| {
            let mut b = hex::decode(h).unwrap();
            b.reverse();
            b.try_into().unwrap()
        })
        .collect()
}

#[test]
fn merkle_single_tx_matches_genesis() {
    // Bitcoin genesis: one coinbase tx, merkle root == txid.
    let txid: [u8; 32] =
        hex::decode("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
            .unwrap()
            .try_into()
            .unwrap();
    let root = merkle_root(&[txid]);
    assert_eq!(root, txid);
}

#[test]
fn merkle_bitcoin_block_100000_vector() {
    // Block 100000 has 4 txs. The merkle root of their txids (raw byte order)
    // must equal the block's merkle root.
    let txids = txids_from_hex_displays(&[
        "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
        "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
        "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
        "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d",
    ]);
    let root = merkle_root(&txids);

    let mut expected: [u8; 32] =
        hex::decode("f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766")
            .unwrap()
            .try_into()
            .unwrap();
    expected.reverse();
    assert_eq!(root, expected);
}

#[test]
fn merkle_odd_count_duplicates_last() {
    // 3 txs: root = hash256(hash256(a||b) || hash256(c||c)).
    let a = [1u8; 32];
    let b = [2u8; 32];
    let c = [3u8; 32];
    let root = merkle_root(&[a, b, c]);

    let ab = chain::hash256(&[a, b].concat());
    let cc = chain::hash256(&[c, c].concat());
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&ab);
    buf[32..].copy_from_slice(&cc);
    assert_eq!(root, chain::hash256(&buf));
}

#[test]
fn spv_proof_roundtrip() {
    let txids: Vec<[u8; 32]> = (0..16u8).map(|i| [i; 32]).collect();
    let root = merkle_root(&txids);
    for index in 0..txids.len() {
        let proof = MerkleProof::new(&txids, index).unwrap();
        assert!(proof.verify(txids[index], root), "index {index} failed");
        assert!(!proof.verify([0xff; 32], root));
    }
}

#[test]
fn spv_proof_index_out_of_range() {
    let txids: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
    assert!(MerkleProof::new(&txids, 4).is_none());
}

#[test]
fn compact_bits_difficulty_one() {
    // 0x1d00ffff is the classic difficulty-1 target.
    let t = Target::from_compact(0x1d00ffff).unwrap();
    assert_eq!(
        t.to_hex(),
        "00000000ffff0000000000000000000000000000000000000000000000000000"
    );
    assert!(t.is_met_by(&[0u8; 32]));
}

#[test]
fn compact_bits_bounds() {
    // exponent = 32, mantissa = 0 -> zero target.
    assert_eq!(
        Target::from_compact(0x20000000),
        Err(chain::pow::DifficultyError::ZeroTarget)
    );
    // exponent 33 > 32 -> too large.
    assert_eq!(
        Target::from_compact(0x21000001),
        Err(chain::pow::DifficultyError::ExponentTooLarge(33))
    );
    // exponent < 3 with mantissa that shrinks to zero.
    assert!(Target::from_compact(0x01000001).is_err());
}

#[test]
fn mining_finds_nonce() {
    let bits = 0x207fffff; // ~2^255 target, ~50% success per attempt
    let target = compute_target(bits).unwrap();
    let mut header = BlockHeader {
        prev_hash: [0u8; 32],
        merkle_root: [9u8; 32],
        timestamp: 0,
        bits,
        nonce: 0,
    };
    let (found, attempts) = mine(&mut header, &target, 1_000_000);
    assert!(found);
    assert!(target.is_met_by(&header.hash()));
    assert!(attempts >= 1);
}

#[test]
fn chain_builds_and_validates() {
    let bits = 0x207fffff;
    let genesis = make_genesis([0xab; 20], bits);
    let mut chain = BlockChain::new(genesis.clone()).unwrap();
    assert_eq!(chain.active_height(), 0);

    // Build a valid next block: pay someone from the genesis coinbase.
    let genesis_out = OutPoint {
        txid: genesis.txs[0].txid(),
        index: 0,
    };
    let tx = Transaction {
        inputs: vec![TxIn {
            prev_out: genesis_out,
            signature: [1u8; 32],
        }],
        outputs: vec![TxOut {
            value: 25_0000_0000,
            script_pubkey: [0xcd; 20],
        }],
    };
    let target = compute_target(bits).unwrap();
    let mut header = BlockHeader {
        prev_hash: genesis.hash(),
        merkle_root: chain::merkle::merkle_root(&[tx.txid()]),
        timestamp: genesis.header.timestamp + 1,
        bits,
        nonce: 0,
    };
    let (mined, _) = mine(&mut header, &target, 1_000_000);
    assert!(mined);
    let block = Block {
        header,
        txs: vec![tx],
    };
    assert_eq!(
        chain.submit(block.clone()).unwrap(),
        chain::SubmitOutcome::Accepted { new_height: 1 }
    );
    assert_eq!(chain.active_height(), 1);
    assert_eq!(chain.active_chain(0).len(), 2);
}

#[test]
fn chain_rejects_bad_merkle() {
    let bits = 0x207fffff;
    let genesis = make_genesis([0xab; 20], bits);
    let mut chain = BlockChain::new(genesis.clone()).unwrap();

    let tx = Transaction {
        inputs: vec![],
        outputs: vec![TxOut {
            value: 5,
            script_pubkey: [1; 20],
        }],
    };
    let target = compute_target(bits).unwrap();
    let mut header = BlockHeader {
        prev_hash: genesis.hash(),
        merkle_root: [0xee; 32], // wrong on purpose
        timestamp: genesis.header.timestamp + 1,
        bits,
        nonce: 0,
    };
    let (mined, _) = mine(&mut header, &target, 1_000_000);
    assert!(mined);
    let bad = Block {
        header,
        txs: vec![tx],
    };
    assert_eq!(chain.submit(bad), Err(chain::ChainError::MerkleMismatch));
    assert_eq!(chain.active_height(), 0);
}

#[test]
fn chain_rejects_unknown_parent() {
    let bits = 0x207fffff;
    let genesis = make_genesis([0xab; 20], bits);
    let mut chain = BlockChain::new(genesis).unwrap();

    let tx = Transaction {
        inputs: vec![],
        outputs: vec![TxOut {
            value: 5,
            script_pubkey: [1; 20],
        }],
    };
    let target = compute_target(bits).unwrap();
    let mut header = BlockHeader {
        prev_hash: [0x42; 32], // nobody knows this block
        merkle_root: chain::merkle::merkle_root(&[tx.txid()]),
        timestamp: 1,
        bits,
        nonce: 0,
    };
    let (mined, _) = mine(&mut header, &target, 1_000_000);
    assert!(mined);
    let block = Block {
        header,
        txs: vec![tx],
    };
    assert!(matches!(
        chain.submit(block),
        Err(chain::ChainError::UnknownParent(_))
    ));
}

#[test]
fn chain_reorgs_to_longest_branch() {
    let bits = 0x207fffff;
    let genesis = make_genesis([0xab; 20], bits);
    let mut chain = BlockChain::new(genesis.clone()).unwrap();

    let target = compute_target(bits).unwrap();

    // Helper to make a child block of `parent` with a fresh coinbase.
    let make_child = |parent: &Block, ts: u32| -> Block {
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![TxOut {
                value: 50_0000_0000,
                script_pubkey: [ts as u8; 20],
            }],
        };
        let mut header = BlockHeader {
            prev_hash: parent.hash(),
            merkle_root: chain::merkle::merkle_root(&[tx.txid()]),
            timestamp: ts,
            bits,
            nonce: 0,
        };
        let (mined, _) = mine(&mut header, &target, 1_000_000);
        assert!(mined);
        Block {
            header,
            txs: vec![tx],
        }
    };

    // Main branch: genesis -> A -> B (height 2).
    let a = make_child(&genesis, 1_234_567_891);
    chain.submit(a.clone()).unwrap();
    let b = make_child(&a, 1_234_567_892);
    chain.submit(b.clone()).unwrap();
    assert_eq!(chain.active_height(), 2);

    // Side branch genesis -> C (height 1): shorter, stays orphan.
    let c = make_child(&genesis, 1_234_567_895);
    assert_eq!(
        chain.submit(c.clone()).unwrap(),
        chain::SubmitOutcome::Orphan { height: 1 }
    );
    assert_eq!(chain.active_tip(), b.hash());

    // Side branch genesis -> C -> D (height 2): ties, kept as-is (no reorg).
    let d = make_child(&c, 1_234_567_896);
    assert_eq!(
        chain.submit(d.clone()).unwrap(),
        chain::SubmitOutcome::Orphan { height: 2 }
    );

    // Side branch genesis -> C -> D -> E (height 3): longer, reorgs.
    let e = make_child(&d, 1_234_567_897);
    assert_eq!(
        chain.submit(e.clone()).unwrap(),
        chain::SubmitOutcome::Accepted { new_height: 3 }
    );
    assert_eq!(chain.active_height(), 3);
    assert_eq!(chain.active_tip(), e.hash());

    // The active chain now runs genesis -> C -> D -> E.
    let hashes: Vec<[u8; 32]> = chain.active_chain(0).iter().map(|b| b.hash()).collect();
    assert_eq!(hashes, vec![genesis.hash(), c.hash(), d.hash(), e.hash()]);
}

#[test]
fn mempool_double_spend_rejected() {
    let mut pool = Mempool::new();
    let op = OutPoint {
        txid: [1u8; 32],
        index: 0,
    };
    {
        let utxo = pool.utxo_mut();
        utxo.credit(op, 100, false);
    }

    let alice = [0xaa; 20];
    let t1 = build_payment(&[(op, 100)], alice, 40, alice).unwrap();
    pool.submit(&t1).unwrap();
    assert_eq!(pool.len(), 1);

    // A second transaction spending the same outpoint must be rejected.
    let t2 = build_payment(&[(op, 100)], alice, 30, alice).unwrap();
    assert_eq!(
        pool.submit(&t2),
        Err(chain::mempool::MempoolError::DoubleSpend {
            txid: op.txid,
            index: op.index
        })
    );
}

#[test]
fn mempool_insufficient_funds_rejected() {
    let mut pool = Mempool::new();
    let op = OutPoint {
        txid: [2u8; 32],
        index: 0,
    };
    {
        let utxo = pool.utxo_mut();
        utxo.credit(op, 100, false);
    }

    let tx = build_payment(&[(op, 100)], [0xaa; 20], 150, [0xaa; 20]);
    assert!(matches!(
        tx,
        Err(chain::mempool::MempoolError::InsufficientFunds { .. })
    ));
}

#[test]
fn mempool_coinbase_not_spendable_in_mempool() {
    let mut pool = Mempool::new();
    let op = OutPoint {
        txid: [3u8; 32],
        index: 0,
    };
    {
        let utxo = pool.utxo_mut();
        utxo.credit(op, 50_0000_0000, true); // immature coinbase money
    }

    let tx = build_payment(&[(op, 50_0000_0000)], [0xaa; 20], 100, [0xaa; 20]).unwrap();
    assert_eq!(
        pool.submit(&tx),
        Err(chain::mempool::MempoolError::CoinbaseSpend)
    );
}

#[test]
fn mempool_apply_and_rollback_block() {
    let mut pool = Mempool::new();
    let op = OutPoint {
        txid: [4u8; 32],
        index: 0,
    };
    {
        let utxo = pool.utxo_mut();
        utxo.credit(op, 100, false);
    }

    let bob = [0xbb; 20];
    let tx = build_payment(&[(op, 100)], bob, 60, bob).unwrap();
    let txid = tx.txid();
    pool.submit(&tx).unwrap();

    // A block containing `tx`.
    let block = Block {
        header: BlockHeader {
            prev_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1,
            bits: 0,
            nonce: 0,
        },
        txs: vec![tx],
    };
    pool.apply_block(&block);

    // tx left the pool; its output is now unspent; the input is spent.
    assert!(!pool.contains(&txid));
    assert!(!pool.utxo().contains(&op));
    let new_op = OutPoint { txid, index: 0 };
    assert_eq!(pool.utxo().value(&new_op), Some(60));

    // Roll the block back: original input is spendable again.
    pool.rollback_block(&block);
    assert!(pool.utxo().contains(&op));
    assert!(!pool.utxo().contains(&new_op));
}
