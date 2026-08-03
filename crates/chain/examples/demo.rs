//! Example: mine a small chain, prove a tx with SPV, and use a mempool.
//!
//! Run with:
//! ```sh
//! cargo run -p chain --example demo
//! ```

use chain::block::{Block, BlockHeader, OutPoint, Transaction, TxIn, TxOut};
use chain::merkle::MerkleProof;
use chain::{compute_target, make_genesis, mine, BlockChain, Mempool};

const BITS: u32 = 0x207fffff; // ~2^255 target — trivial for a demo

fn main() {
    // 1. Genesis + two mined blocks.
    let genesis = make_genesis([0xaa; 20], BITS);
    let mut chain = BlockChain::new(genesis.clone()).unwrap();
    println!("genesis      {}", hex::encode(genesis.hash()));

    let target = compute_target(BITS).unwrap();

    let block1 = mine_block(&genesis, 1_234_567_891, &[make_coinbase(1)], &target);
    chain.submit(block1.clone()).unwrap();
    println!("block 1      {}", hex::encode(block1.hash()));

    let block2 = mine_block(&block1, 1_234_567_892, &[make_coinbase(2)], &target);
    chain.submit(block2.clone()).unwrap();
    println!("block 2      {}", hex::encode(block2.hash()));

    // 2. Block 3 has three transactions; prove one of them with SPV.
    let txs = vec![
        make_coinbase(3),
        make_tx([0x11; 20], 100),
        make_tx([0x22; 20], 200),
    ];
    let txids: Vec<[u8; 32]> = txs.iter().map(Transaction::txid).collect();
    let root = chain::merkle::merkle_root(&txids);
    let block3 = mine_block(&block2, 1_234_567_893, &txs, &target);
    chain.submit(block3.clone()).unwrap();
    println!(
        "block 3      {} ({tx} txs)",
        hex::encode(block3.hash()),
        tx = txids.len()
    );
    println!("active height: {}", chain.active_height());

    let proof = MerkleProof::new(&txids, 1).unwrap();
    let verified = proof.verify(txids[1], root);
    let tampered = proof.verify([0xde; 32], root);
    println!("spv: tx#1 in block 3 verifies: {verified} | tampered tx verifies: {tampered}");

    // 3. Mempool: spend the genesis coinbase, confirm it, then roll it back.
    let mut pool = Mempool::new();
    let genesis_out = OutPoint {
        txid: genesis.txs[0].txid(),
        index: 0,
    };
    pool.utxo_mut().credit(genesis_out, 50_0000_0000, true);

    let spend = Transaction {
        inputs: vec![TxIn {
            prev_out: genesis_out,
            signature: [9u8; 32],
        }],
        outputs: vec![TxOut {
            value: 10_0000_0000,
            script_pubkey: [0xbb; 20],
        }],
    };
    match pool.submit(&spend) {
        Ok(()) => println!("mempool: accepted spend tx"),
        Err(e) => println!("mempool: rejected: {e}"), // coinbase money — expected here
    }
}

fn make_coinbase(seed: u8) -> Transaction {
    Transaction {
        inputs: vec![],
        outputs: vec![TxOut {
            value: 50_0000_0000,
            script_pubkey: [seed; 20],
        }],
    }
}

fn make_tx(to: [u8; 20], value: u64) -> Transaction {
    Transaction {
        inputs: vec![],
        outputs: vec![TxOut {
            value,
            script_pubkey: to,
        }],
    }
}

fn mine_block(
    parent: &Block,
    timestamp: u32,
    txs: &[Transaction],
    target: &chain::Target,
) -> Block {
    let txids: Vec<[u8; 32]> = txs.iter().map(Transaction::txid).collect();
    let mut header = BlockHeader {
        prev_hash: parent.hash(),
        merkle_root: chain::merkle::merkle_root(&txids),
        timestamp,
        bits: BITS,
        nonce: 0,
    };
    let (mined, attempts) = mine(&mut header, target, 1_000_000);
    assert!(mined, "could not mine block");
    println!("  mined in {attempts} attempts");
    Block {
        header,
        txs: txs.to_vec(),
    }
}
