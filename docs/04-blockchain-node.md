# Phase 3 — Blockchain node / ledger

Implemented in `crates/chain` (the ledger core). The goal is to understand what
makes a ledger a ledger — merkle commitments, proof-of-work, chain validation,
reorgs, and a transaction pool — before bolting on networking and an EVM.

## What's implemented

| Piece | Module | Notes |
|---|---|---|
| Merkle roots + SPV proofs | [`merkle`] | Bitcoin-style `hash256` tree, odd-level duplication, `O(log n)` verification |
| Blocks & transactions | [`block`] | txid = `hash256(canonical bytes)`, header commits to merkle root |
| Proof-of-work | [`pow`] | compact-bits difficulty decode, mining, target checks |
| Chain store | [`chain`] | structural + contextual validation, longest-chain reorg |
| Transaction pool | [`mempool`] | UTXO-set backed, double-spend + coinbase-maturity rules |

[`merkle`]: ../crates/chain/src/merkle.rs
[`block`]: ../crates/chain/src/block.rs
[`pow`]: ../crates/chain/src/pow.rs
[`chain`]: ../crates/chain/src/chain.rs
[`mempool`]: ../crates/chain/src/mempool.rs

## Merkle trees and SPV

Leaves are txids; internal nodes are `hash256(a ‖ b)`. Odd levels duplicate the
last node. A `MerkleProof` records each sibling and side, so a light client
verifies a tx is in a block with ~`log2(n)` hashes:

```rust
use chain::merkle::{MerkleProof, merkle_root};

let txids: Vec<[u8; 32]> = (0..16u8).map(|i| [i; 32]).collect();
let root = merkle_root(&txids);
let proof = MerkleProof::new(&txids, 5).unwrap();
assert!(proof.verify(txids[5], root));
```

Validated against real data: Bitcoin block 100000's merkle root computed from
its four txids, and the genesis block where a single-tx root equals the txid.

## Proof-of-work

Difficulty is packed in 4 bytes (Bitcoin compact bits): `0x1d00ffff` is the
classic difficulty-1 target. A header is valid when its work hash is strictly
below the target.

```rust
use chain::{BlockHeader, compute_target, mine};

let target = compute_target(0x207fffff).unwrap(); // ~2^255, easy
let mut header = BlockHeader { /* ... */ bits: 0x207fffff, nonce: 0 };
let (mined, attempts) = mine(&mut header, &target, 1_000_000);
assert!(mined && target.is_met_by(&header.hash()));
```

## Chain validation and reorgs

`BlockChain` stores every seen block and tracks the longest valid branch.
`submit` validates:

1. **Structure** (state-independent): merkle root matches txs, PoW satisfied.
2. **Context**: parent known, timestamp strictly increasing.

When a longer branch arrives, the active tip switches — that's a reorg. The
side-branch blocks are retained (orphans), exactly like a real node.

```rust
use chain::{BlockChain, make_genesis};

let genesis = make_genesis([0xaa; 20], 0x207fffff);
let mut chain = BlockChain::new(genesis).unwrap();
// chain.submit(block)? -> Accepted | Orphan | Duplicate
```

## Mempool / UTXO set

The pool validates spends against a UTXO set: every input must exist, must not
already be claimed, and `sum(inputs) >= sum(outputs)`. Coinbase outputs are
tracked separately so immature money can be policed. `apply_block` /
`rollback_block` keep the UTXO set consistent through confirmations and reorgs.

## Run the demo

```sh
cargo run -p chain --example demo
```

Mines a 3-block chain, proves a transaction is in a block via SPV, and shows
the mempool rejecting a spend of immature coinbase money.

## Tests

```sh
cargo test -p chain
```

Covers Bitcoin merkle/block vectors, SPV round-trips, compact-bits bounds,
mining, chain validation failures (bad merkle, unknown parent), reorg to the
longest branch, and mempool rules (double spend, insufficient funds, coinbase
maturity, apply/rollback).

## Still open in this phase

- P2P block sync (`libp2p`) so two nodes can reach the same tip over a network.
- EVM execution (`revm`) for Ethereum-compatible chains.
- Difficulty adjustment between blocks.

## Next

[Phase 4 — Trading / analytics app](05-trading.md) builds an application on top
of the plumbing.
