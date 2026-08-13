//! Deterministic mutational fuzzing for the chain crate (stable toolchain,
//! no libFuzzer needed). See `crates/wallet/tests/fuzz.rs` for the rationale.

use chain::block::{Block, BlockHeader, Transaction, TxIn, TxOut};
use chain::chain::validate_structure;
use chain::mempool::{build_payment, Mempool};

/// xorshift64* PRNG (same as wallet fuzz tests).
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed.max(1))
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn pick(&mut self, len: usize) -> usize {
        (self.next() % len as u64) as usize
    }
    fn mutate(&mut self, buf: &mut [u8]) {
        if buf.is_empty() {
            return;
        }
        let i = self.pick(buf.len());
        buf[i] ^= 1 << (self.next() % 8);
    }
}

const ITERS: usize = 4_000;

fn make_genesis_like() -> Block {
    // A valid structure (merkle root matches, PoW satisfied) so that
    // validation has real work to do before rejecting mutations. Uses the
    // same easy target (`0x207fffff`, ~50% success per attempt) as the
    // crate's own tests — Bitcoin-difficulty genesis mining would take
    // billions of attempts.
    chain::chain::make_genesis([0xab; 20], 0x207fffff)
}

/// `validate_structure` must never panic on mutated blocks.
#[test]
fn fuzz_validate_structure_never_panics() {
    let seed = make_genesis_like();
    let mut rng = Rng::new(0xB10C_5EED);
    for _ in 0..ITERS {
        let mut block = seed.clone();
        // Mutate header fields.
        match rng.pick(4) {
            0 => block.header.prev_hash[rng.pick(32)] ^= 0xff,
            1 => block.header.timestamp = block.header.timestamp.wrapping_add(rng.next() as u32),
            2 => block.header.bits ^= 1 << rng.pick(32),
            _ => block.header.nonce = block.header.nonce.wrapping_add(rng.next()),
        }
        // Sometimes mutate a transaction's bytes.
        if rng.next().is_multiple_of(3) {
            let mut tx_bytes = block.txs[0].serialize();
            rng.mutate(&mut tx_bytes);
            if let Some(t) = deserialize_tx(&tx_bytes) {
                block.txs[0] = t;
            }
        }
        let _ = validate_structure(&block); // must not panic
    }
}

/// `BlockHeader::hash` must never panic on arbitrary 80-byte buffers and is
/// deterministic.
#[test]
fn fuzz_header_hash_never_panics() {
    let mut rng = Rng::new(0x1EAD_5EED);
    for _ in 0..ITERS {
        let mut buf = [0u8; 80];
        for b in buf.iter_mut() {
            *b = rng.next() as u8;
        }
        let header = header_from_80(&buf);
        let h1 = header.hash();
        let h2 = header.hash();
        assert_eq!(h1, h2, "hash must be deterministic");
    }
}

/// Mempool must never panic on adversarial payment constructions (huge
/// amounts, many inputs, empty outputs).
#[test]
fn fuzz_mempool_submit_never_panics() {
    let mut rng = Rng::new(0xDEAD_1EAD);
    for _ in 0..ITERS {
        let mut mp = Mempool::new();
        let n_inputs = 1 + rng.pick(8);
        let mut inputs = Vec::new();
        for i in 0..n_inputs {
            let mut txid = [0u8; 32];
            txid[0] = i as u8;
            let op = chain::block::OutPoint {
                txid,
                index: rng.next() as u32,
            };
            let value = rng.next() % 1_000_000;
            mp.utxo_mut().credit(op, value, false);
            inputs.push((op, value));
        }
        let amount = rng.next() % 2_000_000;
        let tx = build_payment(&inputs, [0xcc; 20], amount, [0xdd; 20]);
        if let Ok(tx) = tx {
            let _ = mp.submit(&tx); // must not panic
        }
    }
}

fn header_from_80(buf: &[u8; 80]) -> BlockHeader {
    let mut prev_hash = [0u8; 32];
    let mut merkle_root = [0u8; 32];
    prev_hash.copy_from_slice(&buf[..32]);
    merkle_root.copy_from_slice(&buf[32..64]);
    let timestamp = u32::from_le_bytes(buf[64..68].try_into().unwrap());
    let bits = u32::from_le_bytes(buf[68..72].try_into().unwrap());
    let nonce = u64::from_le_bytes(buf[72..80].try_into().unwrap());
    BlockHeader {
        prev_hash,
        merkle_root,
        timestamp,
        bits,
        nonce,
    }
}

/// Best-effort deserializer mirroring `Transaction::serialize`'s layout
/// (0x00/0x01 marker, counts as u8, then fields). Returns `None` on any
/// malformed input — the point is that deserialization never panics either.
fn deserialize_tx(bytes: &[u8]) -> Option<Transaction> {
    let mut it = bytes.iter().copied();
    let _marker = it.next()?;
    let n_in = it.next()? as usize;
    let mut inputs = Vec::new();
    for _ in 0..n_in {
        let mut txid = [0u8; 32];
        for b in txid.iter_mut() {
            *b = it.next()?;
        }
        let index = u32::from_le_bytes([it.next()?, it.next()?, it.next()?, it.next()?]);
        let mut signature = [0u8; 32];
        for b in signature.iter_mut() {
            *b = it.next()?;
        }
        inputs.push(TxIn {
            prev_out: chain::block::OutPoint { txid, index },
            signature,
        });
    }
    let n_out = it.next()? as usize;
    let mut outputs = Vec::new();
    for _ in 0..n_out {
        let mut value = [0u8; 8];
        for b in value.iter_mut() {
            *b = it.next()?;
        }
        let mut script_pubkey = [0u8; 20];
        for b in script_pubkey.iter_mut() {
            *b = it.next()?;
        }
        outputs.push(TxOut {
            value: u64::from_le_bytes(value),
            script_pubkey,
        });
    }
    Some(Transaction { inputs, outputs })
}
