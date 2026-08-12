//! Deterministic mutational fuzzing (roadmap Phase 5 "audit") on a stable
//! toolchain — no nightly/libFuzzer required.
//!
//! Each test seeds a xorshift PRNG, mutates a valid seed input (a signed
//! transaction, a keystore JSON, raw RLP), and asserts the parser **never
//! panics** — it must return `Ok` or `Err`, never crash. Panics in parsers
//! are memory-safety-adjacent bugs (index overruns, integer overflow in
//! length math, stack exhaustion via recursion).
//!
//! Runs are reproducible: the seed is fixed, so a failing build fails the
//! same way every time. Increase `ITERS` and run with `--release` for a
//! deeper sweep (`cargo test -p wallet --release --test fuzz`).

use k256::ecdsa::SigningKey;
use wallet::keystore::Keystore;
use wallet::tx::{FeeMarket, Transaction};

/// Deterministic PRNG (xorshift64*). `next()` is a u64 in `[0, u64::MAX]`.
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
    /// Random index into a slice.
    fn pick(&mut self, len: usize) -> usize {
        (self.next() % len as u64) as usize
    }
    /// Flip a random bit in a byte buffer.
    fn mutate(&mut self, buf: &mut [u8]) {
        if buf.is_empty() {
            return;
        }
        let i = self.pick(buf.len());
        buf[i] ^= 1 << (self.next() % 8);
    }
}

/// Iterations per fuzz target. Cheap parsers can afford a few thousand in a
/// debug build; bump to 100_000+ with `--release`.
const ITERS: usize = 4_000;

fn signer_key() -> SigningKey {
    SigningKey::from_slice(&[0x46; 32]).unwrap()
}

/// A canonical signed EIP-1559 transaction to mutate.
fn seed_tx_raw() -> Vec<u8> {
    let sk = signer_key();
    let to: [u8; 20] = hex::decode("3535353535353535353535353535353535353535")
        .unwrap()
        .try_into()
        .unwrap();
    let mut tx = Transaction::new(
        1,
        FeeMarket::Eip1559 {
            max_priority_fee_per_gas: 2_500_000_000,
            max_fee_per_gas: 30_000_000_000,
        },
        9,
        Some(to),
        1_000_000_000_000_000_000,
        vec![],
    )
    .unwrap();
    tx.gas_limit = 21_000;
    tx.sign(&sk).unwrap();
    tx.raw().unwrap()
}

/// `Transaction::from_raw` must never panic, on any bytes.
#[test]
fn fuzz_transaction_from_raw_never_panics() {
    let seed = seed_tx_raw();
    let mut rng = Rng::new(0x5EED_CAFE);
    for _ in 0..ITERS {
        let mut buf = seed.clone();
        // 1-3 mutations, sometimes truncation, sometimes extension.
        let flips = 1 + rng.pick(3);
        for _ in 0..flips {
            rng.mutate(&mut buf);
        }
        match rng.next() % 4 {
            0 => buf.truncate(rng.pick(buf.len() + 1)),
            1 => buf.extend_from_slice(&[rng.next() as u8; 8]),
            _ => {}
        }
        let _ = Transaction::from_raw(&buf); // must not panic
    }
}

/// `Keystore::from_json` must never panic on arbitrary strings.
#[test]
fn fuzz_keystore_from_json_never_panics() {
    let seed = r#"{"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"6087dab2f9fdbbfaddc31a909735c1e6"},"ciphertext":"5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46","kdf":"pbkdf2","kdfparams":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"},"mac":"517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"},"id":"3198bc9c-6672-5ab3-d995-4942343ae5b6","version":3}"#;
    let mut bytes = seed.as_bytes().to_vec();
    let mut rng = Rng::new(0xDEAD_BEEF);
    for _ in 0..ITERS {
        let mut buf = bytes.clone();
        let flips = 1 + rng.pick(4);
        for _ in 0..flips {
            rng.mutate(&mut buf);
        }
        // Occasionally truncate in the middle of a hex string / number.
        if rng.next() % 3 == 0 {
            buf.truncate(rng.pick(buf.len() + 1));
        }
        // Keep the seed fresh: every 256 iterations re-randomize a chunk.
        if rng.next() % 256 == 0 {
            bytes = buf.clone();
        }
        let s = String::from_utf8_lossy(&buf);
        let _ = Keystore::from_json(&s); // must not panic
    }
}

/// The RLP decoder is the deepest recursive parser; flood it with nested
/// list headers to make sure depth is bounded by input length (no stack
/// exhaustion from a tiny input).
#[test]
fn fuzz_rlp_nested_lists_no_stack_overflow() {
    let mut rng = Rng::new(0xF0F0_F0F0);
    for _ in 0..ITERS {
        // A byte like 0xf8 0xff 0xf8 0xff ... declares a long list containing
        // a long list: depth grows linearly with bytes.
        let depth = 1 + rng.pick(64);
        let mut buf = Vec::with_capacity(depth * 2);
        for _ in 0..depth {
            buf.push(0xf8);
            buf.push(0xff);
        }
        buf.extend_from_slice(&[rng.next() as u8; 16]);
        let _ = Transaction::from_raw(&buf); // must not panic
    }
}
