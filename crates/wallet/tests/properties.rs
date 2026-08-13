//! Property-based tests (roadmap Phase 5 "audit"): serialize/parse round-trips
//! must hold for *arbitrary* inputs, not just the hand-picked vectors.
//!
//! - Any signed transaction, `raw()` bytes must parse back to an identical
//!   transaction (all three EIP types, random fields).
//! - Any keystore JSON produced by this crate must parse back byte-identically
//!   (serde round-trip) and decrypt under the same password.

use k256::ecdsa::SigningKey;
use proptest::prelude::*;

use wallet::keystore::Keystore;
use wallet::tx::{FeeMarket, Transaction};

/// A random-but-valid transaction. The `to` field is a 20-byte address with
/// probability 3/4 (contract creation otherwise); value is bounded to keep
/// RLP integers within u128; gas limit stays >= 21000.
fn arb_tx() -> impl Strategy<Value = Transaction> {
    (
        any::<u64>(), // chain_id (never 0)
        any::<u64>(), // nonce
        prop_oneof![
            Just(FeeMarket::Legacy { gas_price: 1 }),
            Just(FeeMarket::Eip1559 {
                max_priority_fee_per_gas: 1,
                max_fee_per_gas: 30_000_000_000,
            }),
        ],
        prop_oneof![
            3 => any::<[u8; 20]>().prop_map(Some),
            1 => Just(None),
        ],
        0u128..1_000_000_000_000_000_000u128, // value (1 ETH max)
        prop::collection::vec(any::<u8>(), 0..64), // calldata
    )
        .prop_map(|(chain_id, nonce, fee, to, value, data)| {
            let mut tx = Transaction::new(chain_id, fee, nonce, to, value, data).expect("valid tx");
            tx.gas_limit = 21_000;
            tx
        })
}

fn signing_key() -> SigningKey {
    SigningKey::from_slice(&[0x46; 32]).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// Sign → raw → from_raw must reproduce the exact transaction.
    #[test]
    fn tx_raw_roundtrip(tx in arb_tx()) {
        let sk = signing_key();
        let mut signed = tx.clone();
        signed.sign(&sk).expect("sign");
        let raw = signed.raw().expect("encode");
        let parsed = Transaction::from_raw(&raw).expect("parse");
        prop_assert_eq!(&parsed, &signed);
        // And the sender recovers to the signer's own address.
        let sender = parsed.sender_address().expect("ecrecover");
        prop_assert_eq!(sender, wallet::address_from_public_key(sk.verifying_key()));
    }

    /// Signing is deterministic (RFC 6979): same key + payload => same raw.
    #[test]
    fn tx_signing_is_deterministic(tx in arb_tx()) {
        let sk = signing_key();
        let mut a = tx.clone();
        a.sign(&sk).unwrap();
        let mut b = tx;
        b.sign(&sk).unwrap();
        prop_assert_eq!(a.raw().unwrap(), b.raw().unwrap());
    }

    /// tx_hash(raw) must agree with keccak256 of the raw bytes.
    #[test]
    fn tx_hash_matches_keccak_of_raw(tx in arb_tx()) {
        let sk = signing_key();
        let mut signed = tx;
        signed.sign(&sk).unwrap();
        let raw = signed.raw().unwrap();
        prop_assert_eq!(signed.tx_hash().unwrap(), crypto_core::hash::keccak256(&raw));    }
}

proptest! {
    // Keystore JSON must round-trip through serde and decrypt under the
    // original password for arbitrary passwords (empty included). Fewer
    // cases: each encrypt burns 262144 PBKDF2 iterations by design.
    #![proptest_config(ProptestConfig { cases: 4, ..ProptestConfig::default() })]
    #[test]
    fn keystore_json_roundtrip(password in "[a-z0-9]{0,12}", key in any::<[u8; 32]>()) {
        let ks = Keystore::encrypt(&key, &password).expect("encrypt");
        let json = ks.to_json().expect("serialize");
        let parsed = Keystore::from_json(&json).expect("parse");
        prop_assert_eq!(&parsed, &ks);
        prop_assert_eq!(parsed.decrypt(&password).expect("decrypt"), key);
    }
}
