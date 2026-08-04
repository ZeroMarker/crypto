//! Example: sign and verify a message digest with secp256k1 (Ethereum-style),
//! then recover the signer's public key from the signature (ecrecover).
//!
//! Run with:
//! ```sh
//! cargo run -p crypto-core --example signing
//! ```

use crypto_core::hash::keccak256;
use crypto_core::sign::{self, signature_to_hex};

fn main() {
    let (sk, pk) = sign::keypair_from_seed(&[7u8; 32]);

    let message = b"transfer 100 USDC to 0x1234";
    let digest = keccak256(message);

    let sig = sign::sign_digest(&sk, &digest);
    println!("signature: {}", signature_to_hex(&sig));

    let ok = sign::verify_digest(&pk, &digest, &sig);
    println!("verified:  {ok}");

    // A tampered digest must NOT verify.
    let bad = keccak256(b"transfer 999 USDC to 0x1234");
    println!("tampered:  {}", sign::verify_digest(&pk, &bad, &sig));

    // Recover the signer from `r || s || v` alone — this is what on-chain
    // `ecrecover` does to reconstruct the sender's address.
    let recovered = sign::recover_verifying_key(&digest, &sig).expect("valid signature");
    println!("recovered: {}", recovered == pk);
}
