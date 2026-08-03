//! Example: hashes used across Bitcoin and Ethereum in one place.
//!
//! Run with:
//! ```sh
//! cargo run -p crypto-core --example hashes
//! ```

use crypto_core::hash::{hmac_sha256, keccak256, ripemd160, sha256, sha3_256};
use hex::ToHex;

fn main() {
    let data = b"Rust for crypto";

    println!("sha256      {}", sha256(data).encode_hex::<String>());
    println!("sha3-256    {}", sha3_256(data).encode_hex::<String>());
    println!("keccak-256  {}", keccak256(data).encode_hex::<String>());
    println!("ripemd-160  {}", ripemd160(data).encode_hex::<String>());
    println!(
        "hmac-sha256 {}",
        hmac_sha256(b"key", data).encode_hex::<String>()
    );
}
