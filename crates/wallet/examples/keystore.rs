//! Example: protect a wallet's private key with the Ethereum v3 keystore
//! format, and recover it with the password.
//!
//! ```sh
//! cargo run -p wallet --example keystore
//! ```

use wallet::keystore::Keystore;
use wallet::{Account, Mnemonic};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. A wallet derived the usual way (mnemonic → BIP-44 → signing key).
    let mnemonic = Mnemonic::parse(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )?;
    let account = Account::from_mnemonic(&mnemonic, 0)?;
    let private_key: [u8; 32] = account.signing_key().to_bytes().into();

    println!("address:    {}", account.address());
    println!("private key: 0x{}", hex::encode(private_key));

    // 2. Encrypt the private key under a password. Defaults: 262144 PBKDF2
    //    iterations, random 32-byte salt, random 16-byte IV, random UUID.
    let password = "correct horse battery staple";
    let keystore = Keystore::encrypt(&private_key, password)?;
    let json = keystore.to_json()?;
    println!("\nkeystore JSON:\n{json}\n");

    // 3. The file round-trips through JSON (this is what you'd write to
    //    ~/.ethereum/keystore/ and back up).
    let parsed = Keystore::from_json(&json)?;

    // 4. Recover the key with the password.
    let recovered = parsed.decrypt(password)?;
    assert_eq!(recovered, private_key);
    println!("decrypted key matches: true");

    // A wrong password is rejected by the MAC before any decryption.
    match parsed.decrypt("wrong password") {
        Err(e) => println!("wrong password rejected: {e}"),
        Ok(_) => panic!("wrong password must not decrypt"),
    }

    Ok(())
}
