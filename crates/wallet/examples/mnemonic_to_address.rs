//! Example: derive an Ethereum address from a BIP-39 mnemonic (BIP-44 path).
//!
//! Run with:
//! ```sh
//! cargo run -p wallet --example mnemonic_to_address
//! ```

use wallet::{Account, Mnemonic};

fn main() -> Result<(), wallet::WalletError> {
    let mnemonic = Mnemonic::generate()?;

    // Print the phrase. WARNING: this is a secret; only display when setting
    // up a new wallet, never in logs.
    println!("mnemonic: {}", mnemonic.phrase());

    let account = Account::from_mnemonic(&mnemonic, 0)?;
    println!("account 0 address: {}", account.address());

    let second = Account::from_mnemonic(&mnemonic, 1)?;
    println!("account 1 address: {}", second.address());

    Ok(())
}
