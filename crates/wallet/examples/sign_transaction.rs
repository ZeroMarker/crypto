//! Example: build, sign, and verify an EIP-1559 Ethereum transaction.
//!
//! ```sh
//! cargo run -p wallet --example sign_transaction
//! ```

use wallet::tx::{FeeMarket, Transaction};
use wallet::{Account, Mnemonic};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. A wallet derived the usual way (mnemonic → BIP-44 → signing key).
    let mnemonic = Mnemonic::parse(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )?;
    let account = Account::from_mnemonic(&mnemonic, 0)?;

    // 2. A fee-market transaction: send 0.01 ETH to a testnet address.
    let to: [u8; 20] = hex::decode("3535353535353535353535353535353535353535")?
        .try_into()
        .map_err(|_| "recipient must be 20 bytes")?;
    let mut tx = Transaction::new(
        1, // chain id 1 (mainnet; use 11155111 for Sepolia)
        FeeMarket::Eip1559 {
            max_priority_fee_per_gas: 1_500_000_000, // 1.5 gwei tip
            max_fee_per_gas: 30_000_000_000,         // 30 gwei cap
        },
        0, // nonce: number of txs the account has already sent
        Some(to),
        10_000_000_000_000_000, // 0.01 ETH in wei
        vec![],                 // no calldata
    )?;
    tx.gas_limit = 21_000; // plain transfer

    // 3. Sign (deterministic RFC 6979) and print everything broadcastable.
    tx.sign(account.signing_key())?;
    let raw = tx.raw()?;
    let hash = tx.tx_hash()?;
    println!("sender:     {}", account.address());
    println!("recipient:  0x{}", hex::encode(to));
    println!("tx hash:    0x{}", hex::encode(hash));
    println!("raw (hex):  0x{}", hex::encode(&raw));

    // 4. Any node can parse the raw bytes and recover the sender.
    let parsed = Transaction::from_raw(&raw)?;
    println!("parsed sender: {}", parsed.sender_address()?);
    assert_eq!(parsed.sender_address()?, account.address());
    println!("recovered sender matches: true");

    Ok(())
}
