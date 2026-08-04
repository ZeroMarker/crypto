//! Live smoke test against a public Ethereum RPC endpoint.
//!
//! Usage: cargo run -p wallet --example live_smoke [rpc_url]
//! Prints chain id, a sample balance, and a suggested fee market.

use wallet::rpc::Client;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://eth.llamarpc.com".to_string());
    let mut client = Client::new(&url)?;

    let chain_id = client.chain_id()?;
    println!("chain_id: {chain_id}");

    // Vitalik's address — just a fixed sample address.
    let balance = client.balance("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")?;
    println!("balance:  {balance} wei");

    let fee = client.suggest_fee_market()?;
    println!("fee:      {fee:?}");

    let nonce = client.nonce("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", false)?;
    println!("nonce:    {nonce}");
    Ok(())
}
