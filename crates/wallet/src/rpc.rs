//! Minimal Ethereum JSON-RPC client (blocking) plus fee/nonce helpers.
//!
//! Uses `ureq` for HTTP transport. All quantities are returned in native
//! integer form (`u64`/`u128`) and converted to/from the hex-quantity JSON
//! encoding used by `eth_*` methods.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::tx::{FeeMarket, Transaction};

/// Errors produced by RPC calls or gas/nonce estimation.
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    /// Transport failure (DNS, connection, timeout, ...).
    #[error("transport error: {0}")]
    Transport(String),
    /// The server returned an HTTP error status.
    #[error("http error {status}: {body}")]
    Http { status: u16, body: String },
    /// The server returned a JSON-RPC error object.
    #[error("rpc error {code}: {message}")]
    Rpc { code: i64, message: String },
    /// The response did not parse or had an unexpected shape.
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    /// The requested chain is not supported (bad chain id match).
    #[error("chain mismatch: node is on {0}, expected {1}")]
    ChainMismatch(u64, u64),
}

/// Internal JSON-RPC response envelope.
#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcErrorBody>,
}

#[derive(Deserialize)]
struct RpcErrorBody {
    code: i64,
    message: String,
}

/// A blocking Ethereum JSON-RPC client.
///
/// ```no_run
/// use wallet::rpc::Client;
/// let mut client = Client::new("https://eth.llamarpc.com")?;
/// let chain_id = client.chain_id()?;
/// # Ok::<(), wallet::rpc::RpcError>(())
/// ```
#[derive(Debug, Clone)]
pub struct Client {
    url: String,
    agent: ureq::Agent,
    request_id: u64,
}

impl Client {
    /// Create a client for the given JSON-RPC endpoint.
    pub fn new(url: &str) -> Result<Client, RpcError> {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(30)))
            .build()
            .new_agent();
        Ok(Client {
            url: url.to_string(),
            agent,
            request_id: 0,
        })
    }

    /// Send a raw JSON-RPC request. Generic over the expected result type.
    fn call<T: for<'de> Deserialize<'de>>(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<T, RpcError> {
        self.request_id += 1;
        let body = json!({
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
            "params": params,
        });
        let resp = self
            .agent
            .post(&self.url)
            .send_json(body)
            .map_err(|e| RpcError::Transport(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .into_body()
            .read_to_string()
            .map_err(|e| RpcError::Transport(e.to_string()))?;
        if status != 200 {
            return Err(RpcError::Http {
                status: status.into(),
                body: text.chars().take(512).collect(),
            });
        }
        let parsed: RpcResponse<T> = serde_json::from_str(&text)
            .map_err(|e| RpcError::InvalidResponse(format!("{e}: {text}")))?;
        if let Some(err) = parsed.error {
            return Err(RpcError::Rpc {
                code: err.code,
                message: err.message,
            });
        }
        parsed
            .result
            .ok_or_else(|| RpcError::InvalidResponse("missing result".into()))
    }

    /// `eth_chainId` — the chain id the node is connected to.
    pub fn chain_id(&mut self) -> Result<u64, RpcError> {
        let hex: String = self.call("eth_chainId", json!([]))?;
        unquantity(&hex).map(|v| v as u64)
    }

    /// `eth_getBalance` — balance in wei at `address` (default: latest block).
    pub fn balance(&mut self, address: &str) -> Result<u128, RpcError> {
        let hex: String = self.call("eth_getBalance", json!([address, "latest"]))?;
        unquantity(&hex)
    }

    /// `eth_getTransactionCount` — the on-chain nonce for `address`
    /// (pending: includes txs in the mempool from this account).
    pub fn nonce(&mut self, address: &str, pending: bool) -> Result<u64, RpcError> {
        let block = if pending { "pending" } else { "latest" };
        let hex: String = self.call("eth_getTransactionCount", json!([address, block]))?;
        Ok(unquantity(&hex)? as u64)
    }

    /// `eth_gasPrice` — the node's suggested legacy gas price.
    pub fn gas_price(&mut self) -> Result<u64, RpcError> {
        let hex: String = self.call("eth_gasPrice", json!([]))?;
        Ok(unquantity(&hex)? as u64)
    }

    /// `eth_maxPriorityFeePerGas` — the node's tip suggestion for EIP-1559.
    pub fn max_priority_fee(&mut self) -> Result<u64, RpcError> {
        let hex: String = self.call("eth_maxPriorityFeePerGas", json!([]))?;
        Ok(unquantity(&hex)? as u64)
    }

    /// `eth_estimateGas` — simulate `tx` and get the required gas.
    ///
    /// The transaction must not be signed; the node runs it against the
    /// current state using the zero account as sender unless the caller
    /// supplies a `from`.
    pub fn estimate_gas(&mut self, tx: &Transaction, from: Option<&str>) -> Result<u64, RpcError> {
        let mut obj = serde_json::Map::new();
        if let Some(from) = from {
            obj.insert("from".into(), json!(from));
        }
        match &tx.to {
            Some(to) => {
                obj.insert("to".into(), json!(format!("0x{}", hex::encode(to))));
            }
            None => {
                obj.insert("data".into(), json!(format!("0x{}", hex::encode(&tx.data))));
            }
        }
        if !tx.data.is_empty() {
            obj.insert("data".into(), json!(format!("0x{}", hex::encode(&tx.data))));
        }
        obj.insert("value".into(), json!(quantity(tx.value)));
        match &tx.fee {
            FeeMarket::Legacy { gas_price } => {
                obj.insert("gasPrice".into(), json!(quantity(*gas_price)));
            }
            FeeMarket::Eip1559 {
                max_priority_fee_per_gas,
                max_fee_per_gas,
            } => {
                obj.insert(
                    "maxPriorityFeePerGas".into(),
                    json!(quantity(*max_priority_fee_per_gas)),
                );
                obj.insert("maxFeePerGas".into(), json!(quantity(*max_fee_per_gas)));
            }
        }
        let hex: String = self.call("eth_estimateGas", json!([obj]))?;
        Ok(unquantity(&hex)? as u64)
    }

    /// `eth_sendRawTransaction` — broadcast a signed raw transaction.
    /// Returns the transaction hash.
    pub fn send_raw_transaction(&mut self, raw: &[u8]) -> Result<String, RpcError> {
        let hex: String = self.call(
            "eth_sendRawTransaction",
            json!([format!("0x{}", hex::encode(raw))]),
        )?;
        Ok(hex)
    }

    /// `eth_getTransactionReceipt` — fetch a receipt by hash; `None` when
    /// the tx is not mined (still pending/unknown).
    pub fn receipt(&mut self, tx_hash: &str) -> Result<Option<Receipt>, RpcError> {
        let opt: Option<Value> = self.call("eth_getTransactionReceipt", json!([tx_hash]))?;
        match opt {
            None => Ok(None),
            Some(v) => serde_json::from_value(v)
                .map(Some)
                .map_err(|e| RpcError::InvalidResponse(e.to_string())),
        }
    }

    /// `eth_feeHistory` — recent base fees + priority fee percentiles.
    /// Used for a smarter EIP-1559 estimate than the node's raw suggestion.
    pub fn fee_history(
        &mut self,
        blocks: u64,
        newest_block: &str,
        percentiles: &[f64],
    ) -> Result<FeeHistory, RpcError> {
        let v: Value = self.call("eth_feeHistory", json!([blocks, newest_block, percentiles]))?;
        serde_json::from_value(v).map_err(|e| RpcError::InvalidResponse(e.to_string()))
    }

    /// Suggest a fee market for the next transaction.
    ///
    /// For EIP-1559 chains this reads the tip suggestion plus the
    /// 90th-percentile priority fee from recent blocks when available, and
    /// computes a base-fee cap from `feeHistory` (latest base × 2 + tip) so
    /// the tx survives a few blocks of congestion.
    ///
    /// For legacy (PoW) chains it falls back to `eth_gasPrice`.
    pub fn suggest_fee_market(&mut self) -> Result<FeeMarket, RpcError> {
        match self.max_priority_fee() {
            Ok(tip) => {
                let mut tip = tip;
                if let Ok(fh) = self.fee_history(5, "latest", &[90.0]) {
                    for h in &fh.reward {
                        if let Some(r) = h.last() {
                            if *r > tip {
                                tip = *r;
                            }
                        }
                    }
                }
                let latest = if let Ok(fh) = self.fee_history(1, "latest", &[]) {
                    fh.base_fee_per_gas.last().copied().unwrap_or(0)
                } else {
                    0
                };
                // cap = (current base × 2) + tip → survives ~2× base growth.
                let cap = tip.saturating_add(latest.saturating_mul(2).max(latest));
                Ok(FeeMarket::Eip1559 {
                    max_priority_fee_per_gas: tip,
                    max_fee_per_gas: cap,
                })
            }
            Err(RpcError::Rpc { .. }) => {
                let gp = self.gas_price()?;
                Ok(FeeMarket::Legacy { gas_price: gp })
            }
            Err(e) => Err(e),
        }
    }

    /// Convenience: fill in `nonce`, `fee`, and `gas_limit` for a `Transaction`.
    ///
    /// - `nonce` from pending tx count
    /// - `fee` from `suggest_fee_market`
    /// - `gas_limit` from `eth_estimateGas` (fallback: 21_000 transfer default)
    ///
    /// `from` is the account that will sign; required for accurate gas
    /// estimation on contract calls.
    pub fn fill_transaction(&mut self, tx: &mut Transaction, from: &str) -> Result<(), RpcError> {
        tx.nonce = self.nonce(from, true)?;
        tx.fee = self.suggest_fee_market()?;
        match self.estimate_gas(tx, Some(from)) {
            Ok(gas) => tx.gas_limit = gas,
            Err(RpcError::Rpc { ref message, .. }) if message.contains("intrinsic gas too low") => {
                // Purely a value transfer; the 21,000 default is correct.
                tx.gas_limit = 21_000;
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }
}

/// A transaction receipt (fields we care about).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    pub transaction_hash: String,
    pub status: Option<String>,
    pub gas_used: String,
    pub effective_gas_price: Option<String>,
    #[serde(default)]
    pub logs: Vec<Value>,
}

impl Receipt {
    /// Whether the transaction succeeded (`status == "0x1"`).
    pub fn is_success(&self) -> bool {
        self.status.as_deref() == Some("0x1")
    }
}

/// `eth_feeHistory` response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeHistory {
    #[serde(default)]
    pub base_fee_per_gas: Vec<u64>,
    #[serde(default)]
    pub reward: Vec<Vec<u64>>,
}

/// Parse a hex quantity (0x-prefixed, big-endian, no leading zeros) to u128.
fn unquantity(hex: &str) -> Result<u128, RpcError> {
    let clean = hex.strip_prefix("0x").unwrap_or(hex);
    if clean.is_empty() {
        return Ok(0);
    }
    u128::from_str_radix(clean, 16)
        .map_err(|e| RpcError::InvalidResponse(format!("bad hex quantity {hex:?}: {e}")))
}

/// Encode an integer as a hex quantity (0x-prefixed, no leading zeros).
fn quantity(v: impl Into<u128>) -> String {
    format!("0x{:x}", v.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantity_round_trip() {
        for v in [0u128, 1, 21_000, 0xffffffff, u64::MAX as u128, u128::MAX] {
            let q = quantity(v);
            assert_eq!(unquantity(&q).unwrap(), v);
        }
    }

    #[test]
    fn quantity_parses_odd_forms() {
        assert_eq!(unquantity("0x0").unwrap(), 0);
        assert_eq!(unquantity("0x").unwrap(), 0);
        assert_eq!(unquantity("0x2a").unwrap(), 42);
        assert_eq!(unquantity("2a").unwrap(), 42);
    }

    #[test]
    fn quantity_rejects_bad() {
        assert!(unquantity("0xzz").is_err());
        assert!(unquantity("0x12g").is_err());
        assert!(unquantity("0x-1").is_err());
    }

    #[test]
    fn receipt_success_flag() {
        let ok = Receipt {
            transaction_hash: "0xabc".into(),
            status: Some("0x1".into()),
            gas_used: "0x5208".into(),
            effective_gas_price: None,
            logs: vec![],
        };
        let fail = Receipt {
            status: Some("0x0".into()),
            ..ok.clone()
        };
        assert!(ok.is_success());
        assert!(!fail.is_success());
    }
}
