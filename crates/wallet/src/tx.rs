//! Ethereum transaction construction, signing, and parsing.
//!
//! Builds the three transaction types in use on Ethereum today, signs them
//! with a secp256k1 key (Phase 1 primitives), and decodes signed raw bytes
//! back into fields:
//!
//! | Type | EIP | Fee model | Payload |
//! |---|---|---|---|
//! | 0 | 155 | flat `gas_price` | `rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])` |
//! | 1 | 2930 | flat `gas_price` + access list | `0x01 ‖ rlp([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, yParity, r, s])` |
//! | 2 | 1559 | `max_priority_fee` + `max_fee` (base fee burned) | `0x02 ‖ rlp([chainId, nonce, maxPriority, maxFee, gasLimit, to, value, data, accessList, yParity, r, s])` |
//!
//! Signing hashes the *unsigned* payload with Keccak-256, signs the digest
//! with ECDSA (RFC 6979 deterministic nonce, low-`s` per EIP-2), then appends
//! the recovery parity. Legacy transactions get a chain-id-adjusted `v`
//! (EIP-155 replay protection); typed transactions use the raw parity.
//!
//! The whole pipeline — RLP encoding, Keccak hashing, secp256k1 signing — is
//! pinned byte-for-byte against the official EIP-155 test vector, and the
//! signing hashes below are cross-checked against an independent Python
//! implementation. The EIP-155 vector is the famous `0xf86c09...` transaction
//! included in the EIP itself.
//!
//! ```
//! use k256::ecdsa::SigningKey;
//! use wallet::tx::{FeeMarket, Transaction};
//!
//! let sk = SigningKey::from_slice(&[0x46; 32]).unwrap();
//! let to = hex::decode("3535353535353535353535353535353535353535").unwrap();
//! let mut tx = Transaction::new(
//!     1,                                              // mainnet
//!     FeeMarket::Eip1559 {
//!         max_priority_fee_per_gas: 2_500_000_000,    // 2.5 gwei tip
//!         max_fee_per_gas: 30_000_000_000,            // 30 gwei cap
//!     },
//!     9,                                              // account nonce
//!     Some(to.try_into().unwrap()),
//!     1_000_000_000_000_000_000,                      // 1 ETH in wei
//!     vec![],                                         // no calldata
//! ).unwrap();
//! tx.sign(&sk).unwrap();
//! println!("raw: 0x{}", hex::encode(tx.raw().unwrap()));
//! println!("hash: 0x{}", hex::encode(tx.tx_hash().unwrap()));
//! ```

use crypto_core::hash::keccak256;
use crypto_core::sign::{recover_verifying_key, sign_digest, SignatureData};
use k256::ecdsa::SigningKey;

use crate::address_from_public_key;

/// Errors from transaction construction, signing, or decoding.
#[derive(Debug, thiserror::Error)]
pub enum TxError {
    /// The transaction has no signature yet.
    #[error("transaction is not signed")]
    Unsigned,
    /// A field combination violates the protocol (fee cap < tip, chainId 0, ...).
    #[error("invalid transaction: {0}")]
    Invalid(String),
    /// The raw bytes do not parse as a known transaction type.
    #[error("cannot decode transaction: {0}")]
    Decode(String),
}

/// One access-list entry (EIP-2930): an address to warm up plus its storage
/// keys. Paying a small upfront cost to skip future `SLOAD`/`SSTORE` charges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessListItem {
    pub address: [u8; 20],
    pub storage_keys: Vec<[u8; 32]>,
}

/// The fee market a transaction participates in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeeMarket {
    /// Type 0/1: one flat gas price (EIP-155 legacy; EIP-2930 adds an access
    /// list). The miner keeps the whole fee.
    Legacy { gas_price: u64 },
    /// Type 2 (EIP-1559): a tip for the miner plus a cap on the total fee.
    /// The network's base fee is burned; the miner keeps the priority fee.
    Eip1559 {
        max_priority_fee_per_gas: u64,
        max_fee_per_gas: u64,
    },
}

/// An Ethereum transaction, unsigned or signed.
///
/// `value` is in wei. It is a `u128` here (covers ~3.4e20 ETH; production
/// wallets use a 256-bit integer). `to == None` means contract creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub fee: FeeMarket,
    pub gas_limit: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub access_list: Vec<AccessListItem>,
    /// `r ‖ s ‖ v` where `v` is the raw y-parity (0 or 1) for every type.
    /// The legacy chain-adjusted `v` (`chain_id * 2 + 35 + y_parity`) is
    /// computed at encode time, so large chain ids (e.g. 42161 on Arbitrum)
    /// don't overflow a byte.
    pub signature: Option<SignatureData>,
}

impl Transaction {
    /// Create an unsigned transaction with a 21,000 gas limit (a plain value
    /// transfer); override `gas_limit` for contract calls.
    pub fn new(
        chain_id: u64,
        fee: FeeMarket,
        nonce: u64,
        to: Option<[u8; 20]>,
        value: u128,
        data: Vec<u8>,
    ) -> Result<Transaction, TxError> {
        if chain_id == 0 {
            return Err(TxError::Invalid(
                "chain_id 0 is pre-EIP-155 and vulnerable to replay; use a real chain id".into(),
            ));
        }
        if let FeeMarket::Eip1559 {
            max_priority_fee_per_gas,
            max_fee_per_gas,
        } = &fee
        {
            if max_fee_per_gas < max_priority_fee_per_gas {
                return Err(TxError::Invalid(
                    "max_fee_per_gas must be >= max_priority_fee_per_gas".into(),
                ));
            }
        }
        Ok(Transaction {
            chain_id,
            nonce,
            fee,
            gas_limit: 21_000,
            to,
            value,
            data,
            access_list: Vec::new(),
            signature: None,
        })
    }

    /// The EIP-2718 type byte: 0 (legacy), 1 (EIP-2930), 2 (EIP-1559).
    pub fn tx_type(&self) -> u8 {
        match (&self.fee, self.access_list.is_empty()) {
            (FeeMarket::Legacy { .. }, true) => 0,
            (FeeMarket::Legacy { .. }, false) => 1,
            (FeeMarket::Eip1559 { .. }, _) => 2,
        }
    }

    /// The bytes that get Keccak-256'd and signed. For legacy this is the
    /// EIP-155 extended form (extra `chain_id, 0, 0`); for typed txs it is
    /// the type byte followed by the RLP of the common fields.
    pub fn signing_payload(&self) -> Vec<u8> {
        let to = rlp_to(self.to);
        let data = rlp_bytes(&self.data);
        let value = rlp_uint(self.value);
        let gas_limit = rlp_uint(self.gas_limit);
        let nonce = rlp_uint(self.nonce);
        match &self.fee {
            FeeMarket::Legacy { gas_price } => rlp_list(&[
                nonce,
                rlp_uint(*gas_price),
                gas_limit,
                to,
                value,
                data,
                rlp_uint(self.chain_id),
                rlp_bytes(&[]), // EIP-155: 0
                rlp_bytes(&[]), // EIP-155: 0
            ]),
            FeeMarket::Eip1559 {
                max_priority_fee_per_gas,
                max_fee_per_gas,
            } => {
                let mut payload = vec![0x02];
                payload.extend_from_slice(&rlp_list(&[
                    rlp_uint(self.chain_id),
                    nonce,
                    rlp_uint(*max_priority_fee_per_gas),
                    rlp_uint(*max_fee_per_gas),
                    gas_limit,
                    to,
                    value,
                    data,
                    rlp_access_list(&self.access_list),
                ]));
                payload
            }
        }
    }

    /// Keccak-256 of the signing payload — the digest the signature covers.
    pub fn signing_hash(&self) -> [u8; 32] {
        keccak256(&self.signing_payload())
    }

    /// Sign with `sk`, storing the signature. Returns the signing hash. The
    /// nonce is deterministic (RFC 6979), so signing twice gives the same raw
    /// bytes — no RNG involved.
    pub fn sign(&mut self, sk: &SigningKey) -> Result<[u8; 32], TxError> {
        let hash = self.signing_hash();
        let sig = sign_digest(sk, &hash);
        // `v` holds the raw y-parity for all types; legacy txs chain-adjust it
        // inside `raw()` where the arithmetic has u128 headroom.
        self.signature = Some(sig);
        Ok(hash)
    }

    /// The fully encoded signed transaction (the bytes you broadcast).
    pub fn raw(&self) -> Result<Vec<u8>, TxError> {
        let sig = self.signature.as_ref().ok_or(TxError::Unsigned)?;
        let common = [
            rlp_uint(self.nonce),
            rlp_uint(self.gas_limit),
            rlp_to(self.to),
            rlp_uint(self.value),
            rlp_bytes(&self.data),
        ];
        match (&self.fee, self.tx_type()) {
            (FeeMarket::Legacy { gas_price }, 0) => Ok(rlp_list(&[
                common[0].clone(),
                rlp_uint(*gas_price),
                common[1].clone(),
                common[2].clone(),
                common[3].clone(),
                common[4].clone(),
                rlp_uint(self.chain_id as u128 * 2 + 35 + sig.v as u128), // EIP-155 v
                rlp_bytes(&sig.r),
                rlp_bytes(&sig.s),
            ])),
            (FeeMarket::Legacy { gas_price }, 1) => {
                let mut out = vec![0x01];
                out.extend_from_slice(&rlp_list(&[
                    rlp_uint(self.chain_id),
                    common[0].clone(),
                    rlp_uint(*gas_price),
                    common[1].clone(),
                    common[2].clone(),
                    common[3].clone(),
                    common[4].clone(),
                    rlp_access_list(&self.access_list),
                    rlp_uint(sig.v as u128),
                    rlp_bytes(&sig.r),
                    rlp_bytes(&sig.s),
                ]));
                Ok(out)
            }
            (
                FeeMarket::Eip1559 {
                    max_priority_fee_per_gas,
                    max_fee_per_gas,
                },
                2,
            ) => {
                let mut out = vec![0x02];
                out.extend_from_slice(&rlp_list(&[
                    rlp_uint(self.chain_id),
                    common[0].clone(),
                    rlp_uint(*max_priority_fee_per_gas),
                    rlp_uint(*max_fee_per_gas),
                    common[1].clone(),
                    common[2].clone(),
                    common[3].clone(),
                    common[4].clone(),
                    rlp_access_list(&self.access_list),
                    rlp_uint(sig.v as u128),
                    rlp_bytes(&sig.r),
                    rlp_bytes(&sig.s),
                ]));
                Ok(out)
            }
            _ => unreachable!("tx_type matches fee/access-list combination"),
        }
    }

    /// The transaction hash: `keccak256(raw)`. This is the identifier other
    /// nodes use to reference the transaction.
    pub fn tx_hash(&self) -> Result<[u8; 32], TxError> {
        Ok(keccak256(&self.raw()?))
    }

    /// Recover the sender's checksummed address from the signature, without
    /// trusting any external state. Works for all types because `v` is stored
    /// as the raw y-parity.
    pub fn sender_address(&self) -> Result<String, TxError> {
        let sig = self.signature.as_ref().ok_or(TxError::Unsigned)?;
        if sig.v > 1 {
            return Err(TxError::Invalid(format!(
                "y-parity must be 0 or 1, got {}",
                sig.v
            )));
        }
        let pk = recover_verifying_key(&self.signing_hash(), sig)
            .ok_or_else(|| TxError::Invalid("signature does not verify".into()))?;
        Ok(address_from_public_key(&pk))
    }

    /// Decode raw signed bytes back into a [`Transaction`].
    pub fn from_raw(raw: &[u8]) -> Result<Transaction, TxError> {
        let (tx_type, body) = match raw.first() {
            Some(1) => (1u8, &raw[1..]),
            Some(2) => (2u8, &raw[1..]),
            _ => (0u8, raw), // legacy is a bare RLP list
        };
        let (root, consumed) = rlp_decode(body)?;
        if consumed != body.len() {
            return Err(TxError::Decode("trailing bytes after transaction".into()));
        }
        let items = match root {
            RlpItem::List(items) => items,
            RlpItem::Bytes(_) => return Err(TxError::Decode("root must be a list".into())),
        };

        // Reconstruct the fee market and common fields.
        let (fee, chain_id, signature, access_list, fields) = match tx_type {
            0 => {
                if items.len() != 9 {
                    return Err(TxError::Decode("legacy tx needs 9 fields".into()));
                }
                let gas_price = item_uint(&items[1])? as u64;
                let v = item_uint(&items[6])?;
                let r: [u8; 32] = item_bytes(&items[7])?
                    .try_into()
                    .map_err(|_| TxError::Decode("legacy r must be 32 bytes".into()))?;
                let s: [u8; 32] = item_bytes(&items[8])?
                    .try_into()
                    .map_err(|_| TxError::Decode("legacy s must be 32 bytes".into()))?;
                // v = chain_id * 2 + 35 + y_parity; recover both.
                if v < 35 {
                    return Err(TxError::Decode(format!("legacy v={v} too small")));
                }
                let y_parity = (v - 35) % 2;
                let chain_id = ((v - 35 - y_parity) / 2) as u64;
                let sig = SignatureData {
                    r,
                    s,
                    v: y_parity as u8,
                };
                (
                    FeeMarket::Legacy { gas_price },
                    chain_id,
                    sig,
                    Vec::new(),
                    vec![
                        items[0].clone(),
                        items[1].clone(),
                        items[2].clone(),
                        items[3].clone(),
                        items[4].clone(),
                        items[5].clone(),
                    ],
                )
            }
            1 => {
                if items.len() != 11 {
                    return Err(TxError::Decode("type-1 tx needs 11 fields".into()));
                }
                let chain_id = item_uint(&items[0])? as u64;
                let gas_price = item_uint(&items[2])? as u64;
                let (signature, access_list) = parse_typed_signature(&items, 8)?;
                (
                    FeeMarket::Legacy { gas_price },
                    chain_id,
                    signature,
                    access_list,
                    vec![
                        items[1].clone(),
                        items[2].clone(),
                        items[3].clone(),
                        items[4].clone(),
                        items[5].clone(),
                        items[6].clone(),
                    ],
                )
            }
            2 => {
                // EIP-1559 payload: chainId, nonce, max_prio, max_fee, gas,
                // to, value, data, access_list, yParity, r, s (12 fields).
                if items.len() != 12 {
                    return Err(TxError::Decode("type-2 tx needs 12 fields".into()));
                }
                let chain_id = item_uint(&items[0])? as u64;
                let max_priority_fee_per_gas = item_uint(&items[2])? as u64;
                let max_fee_per_gas = item_uint(&items[3])? as u64;
                let (signature, access_list) = parse_typed_signature(&items, 8)?;
                (
                    FeeMarket::Eip1559 {
                        max_priority_fee_per_gas,
                        max_fee_per_gas,
                    },
                    chain_id,
                    signature,
                    access_list,
                    // fields laid out as [nonce, _, gas, to, value, data]
                    // (position 1 is the unused fee slot).
                    vec![
                        items[1].clone(),
                        items[3].clone(),
                        items[4].clone(),
                        items[5].clone(),
                        items[6].clone(),
                        items[7].clone(),
                    ],
                )
            }
            _ => unreachable!(),
        };

        let nonce = item_uint(&fields[0])? as u64;
        let gas_limit = item_uint(&fields[2])? as u64;
        let to = item_address(&fields[3])?;
        let value = item_uint(&fields[4])?;
        let data = item_bytes(&fields[5])?.to_vec();

        Ok(Transaction {
            chain_id,
            nonce,
            fee,
            gas_limit,
            to,
            value,
            data,
            access_list,
            signature: Some(signature),
        })
    }
}

/// Parse the trailing `[y_parity, r, s]` of a typed transaction, returning
/// the signature and the access list (field at index `al_idx`).
fn parse_typed_signature(
    items: &[RlpItem<'_>],
    al_idx: usize,
) -> Result<(SignatureData, Vec<AccessListItem>), TxError> {
    let y_parity = item_uint(&items[al_idx + 1])?;
    if y_parity > 1 {
        return Err(TxError::Decode(format!(
            "y_parity must be 0 or 1, got {y_parity}"
        )));
    }
    let r: [u8; 32] = item_bytes(&items[al_idx + 2])?
        .try_into()
        .map_err(|_| TxError::Decode("r must be 32 bytes".into()))?;
    let s: [u8; 32] = item_bytes(&items[al_idx + 3])?
        .try_into()
        .map_err(|_| TxError::Decode("s must be 32 bytes".into()))?;
    let access_list = item_access_list(&items[al_idx])?;
    Ok((
        SignatureData {
            r,
            s,
            v: y_parity as u8,
        },
        access_list,
    ))
}

// ---------------------------------------------------------------------------
// RLP encoding
// ---------------------------------------------------------------------------

/// RLP-encode a byte string (with its length prefix).
fn rlp_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 3);
    if data.len() == 1 && data[0] < 0x80 {
        out.push(data[0]); // single byte < 0x80 encodes as itself
    } else if data.len() < 56 {
        out.push(0x80 + data.len() as u8);
        out.extend_from_slice(data);
    } else {
        let len_bytes = minimal_be(data.len() as u64);
        out.push(0xb7 + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(data);
    }
    out
}

/// RLP-encode a non-negative integer as its minimal big-endian form (0 = `0x80`).
fn rlp_uint<T: Into<u128>>(n: T) -> Vec<u8> {
    let n: u128 = n.into();
    if n == 0 {
        return rlp_bytes(&[]);
    }
    let mut bytes = Vec::new();
    let mut x = n;
    while x > 0 {
        bytes.push((x & 0xff) as u8);
        x >>= 8;
    }
    bytes.reverse();
    rlp_bytes(&bytes)
}

/// RLP-encode a list of already-encoded items.
fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_len: usize = items.iter().map(Vec::len).sum();
    let mut out = Vec::with_capacity(payload_len + 9);
    if payload_len < 56 {
        out.push(0xc0 + payload_len as u8);
    } else {
        let len_bytes = minimal_be(payload_len as u64);
        out.push(0xf7 + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
    }
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// `to` field: empty bytes for contract creation.
fn rlp_to(to: Option<[u8; 20]>) -> Vec<u8> {
    match to {
        Some(addr) => rlp_bytes(&addr),
        None => rlp_bytes(&[]),
    }
}

/// RLP-encode an access list: `[[address, [key, ...]], ...]`.
fn rlp_access_list(list: &[AccessListItem]) -> Vec<u8> {
    let entries: Vec<Vec<u8>> = list
        .iter()
        .map(|entry| {
            let keys: Vec<Vec<u8>> = entry.storage_keys.iter().map(|k| rlp_bytes(k)).collect();
            rlp_list(&[rlp_bytes(&entry.address), rlp_list(&keys)])
        })
        .collect();
    rlp_list(&entries)
}

/// Minimal big-endian bytes of `n` (empty for 0).
fn minimal_be(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while n > 0 {
        out.push((n & 0xff) as u8);
        n >>= 8;
    }
    out.reverse();
    out
}

// ---------------------------------------------------------------------------
// RLP decoding
// ---------------------------------------------------------------------------

/// A decoded RLP node: a byte string or a list of further nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RlpItem<'a> {
    Bytes(&'a [u8]),
    List(Vec<RlpItem<'a>>),
}

/// Decode one RLP item from the front of `data`, returning it plus the number
/// of bytes consumed. Fails on truncated or absurdly large inputs.
fn rlp_decode(data: &[u8]) -> Result<(RlpItem<'_>, usize), TxError> {
    let first = *data
        .first()
        .ok_or_else(|| TxError::Decode("empty input".into()))?;
    if first < 0x80 {
        return Ok((RlpItem::Bytes(&data[..1]), 1));
    }
    if first <= 0xb7 {
        let len = (first - 0x80) as usize;
        return Ok((RlpItem::Bytes(take(data, 1, len)?), 1 + len));
    }
    if first <= 0xbf {
        let len_len = (first - 0xb7) as usize;
        let len = be_len(take(data, 1, len_len)?)?;
        return Ok((
            RlpItem::Bytes(take(data, 1 + len_len, len)?),
            1 + len_len + len,
        ));
    }
    if first <= 0xf7 {
        let len = (first - 0xc0) as usize;
        let payload = take(data, 1, len)?;
        return Ok((RlpItem::List(parse_list(payload)?), 1 + len));
    }
    let len_len = (first - 0xf7) as usize;
    let len = be_len(take(data, 1, len_len)?)?;
    let payload = take(data, 1 + len_len, len)?;
    Ok((RlpItem::List(parse_list(payload)?), 1 + len_len + len))
}

/// Decode a list payload into its child items.
fn parse_list(payload: &[u8]) -> Result<Vec<RlpItem<'_>>, TxError> {
    let mut items = Vec::new();
    let mut rest = payload;
    while !rest.is_empty() {
        let (item, consumed) = rlp_decode(rest)?;
        items.push(item);
        rest = &rest[consumed..];
    }
    Ok(items)
}

/// `data[offset..offset+len]` with bounds checking.
fn take(data: &[u8], offset: usize, len: usize) -> Result<&[u8], TxError> {
    data.get(offset..offset + len)
        .ok_or_else(|| TxError::Decode("RLP length overruns input".into()))
}

/// Decode a big-endian length prefix (1..=8 bytes).
fn be_len(bytes: &[u8]) -> Result<usize, TxError> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(TxError::Decode("bad RLP length prefix".into()));
    }
    let mut n = 0usize;
    for b in bytes {
        n = n << 8 | *b as usize;
    }
    Ok(n)
}

/// Interpret an RLP item as bytes.
fn item_bytes<'a>(item: &RlpItem<'a>) -> Result<&'a [u8], TxError> {
    match item {
        RlpItem::Bytes(b) => Ok(b),
        RlpItem::List(_) => Err(TxError::Decode("expected byte string, got list".into())),
    }
}

/// Interpret an RLP item as a non-negative integer.
fn item_uint(item: &RlpItem<'_>) -> Result<u128, TxError> {
    let bytes = item_bytes(item)?;
    if bytes.len() > 16 {
        return Err(TxError::Decode("integer wider than u128".into()));
    }
    let mut n = 0u128;
    for b in bytes {
        n = n << 8 | *b as u128;
    }
    Ok(n)
}

/// Interpret `to`: empty bytes → `None`, else 20-byte address.
fn item_address(item: &RlpItem<'_>) -> Result<Option<[u8; 20]>, TxError> {
    let bytes = item_bytes(item)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    bytes
        .try_into()
        .map(Some)
        .map_err(|_| TxError::Decode("to must be empty or exactly 20 bytes".into()))
}

/// Parse an access list item into structured entries.
fn item_access_list(item: &RlpItem<'_>) -> Result<Vec<AccessListItem>, TxError> {
    let entries = match item {
        RlpItem::List(l) => l,
        _ => return Err(TxError::Decode("access list must be a list".into())),
    };
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let fields = match entry {
            RlpItem::List(l) if l.len() == 2 => l,
            _ => {
                return Err(TxError::Decode(
                    "access list entry must be [address, keys]".into(),
                ))
            }
        };
        let address: [u8; 20] = item_bytes(&fields[0])?
            .try_into()
            .map_err(|_| TxError::Decode("access list address must be 20 bytes".into()))?;
        let keys = match &fields[1] {
            RlpItem::List(l) => l,
            _ => {
                return Err(TxError::Decode(
                    "access list storage keys must be a list".into(),
                ))
            }
        };
        let mut storage_keys = Vec::with_capacity(keys.len());
        for key in keys {
            storage_keys.push(
                item_bytes(key)?.try_into().map_err(|_| {
                    TxError::Decode("access list storage key must be 32 bytes".into())
                })?,
            );
        }
        out.push(AccessListItem {
            address,
            storage_keys,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer_key() -> SigningKey {
        // The EIP-155 spec's example key: 32 bytes of 0x46.
        SigningKey::from_slice(&[0x46; 32]).unwrap()
    }

    fn example_to() -> [u8; 20] {
        hex::decode("3535353535353535353535353535353535353535")
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn rlp_spec_vectors() {
        // Canonical RLP vectors (ethereum/tests rlptest suite).
        assert_eq!(hex::encode(rlp_bytes(b"")), "80");
        assert_eq!(hex::encode(rlp_bytes(b"dog")), "83646f67");
        assert_eq!(hex::encode(rlp_bytes(&[15])), "0f");
        assert_eq!(hex::encode(rlp_bytes(&[0x80])), "8180");
        assert_eq!(hex::encode(rlp_uint(1024u32)), "820400");
        assert_eq!(hex::encode(rlp_list(&[])), "c0");
        assert_eq!(
            hex::encode(rlp_list(&[rlp_bytes(b"cat"), rlp_bytes(b"dog")])),
            "c88363617483646f67"
        );
        // Strings of exactly 56 bytes flip to the long form.
        assert_eq!(
            hex::encode(rlp_bytes(&[0x5a; 56])),
            format!("b838{}", "5a".repeat(56))
        );
        // And decode round-trips everything above.
        for bytes in [
            rlp_bytes(b""),
            rlp_bytes(b"dog"),
            rlp_bytes(&[15]),
            rlp_bytes(&[0x80]),
            rlp_uint(1024u32),
            rlp_list(&[]),
            rlp_list(&[rlp_bytes(b"cat"), rlp_bytes(b"dog")]),
            rlp_bytes(&[0x5a; 56]),
            rlp_bytes(&[0x5a; 200]), // long string + long-ish length byte
        ] {
            let (item, consumed) = rlp_decode(&bytes).unwrap();
            assert_eq!(consumed, bytes.len());
            let reencoded = match item {
                RlpItem::Bytes(b) => rlp_bytes(b),
                RlpItem::List(_) => bytes.clone(),
            };
            assert_eq!(reencoded, bytes);
        }
    }

    #[test]
    fn eip155_spec_vector_byte_exact() {
        // The canonical EIP-155 example: key 0x46*32, nonce 9, 20 gwei,
        // 21000 gas, 1 ETH to 0x3535..., chain 1. The raw signed bytes are
        // pinned by the EIP itself; signing must reproduce them exactly.
        let sk = signer_key();
        let mut tx = Transaction::new(
            1,
            FeeMarket::Legacy {
                gas_price: 20_000_000_000,
            },
            9,
            Some(example_to()),
            1_000_000_000_000_000_000,
            vec![],
        )
        .unwrap();
        tx.gas_limit = 21_000;
        let hash = tx.sign(&sk).unwrap();

        // Independent Python (pycryptodome keccak + stdlib RLP) computed:
        assert_eq!(
            hex::encode(hash),
            "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
        );
        assert_eq!(
            hex::encode(tx.raw().unwrap()),
            "f86c098504a817c800825208943535353535353535353535353535353535353535\
             880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d\
             3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9\
             f3dc64214b297fb1966a3b6d83"
        );
        // tx_hash computed independently: keccak256 of the canonical raw is
        // the hash of the real mainnet transaction (0x33469b22...).
        assert_eq!(
            hex::encode(tx.tx_hash().unwrap()),
            "33469b22e9f636356c4160a87eb19df52b7412e8eac32a4a55ffe88ea8350788"
        );
        // The sender recovers to the key's own address.
        assert_eq!(
            tx.sender_address().unwrap(),
            address_from_public_key(sk.verifying_key())
        );
        // And the raw bytes parse back into the identical transaction.
        assert_eq!(Transaction::from_raw(&tx.raw().unwrap()).unwrap(), tx);
    }

    #[test]
    fn eip1559_signing_and_roundtrip() {
        let sk = signer_key();
        let mut tx = Transaction::new(
            1,
            FeeMarket::Eip1559 {
                max_priority_fee_per_gas: 2_500_000_000,
                max_fee_per_gas: 30_000_000_000,
            },
            9,
            Some(example_to()),
            1_000_000_000_000_000_000,
            vec![],
        )
        .unwrap();
        tx.gas_limit = 21_000;
        assert_eq!(tx.tx_type(), 2);

        let hash = tx.sign(&sk).unwrap();
        // Cross-checked against the independent Python implementation.
        assert_eq!(
            hex::encode(hash),
            "f4b13dcf37ae6bc9285ac3a787acadb6be5a3e79861a1b9d4922cd728cbbf8e2"
        );

        let raw = tx.raw().unwrap();
        assert_eq!(raw[0], 0x02);
        // Deterministic signing: same key+payload => same raw bytes.
        let mut again = tx.clone();
        again.signature = None;
        again.sign(&sk).unwrap();
        assert_eq!(again.raw().unwrap(), raw);

        // ecrecover round-trips to the signer.
        assert_eq!(
            tx.sender_address().unwrap(),
            address_from_public_key(sk.verifying_key())
        );
        // Decode parses the raw bytes back into the same transaction.
        let parsed = Transaction::from_raw(&raw).unwrap();
        assert_eq!(parsed, tx);
        assert_eq!(parsed.tx_hash().unwrap(), keccak256(&raw));
    }

    #[test]
    fn eip1559_with_access_list() {
        let sk = signer_key();
        let mut tx = Transaction::new(
            1,
            FeeMarket::Eip1559 {
                max_priority_fee_per_gas: 2_500_000_000,
                max_fee_per_gas: 30_000_000_000,
            },
            9,
            Some(example_to()),
            1_000_000_000_000_000_000,
            vec![],
        )
        .unwrap();
        tx.gas_limit = 21_000;
        tx.access_list = vec![AccessListItem {
            address: hex::decode("de0b295669a9fd93d5f28d9ec85e40f4cb697bae")
                .unwrap()
                .try_into()
                .unwrap(),
            storage_keys: vec![
                {
                    let mut k = [0u8; 32];
                    k[31] = 3;
                    k
                },
                {
                    let mut k = [0u8; 32];
                    k[31] = 7;
                    k
                },
            ],
        }];

        let hash = tx.sign(&sk).unwrap();
        // Cross-checked against the independent Python implementation.
        assert_eq!(
            hex::encode(hash),
            "bf1b7151bcbd33dae85f67d910f3dcb48fe06c2bef46aadc4e007de6f4c542b9"
        );

        let raw = tx.raw().unwrap();
        let parsed = Transaction::from_raw(&raw).unwrap();
        assert_eq!(parsed, tx);
        assert_eq!(
            parsed.sender_address().unwrap(),
            address_from_public_key(sk.verifying_key())
        );
    }

    #[test]
    fn contract_creation_and_empty_fields() {
        let sk = signer_key();
        // to = None => contract creation; the `to` field is RLP-empty (0x80).
        let mut tx =
            Transaction::new(5, FeeMarket::Legacy { gas_price: 1 }, 0, None, 0, vec![]).unwrap();
        tx.sign(&sk).unwrap();
        let raw = tx.raw().unwrap();
        let parsed = Transaction::from_raw(&raw).unwrap();
        assert_eq!(parsed, tx);
        assert_eq!(parsed.to, None);
        assert_eq!(parsed.value, 0);
        assert_eq!(parsed.chain_id, 5);
        assert_eq!(
            parsed.sender_address().unwrap(),
            address_from_public_key(sk.verifying_key())
        );
    }

    #[test]
    fn large_chain_id_legacy_v_fits() {
        // Arbitrum One's chain id (42161) makes legacy v = 2*42161+35+1 =
        // 84358, far beyond u8. It must encode and decode losslessly.
        let sk = signer_key();
        let mut tx = Transaction::new(
            42161,
            FeeMarket::Legacy {
                gas_price: 1_000_000_000,
            },
            0,
            Some(example_to()),
            1,
            vec![],
        )
        .unwrap();
        tx.sign(&sk).unwrap();
        let raw = tx.raw().unwrap();
        let parsed = Transaction::from_raw(&raw).unwrap();
        assert_eq!(parsed, tx);
        assert_eq!(parsed.chain_id, 42161);
        assert_eq!(
            parsed.sender_address().unwrap(),
            address_from_public_key(sk.verifying_key())
        );
    }

    #[test]
    fn invalid_transactions_rejected() {
        // chain_id 0 (pre-EIP-155, replay-vulnerable).
        assert!(
            Transaction::new(0, FeeMarket::Legacy { gas_price: 1 }, 0, None, 0, vec![]).is_err()
        );
        // max fee below the tip.
        assert!(Transaction::new(
            1,
            FeeMarket::Eip1559 {
                max_priority_fee_per_gas: 30,
                max_fee_per_gas: 20,
            },
            0,
            None,
            0,
            vec![],
        )
        .is_err());
        // raw() before signing.
        let tx =
            Transaction::new(1, FeeMarket::Legacy { gas_price: 1 }, 0, None, 0, vec![]).unwrap();
        assert!(matches!(tx.raw(), Err(TxError::Unsigned)));
        assert!(matches!(tx.sender_address(), Err(TxError::Unsigned)));
    }

    #[test]
    fn tampered_raw_fails_parse_or_recovery() {
        let sk = signer_key();
        let mut tx = Transaction::new(
            1,
            FeeMarket::Eip1559 {
                max_priority_fee_per_gas: 1_000_000_000,
                max_fee_per_gas: 2_000_000_000,
            },
            3,
            Some(example_to()),
            5_000_000_000_000_000_000,
            vec![],
        )
        .unwrap();
        tx.sign(&sk).unwrap();
        let mut raw = tx.raw().unwrap();

        // Corrupting the signature must break ecrecover (or the parse).
        let last = raw.len() - 1;
        raw[last] ^= 1;
        // If it still parses, the signature must no longer recover the
        // original sender (either fails or yields a stranger).
        if let Ok(parsed) = Transaction::from_raw(&raw) {
            let sender = parsed.sender_address();
            assert!(
                sender.is_err() || sender.unwrap() != address_from_public_key(sk.verifying_key())
            );
        }
    }
}
