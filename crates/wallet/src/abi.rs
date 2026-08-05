//! # ABI encoding / decoding (Ethereum Contract ABI)
//!
//! Phase 3 — the missing link between `rpc::Client` and a deployed contract.
//! Builds calldata for `eth_call` / `eth_sendRawTransaction` and decodes
//! return values and logs.
//!
//! Implements the [Contract ABI specification](https://docs.soliditylang.org/en/latest/abi-spec.html):
//!
//! ```text
//! head: one 32-byte slot per argument — the value itself for static types,
//!       a byte offset for dynamic ones (bytes, string, T[], dynamic tuples).
//! tail: the actual payload for dynamic arguments, concatenated in order.
//! ```
//!
//! ## Example
//!
//! ```no_run
//! use wallet::abi::{encode_call, Token};
//!
//! // selector = keccak256("transfer(address,uint256)")[..4]
//! let calldata = encode_call(
//!     "transfer(address,uint256)",
//!     &[Token::Address([7u8; 20]), Token::Uint(1000u64.into())],
//! )?;
//! assert_eq!(calldata.len(), 4 + 64);
//! # Ok::<(), wallet::abi::AbiError>(())
//! ```

use crypto_core::hash::keccak256;
pub use primitive_types::U256;

/// Errors produced by ABI encoding or decoding.
#[derive(Debug, thiserror::Error)]
pub enum AbiError {
    /// A type string could not be parsed ("uint256[", "tuple", ...).
    #[error("cannot parse ABI type {input:?}: {reason}")]
    Parse { input: String, reason: String },
    /// The token does not match the declared type.
    #[error("type mismatch: expected {expected}, got {got}")]
    Mismatch { expected: String, got: &'static str },
    /// A numeric value is outside the declared type's range (e.g. 300 for uint8).
    #[error("value out of range for {ty}")]
    OutOfRange { ty: String },
    /// The byte buffer is too short or contains an invalid offset.
    #[error("cannot decode {ty}: {reason}")]
    Decode { ty: String, reason: String },
}

/// A parsed ABI type (Solidity syntax).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbiType {
    /// `uint<M>` with `M` in 8..=256 (step 8). Value encoded as 32-byte big-endian.
    Uint(usize),
    /// `int<M>`. Negative values are stored as their two's-complement 256-bit
    /// form (so encoding is a plain big-endian write).
    Int(usize),
    /// `address` — 20 bytes, left-padded to 32.
    Address,
    /// `bool` — 0 or 1.
    Bool,
    /// `bytes<M>` with `M` in 1..=32 — right-padded to 32.
    FixedBytes(usize),
    /// `bytes` — dynamic: 32-byte length + data padded to 32.
    Bytes,
    /// `string` — UTF-8, encoded like `bytes`.
    String,
    /// `T[]` — dynamic array: 32-byte count + elements (head/tail layout).
    Array(Box<AbiType>),
    /// `T[k]` — fixed-size array: elements with head/tail layout.
    FixedArray(Box<AbiType>, usize),
    /// `(T1,...,Tn)` — tuple with head/tail layout.
    Tuple(Vec<AbiType>),
}

impl AbiType {
    /// Parse a type from Solidity syntax: `uint256`, `bytes32`, `address[]`,
    /// `(uint256,address)[]`, nested combinations.
    pub fn parse(input: &str) -> Result<AbiType, AbiError> {
        let s = input.trim();
        let (t, rest) = parse_one(s)?;
        if !rest.is_empty() {
            return Err(err_parse(s, format!("trailing input {rest:?}")));
        }
        Ok(t)
    }

    /// True if the type is dynamic (needs a head offset when a tuple/array member).
    pub fn is_dynamic(&self) -> bool {
        match self {
            AbiType::Bytes | AbiType::String => true,
            AbiType::Array(_) => true,
            AbiType::FixedArray(t, _) => t.is_dynamic(),
            AbiType::Tuple(ts) => ts.iter().any(|t| t.is_dynamic()),
            _ => false,
        }
    }

    /// The encoded size in bytes, if the type is static.
    pub fn static_size(&self) -> Option<usize> {
        if self.is_dynamic() {
            return None;
        }
        match self {
            AbiType::Uint(_) | AbiType::Int(_) | AbiType::Address | AbiType::Bool => Some(32),
            AbiType::FixedBytes(_) => Some(32),
            AbiType::FixedArray(t, k) => t.static_size().map(|s| s * k),
            AbiType::Tuple(ts) => ts
                .iter()
                .try_fold(0usize, |acc, t| t.static_size().map(|s| acc + s)),
            _ => None,
        }
    }

    /// A human-readable name for error messages.
    pub fn name(&self) -> String {
        match self {
            AbiType::Uint(m) => format!("uint{m}"),
            AbiType::Int(m) => format!("int{m}"),
            AbiType::Address => "address".into(),
            AbiType::Bool => "bool".into(),
            AbiType::FixedBytes(m) => format!("bytes{m}"),
            AbiType::Bytes => "bytes".into(),
            AbiType::String => "string".into(),
            AbiType::Array(t) => format!("{}[]", t.name()),
            AbiType::FixedArray(t, k) => format!("{}[{k}]", t.name()),
            AbiType::Tuple(ts) => {
                let inner: Vec<String> = ts.iter().map(|t| t.name()).collect();
                format!("({})", inner.join(","))
            }
        }
    }
}

/// A value to encode (or a value decoded from calldata/return data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// Unsigned integer (`uint<M>`). Stored as a 256-bit value.
    Uint(U256),
    /// Signed integer (`int<M>`) in two's-complement 256-bit form.
    Int(U256),
    /// 20-byte address.
    Address([u8; 20]),
    Bool(bool),
    /// `bytes<M>`: exactly M bytes.
    FixedBytes(Vec<u8>),
    /// `bytes`: arbitrary length.
    Bytes(Vec<u8>),
    String(String),
    /// `T[]`: dynamic array.
    Array(Vec<Token>),
    /// `T[k]` or tuple members: fixed-size sequence.
    FixedArray(Vec<Token>),
    /// `(T1,...,Tn)`
    Tuple(Vec<Token>),
}

impl Token {
    /// Helper for signed integers: wrap an `i64` into its two's-complement form.
    pub fn int_from_i64(v: i64) -> Token {
        if v >= 0 {
            Token::Int(v.into())
        } else {
            Token::Int(U256::MAX - U256::from((-(v as i128)) as u64) + U256::from(1u64))
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse one type from the front of `s`; returns the type and the remainder.
fn parse_one(s: &str) -> Result<(AbiType, &str), AbiError> {
    let s = s.trim_start();
    if s.is_empty() {
        return Err(err_parse("", "empty type".into()));
    }
    // Tuple: balanced parens, then optional array suffixes.
    if s.starts_with('(') {
        let mut depth = 0usize;
        let mut end = None;
        for (i, c) in s.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let end = end.ok_or_else(|| err_parse(s, "unbalanced parentheses".into()))?;
        let inner = &s[1..end];
        let mut members = Vec::new();
        if !inner.trim().is_empty() {
            let mut rest = inner;
            loop {
                let (t, r) = parse_one(rest)?;
                members.push(t);
                rest = r.trim_start();
                if rest.is_empty() {
                    break;
                }
                if !rest.starts_with(',') {
                    return Err(err_parse(s, format!("expected ',' in tuple, got {rest:?}")));
                }
                rest = &rest[1..];
            }
        }
        return with_suffix(s, AbiType::Tuple(members), &s[end + 1..]);
    }

    // Simple type name up to a non-alphanumeric character.
    let name_end = s
        .find(|c: char| !c.is_ascii_alphanumeric())
        .unwrap_or(s.len());
    let (name, rest) = s.split_at(name_end);

    let base = match name {
        "address" => AbiType::Address,
        "bool" => AbiType::Bool,
        "bytes" => AbiType::Bytes,
        "string" => AbiType::String,
        "uint" => AbiType::Uint(256),
        "int" => AbiType::Int(256),
        _ => {
            if let Some(m) = name.strip_prefix("uint") {
                let m: usize = m
                    .parse()
                    .map_err(|_| err_parse(s, format!("bad integer width in {name:?}")))?;
                if m == 0 || m > 256 || !m.is_multiple_of(8) {
                    return Err(err_parse(
                        s,
                        format!("uint width must be 8..=256 in steps of 8, got {m}"),
                    ));
                }
                AbiType::Uint(m)
            } else if let Some(m) = name.strip_prefix("int") {
                let m: usize = m
                    .parse()
                    .map_err(|_| err_parse(s, format!("bad integer width in {name:?}")))?;
                if m == 0 || m > 256 || !m.is_multiple_of(8) {
                    return Err(err_parse(
                        s,
                        format!("int width must be 8..=256 in steps of 8, got {m}"),
                    ));
                }
                AbiType::Int(m)
            } else if let Some(m) = name.strip_prefix("bytes") {
                let m: usize = m
                    .parse()
                    .map_err(|_| err_parse(s, format!("bad fixed bytes length in {name:?}")))?;
                if m == 0 || m > 32 {
                    return Err(err_parse(s, format!("bytes<M> requires 1..=32, got {m}")));
                }
                AbiType::FixedBytes(m)
            } else {
                return Err(err_parse(s, format!("unknown type {name:?}")));
            }
        }
    };
    with_suffix(s, base, rest)
}

/// Attach `[]` / `[k]` suffixes to a parsed base type.
fn with_suffix<'a>(
    input: &str,
    mut t: AbiType,
    mut rest: &'a str,
) -> Result<(AbiType, &'a str), AbiError> {
    loop {
        rest = rest.trim_start();
        if let Some(r) = rest.strip_prefix('[') {
            let close = r
                .find(']')
                .ok_or_else(|| err_parse(input, "unclosed '['".into()))?;
            let inner = &r[..close];
            t = if inner.is_empty() {
                AbiType::Array(Box::new(t))
            } else {
                let k: usize = inner
                    .parse()
                    .map_err(|_| err_parse(input, format!("bad array size {inner:?}")))?;
                if k == 0 {
                    return Err(err_parse(input, "array size must be >= 1".into()));
                }
                AbiType::FixedArray(Box::new(t), k)
            };
            rest = &r[close + 1..];
        } else {
            return Ok((t, rest));
        }
    }
}

fn err_parse(input: &str, reason: String) -> AbiError {
    AbiError::Parse {
        input: input.into(),
        reason,
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Encode a list of arguments (no selector) per the ABI head/tail layout.
pub fn encode(types: &[AbiType], tokens: &[Token]) -> Result<Vec<u8>, AbiError> {
    if types.len() != tokens.len() {
        return Err(AbiError::Mismatch {
            expected: format!("{} arguments", types.len()),
            got: "different token count",
        });
    }
    let paired: Vec<(&AbiType, &Token)> = types.iter().zip(tokens).collect();
    encode_list(&paired)
}

/// Compute a function selector: `keccak256(signature)[..4]`.
pub fn selector(signature: &str) -> [u8; 4] {
    let h = keccak256(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

/// Encode a full call: 4-byte selector + ABI-encoded arguments.
pub fn encode_call(signature: &str, args: &[Token]) -> Result<Vec<u8>, AbiError> {
    let (name, types) = split_signature(signature)?;
    if name.is_empty() {
        return Err(err_parse(signature, "missing function name".into()));
    }
    let mut out = Vec::with_capacity(4 + args.len() * 32);
    out.extend_from_slice(&selector(signature));
    out.extend_from_slice(&encode(&types, args)?);
    Ok(out)
}

/// Split `"transfer(address,uint256)"` into `("transfer", [Address, Uint256])`.
pub fn split_signature(signature: &str) -> Result<(String, Vec<AbiType>), AbiError> {
    let sig = signature.trim();
    let paren = sig
        .find('(')
        .ok_or_else(|| err_parse(signature, "missing '(' in signature".into()))?;
    let name = sig[..paren].trim().to_string();
    let close = sig
        .rfind(')')
        .ok_or_else(|| err_parse(signature, "missing ')' in signature".into()))?;
    let inner = &sig[paren + 1..close];
    let mut types = Vec::new();
    if !inner.trim().is_empty() {
        let mut rest = inner;
        loop {
            let (t, r) = parse_one(rest)?;
            types.push(t);
            rest = r.trim_start();
            if rest.is_empty() {
                break;
            }
            if !rest.starts_with(',') {
                return Err(err_parse(
                    signature,
                    format!("expected ',' in signature, got {rest:?}"),
                ));
            }
            rest = &rest[1..];
        }
    }
    Ok((name, types))
}

/// Encode a list of typed values as one head/tail payload.
fn encode_list(items: &[(&AbiType, &Token)]) -> Result<Vec<u8>, AbiError> {
    let mut head = Vec::new();
    let mut tail = Vec::new();
    for (t, tok) in items {
        if t.is_dynamic() {
            tail.extend_from_slice(&encode_dynamic(t, tok)?);
            head.extend_from_slice(&[0u8; 32]);
        } else {
            head.extend_from_slice(&encode_static(t, tok)?);
        }
    }
    let head_len = head.len();
    let mut cursor = head_len;
    let mut head_pos = 0usize;
    for (t, tok) in items {
        if t.is_dynamic() {
            let size = encode_dynamic(t, tok)?.len();
            head[head_pos..head_pos + 32].copy_from_slice(&u256_be(cursor.into()));
            head_pos += 32;
            cursor += size;
        } else {
            head_pos += 32;
        }
    }
    let mut out = Vec::with_capacity(head_len + tail.len());
    out.extend_from_slice(&head);
    out.extend_from_slice(&tail);
    Ok(out)
}

/// Encode a static token (32-byte slots; tuples may span several slots).
fn encode_static(t: &AbiType, tok: &Token) -> Result<Vec<u8>, AbiError> {
    let mut out = Vec::new();
    encode_static_into(t, tok, &mut out)?;
    Ok(out)
}

fn encode_static_into(t: &AbiType, tok: &Token, out: &mut Vec<u8>) -> Result<(), AbiError> {
    match (t, tok) {
        (AbiType::Uint(m), Token::Uint(v)) => {
            let max = U256::from(1u8) << (m - 1);
            if *m < 256 && *v >= max {
                return Err(AbiError::OutOfRange { ty: t.name() });
            }
            out.extend_from_slice(&u256_be(*v));
        }
        (AbiType::Uint(m), Token::Int(v)) => {
            let max = U256::from(1u8) << (m - 1);
            if *m < 256 && *v >= max {
                return Err(AbiError::OutOfRange { ty: t.name() });
            }
            out.extend_from_slice(&u256_be(*v));
        }
        (AbiType::Int(m), Token::Int(v)) | (AbiType::Int(m), Token::Uint(v)) => {
            if *m < 256 {
                // Valid raw encodings: [0, 2^(m-1)) for positives and
                // [2^256 - 2^(m-1), 2^256) for two's-complement negatives.
                let pos_max = U256::from(1u8) << (m - 1);
                let neg_min = U256::MAX - pos_max + U256::one();
                if *v >= pos_max && *v < neg_min {
                    return Err(AbiError::OutOfRange { ty: t.name() });
                }
            }
            out.extend_from_slice(&u256_be(*v));
        }
        (AbiType::Address, Token::Address(a)) => {
            let mut w = [0u8; 32];
            w[12..].copy_from_slice(a);
            out.extend_from_slice(&w);
        }
        (AbiType::Bool, Token::Bool(b)) => {
            out.extend_from_slice(&u256_be(if *b { U256::one() } else { U256::zero() }));
        }
        (AbiType::FixedBytes(m), Token::FixedBytes(b)) => {
            if b.len() != *m {
                return Err(AbiError::Mismatch {
                    expected: format!("{} bytes", m),
                    got: "different fixed-bytes length",
                });
            }
            let mut w = [0u8; 32];
            w[..b.len()].copy_from_slice(b);
            out.extend_from_slice(&w);
        }
        (AbiType::FixedArray(inner, k), Token::FixedArray(items)) => {
            if items.len() != *k {
                return Err(AbiError::Mismatch {
                    expected: format!("{} elements", k),
                    got: "different fixed-array length",
                });
            }
            for it in items {
                encode_static_into(inner, it, out)?;
            }
        }
        (AbiType::Tuple(ts), Token::Tuple(items)) => {
            if ts.len() != items.len() {
                return Err(AbiError::Mismatch {
                    expected: format!("{} members", ts.len()),
                    got: "different tuple length",
                });
            }
            let paired: Vec<(&AbiType, &Token)> = ts.iter().zip(items).collect();
            out.extend_from_slice(&encode_list(&paired)?);
        }
        (AbiType::Tuple(ts), Token::FixedArray(items)) => {
            if ts.len() != items.len() {
                return Err(AbiError::Mismatch {
                    expected: format!("{} members", ts.len()),
                    got: "different tuple length",
                });
            }
            let paired: Vec<(&AbiType, &Token)> = ts.iter().zip(items).collect();
            out.extend_from_slice(&encode_list(&paired)?);
        }
        _ => {
            return Err(AbiError::Mismatch {
                expected: t.name(),
                got: token_kind(tok),
            });
        }
    }
    Ok(())
}

/// Encode a dynamic token: length prefix + padded data (`bytes`/`string`) or
/// count + head/tail (`T[]`, and tuples/arrays that contain dynamic members).
fn encode_dynamic(t: &AbiType, tok: &Token) -> Result<Vec<u8>, AbiError> {
    let mut out = Vec::new();
    match (t, tok) {
        (AbiType::Bytes, Token::Bytes(b)) | (AbiType::Bytes, Token::FixedBytes(b)) => {
            out.extend_from_slice(&u256_be(b.len().into()));
            out.extend_from_slice(b);
            while out.len() % 32 != 0 {
                out.push(0);
            }
        }
        (AbiType::String, Token::String(s)) => {
            let b = s.as_bytes();
            out.extend_from_slice(&u256_be(b.len().into()));
            out.extend_from_slice(b);
            while out.len() % 32 != 0 {
                out.push(0);
            }
        }
        (AbiType::Array(inner), Token::Array(items)) => {
            out.extend_from_slice(&u256_be(items.len().into()));
            let paired: Vec<(&AbiType, &Token)> =
                items.iter().map(|it| (inner.as_ref(), it)).collect();
            out.extend_from_slice(&encode_list(&paired)?);
        }
        (AbiType::Array(_), Token::FixedArray(items)) => {
            out.extend_from_slice(&u256_be(items.len().into()));
            let inner = match t {
                AbiType::Array(inner) => inner.as_ref(),
                _ => unreachable!(),
            };
            let paired: Vec<(&AbiType, &Token)> = items.iter().map(|it| (inner, it)).collect();
            out.extend_from_slice(&encode_list(&paired)?);
        }
        (AbiType::FixedArray(inner, k), Token::FixedArray(items)) => {
            if items.len() != *k {
                return Err(AbiError::Mismatch {
                    expected: format!("{} elements", k),
                    got: "different fixed-array length",
                });
            }
            let paired: Vec<(&AbiType, &Token)> =
                items.iter().map(|it| (inner.as_ref(), it)).collect();
            out.extend_from_slice(&encode_list(&paired)?);
        }
        (AbiType::Tuple(ts), Token::Tuple(items))
        | (AbiType::Tuple(ts), Token::FixedArray(items)) => {
            if ts.len() != items.len() {
                return Err(AbiError::Mismatch {
                    expected: format!("{} members", ts.len()),
                    got: "different tuple length",
                });
            }
            let paired: Vec<(&AbiType, &Token)> = ts.iter().zip(items).collect();
            out.extend_from_slice(&encode_list(&paired)?);
        }
        // A dynamic top-level type must match a dynamic token kind.
        _ => {
            return Err(AbiError::Mismatch {
                expected: t.name(),
                got: token_kind(tok),
            });
        }
    }
    Ok(out)
}

fn token_kind(t: &Token) -> &'static str {
    match t {
        Token::Uint(_) => "uint",
        Token::Int(_) => "int",
        Token::Address(_) => "address",
        Token::Bool(_) => "bool",
        Token::FixedBytes(_) => "fixed bytes",
        Token::Bytes(_) => "bytes",
        Token::String(_) => "string",
        Token::Array(_) => "array",
        Token::FixedArray(_) => "fixed array",
        Token::Tuple(_) => "tuple",
    }
}

fn u256_be(v: U256) -> [u8; 32] {
    let mut b = [0u8; 32];
    v.to_big_endian(&mut b);
    b
}

fn u256_from(data: &[u8]) -> U256 {
    U256::from_big_endian(&data[..32])
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Decode a list of typed values from a head/tail payload (no selector).
pub fn decode(types: &[AbiType], data: &[u8]) -> Result<Vec<Token>, AbiError> {
    let mut items = Vec::with_capacity(types.len());
    let mut cursor = 0usize;
    for t in types {
        let tok = decode_from(t, data, cursor, 0)?;
        cursor += if t.is_dynamic() { 32 } else { static_size(t)? };
        items.push(tok);
    }
    Ok(items)
}

/// Encoded size in bytes of a static value (tuples/arrays can span many slots).
fn static_size(t: &AbiType) -> Result<usize, AbiError> {
    match t {
        AbiType::FixedArray(inner, k) => Ok(static_size(inner)? * k),
        AbiType::Tuple(ts) => {
            let mut n = 0;
            for m in ts {
                n += if m.is_dynamic() { 32 } else { static_size(m)? };
            }
            Ok(n)
        }
        _ => Ok(32),
    }
}

/// Decode one value whose head slot is at `slot_abs`. For dynamic values the
/// slot holds an offset relative to `head_abs` (start of the enclosing head).
fn decode_from(
    t: &AbiType,
    data: &[u8],
    slot_abs: usize,
    head_abs: usize,
) -> Result<Token, AbiError> {
    if data.len() < slot_abs + 32 {
        return Err(AbiError::Decode {
            ty: t.name(),
            reason: "data too short".into(),
        });
    }
    if t.is_dynamic() {
        let rel = u256_from(&data[slot_abs..slot_abs + 32]);
        let rel = usize::try_from(rel).map_err(|_| AbiError::Decode {
            ty: t.name(),
            reason: "offset does not fit usize".into(),
        })?;
        decode_dynamic(t, data, head_abs + rel)
    } else {
        decode_static(t, data, slot_abs)
    }
}

fn decode_static(t: &AbiType, data: &[u8], offset: usize) -> Result<Token, AbiError> {
    match t {
        AbiType::Uint(m) => {
            let v = u256_from(&data[offset..offset + 32]);
            if *m < 256 && v >= (U256::from(1u8) << (m - 1)) {
                return Err(AbiError::Decode {
                    ty: t.name(),
                    reason: "value has high bits set".into(),
                });
            }
            Ok(Token::Uint(v))
        }
        AbiType::Int(_) => Ok(Token::Int(u256_from(&data[offset..offset + 32]))),
        AbiType::Address => {
            let mut a = [0u8; 20];
            a.copy_from_slice(&data[offset + 12..offset + 32]);
            Ok(Token::Address(a))
        }
        AbiType::Bool => {
            let v = u256_from(&data[offset..offset + 32]);
            if v == U256::zero() {
                Ok(Token::Bool(false))
            } else if v == U256::one() {
                Ok(Token::Bool(true))
            } else {
                Err(AbiError::Decode {
                    ty: "bool".into(),
                    reason: "value is not 0 or 1".into(),
                })
            }
        }
        AbiType::FixedBytes(m) => Ok(Token::FixedBytes(data[offset..offset + m].to_vec())),
        AbiType::FixedArray(inner, k) => {
            let mut items = Vec::with_capacity(*k);
            let mut pos = offset;
            for _ in 0..*k {
                items.push(decode_static(inner, data, pos)?);
                pos += static_size(inner)?;
            }
            Ok(Token::FixedArray(items))
        }
        AbiType::Tuple(ts) => {
            let mut items = Vec::with_capacity(ts.len());
            let mut pos = offset;
            for m in ts {
                items.push(decode_static(m, data, pos)?);
                pos += static_size(m)?;
            }
            Ok(Token::Tuple(items))
        }
        _ => Err(AbiError::Decode {
            ty: t.name(),
            reason: "unexpected dynamic type in static position".into(),
        }),
    }
}

fn decode_dynamic(t: &AbiType, data: &[u8], pos: usize) -> Result<Token, AbiError> {
    let need = |n: usize| -> Result<(), AbiError> {
        if data.len() < pos + n {
            Err(AbiError::Decode {
                ty: t.name(),
                reason: "dynamic payload out of bounds".into(),
            })
        } else {
            Ok(())
        }
    };
    match t {
        AbiType::Bytes => {
            need(32)?;
            let len = u256_from(&data[pos..pos + 32]);
            let len = usize::try_from(len).map_err(|_| AbiError::Decode {
                ty: "bytes".into(),
                reason: "length does not fit usize".into(),
            })?;
            need(32 + len)?;
            Ok(Token::Bytes(data[pos + 32..pos + 32 + len].to_vec()))
        }
        AbiType::String => {
            need(32)?;
            let len = u256_from(&data[pos..pos + 32]);
            let len = usize::try_from(len).map_err(|_| AbiError::Decode {
                ty: "string".into(),
                reason: "length does not fit usize".into(),
            })?;
            need(32 + len)?;
            let bytes = &data[pos + 32..pos + 32 + len];
            let s = std::str::from_utf8(bytes).map_err(|e| AbiError::Decode {
                ty: "string".into(),
                reason: format!("invalid utf-8: {e}"),
            })?;
            Ok(Token::String(s.to_string()))
        }
        AbiType::Array(inner) => {
            need(32)?;
            let count = u256_from(&data[pos..pos + 32]);
            let count = usize::try_from(count).map_err(|_| AbiError::Decode {
                ty: t.name(),
                reason: "length does not fit usize".into(),
            })?;
            let head_start = pos + 32;
            let step = if inner.is_dynamic() {
                32
            } else {
                static_size(inner)?
            };
            need(32 + count * step)?;
            let mut items = Vec::with_capacity(count);
            for i in 0..count {
                items.push(decode_from(inner, data, head_start + i * step, head_start)?);
            }
            Ok(Token::Array(items))
        }
        // Dynamic tuples: only reachable inside another dynamic context; the
        // offset points at the tuple's own head.
        AbiType::Tuple(ts) => {
            let mut items = Vec::with_capacity(ts.len());
            let mut slot = pos;
            for m in ts {
                items.push(decode_from(m, data, slot, pos)?);
                slot += if m.is_dynamic() { 32 } else { static_size(m)? };
            }
            Ok(Token::Tuple(items))
        }
        _ => Err(AbiError::Decode {
            ty: t.name(),
            reason: "type is not dynamic".into(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn u(v: u64) -> Token {
        Token::Uint(v.into())
    }

    fn roundtrip(sig: &str, toks: Vec<Token>) {
        let (_, types) = split_signature(sig).unwrap();
        let enc = encode(&types, &toks).unwrap();
        let dec = decode(&types, &enc).unwrap();
        assert_eq!(dec, toks, "roundtrip failed for {sig}");
    }

    #[test]
    fn selector_transfer() {
        assert_eq!(
            selector("transfer(address,uint256)"),
            [0xa9, 0x05, 0x9c, 0xbb]
        );
        assert_eq!(selector("balanceOf(address)"), [0x70, 0xa0, 0x82, 0x31]);
        assert_eq!(selector("symbol()"), [0x95, 0xd8, 0x9b, 0x41]);
    }

    #[test]
    fn encode_call_transfer() {
        let calldata = encode_call(
            "transfer(address,uint256)",
            &[
                Token::Address(
                    hx("1234567890abcdef1234567890abcdef12345678")
                        .try_into()
                        .unwrap(),
                ),
                Token::Uint(1000u64.into()),
            ],
        )
        .unwrap();
        let mut want = hx("a9059cbb");
        want.extend_from_slice(&hx(
            "0000000000000000000000001234567890abcdef1234567890abcdef12345678\
             00000000000000000000000000000000000000000000000000000000000003e8",
        ));
        assert_eq!(calldata, want);
    }

    #[test]
    fn static_roundtrip() {
        roundtrip(
            "(uint256,address,bool,bytes32)",
            vec![
                u(42),
                Token::Address([0x11; 20]),
                Token::Bool(true),
                Token::FixedBytes(vec![0xab; 32]),
            ],
        );
    }

    #[test]
    fn dynamic_roundtrip() {
        roundtrip(
            "(string,bytes,uint256[])",
            vec![
                Token::String("hello".into()),
                Token::Bytes(vec![1, 2, 3, 4, 5]),
                Token::Array(vec![u(7), u(8), u(9)]),
            ],
        );
    }

    #[test]
    fn encode_string_known() {
        // (uint256,string) with (1, "abc")
        let enc = encode(
            &[AbiType::Uint(256), AbiType::String],
            &[u(1), Token::String("abc".into())],
        )
        .unwrap();
        let want = hx(
            "0000000000000000000000000000000000000000000000000000000000000001\
             0000000000000000000000000000000000000000000000000000000000000040\
             0000000000000000000000000000000000000000000000000000000000000003\
             6162630000000000000000000000000000000000000000000000000000000000",
        );
        assert_eq!(enc, want);
        assert_eq!(
            decode(&[AbiType::Uint(256), AbiType::String], &want).unwrap(),
            vec![u(1), Token::String("abc".into())]
        );
    }

    #[test]
    fn negative_int() {
        // int256 -1 encodes as all-ones.
        let enc = encode(&[AbiType::Int(256)], &[Token::Int(U256::MAX)]).unwrap();
        assert_eq!(enc, vec![0xff; 32]);
        // int8 -1 is sign-extended: raw word is all-ones, not 0xff.
        let enc8 = encode(&[AbiType::Int(8)], &[Token::Int(U256::MAX)]).unwrap();
        assert_eq!(enc8, vec![0xff; 32]);
        assert!(matches!(
            encode(&[AbiType::Int(8)], &[Token::Int(255u8.into())]),
            Err(AbiError::OutOfRange { .. })
        ));
        assert!(matches!(
            encode(&[AbiType::Uint(8)], &[u(300)]),
            Err(AbiError::OutOfRange { .. })
        ));
        roundtrip(
            "(int8,int256)",
            vec![Token::Int(5u8.into()), Token::Int(U256::MAX)],
        );
    }

    #[test]
    fn nested_arrays() {
        // string[] -> offsets relative to the array head.
        let toks = Token::Array(vec![Token::String("a".into()), Token::String("b".into())]);
        let enc = encode(
            &[AbiType::Array(Box::new(AbiType::String))],
            std::slice::from_ref(&toks),
        )
        .unwrap();
        // head: offset 0x20; tail: count 2, offs 0x40/0x60, then "a", "b"
        let want = hx(
            "0000000000000000000000000000000000000000000000000000000000000020\
             0000000000000000000000000000000000000000000000000000000000000002\
             0000000000000000000000000000000000000000000000000000000000000040\
             0000000000000000000000000000000000000000000000000000000000000080\
             0000000000000000000000000000000000000000000000000000000000000001\
             6100000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000001\
             6200000000000000000000000000000000000000000000000000000000000000",
        );
        assert_eq!(enc, want);
        assert_eq!(
            decode(&[AbiType::Array(Box::new(AbiType::String))], &enc).unwrap(),
            vec![toks]
        );
    }

    #[test]
    fn fixed_array_of_tuples() {
        let ty = parse_one("(uint256,uint256)[2]").unwrap().0;
        // (uint256,uint256)[2] — static element spanning 2 slots each.
        let toks = Token::FixedArray(vec![
            Token::Tuple(vec![u(1), u(2)]),
            Token::Tuple(vec![u(3), u(4)]),
        ]);
        let enc = encode(std::slice::from_ref(&ty), std::slice::from_ref(&toks)).unwrap();
        assert_eq!(enc.len(), 4 * 32);
        assert_eq!(decode(std::slice::from_ref(&ty), &enc).unwrap(), vec![toks]);
        // uint256[2][] — dynamic array of static 2-slot elements.
        let ty2 = parse_one("uint256[2][]").unwrap().0;
        let arr = Token::Array(vec![
            Token::FixedArray(vec![u(5), u(6)]),
            Token::FixedArray(vec![u(7), u(8)]),
        ]);
        let enc2 = encode(std::slice::from_ref(&ty2), std::slice::from_ref(&arr)).unwrap();
        assert_eq!(enc2.len(), 32 + 32 + 4 * 32);
        assert_eq!(
            decode(std::slice::from_ref(&ty2), &enc2).unwrap(),
            vec![arr]
        );
    }

    #[test]
    fn dynamic_tuple() {
        // (uint256,string) as a single tuple value
        let ty = parse_one("(uint256,string)").unwrap().0;
        let toks = Token::Tuple(vec![u(1), Token::String("hi".into())]);
        let enc = encode(std::slice::from_ref(&ty), std::slice::from_ref(&toks)).unwrap();
        assert_eq!(decode(std::slice::from_ref(&ty), &enc).unwrap(), vec![toks]);
    }

    #[test]
    fn parse_errors() {
        assert!(split_signature("transfer").is_err());
        assert!(split_signature("(uint256").is_err());
        assert!(matches!(parse_one("uint7"), Err(AbiError::Parse { .. })));
        assert!(matches!(
            parse_one("uint256[0]"),
            Err(AbiError::Parse { .. })
        ));
    }
}
