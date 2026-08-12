//! A minimal, teaching-grade EVM (Ethereum Virtual Machine) interpreter.
//!
//! Implements the *shape* of the real EVM — a 256-bit stack machine with
//! memory, key-value storage, jumps, message calls and contract deployment —
//! using a deliberate subset of the opcode table. Gas costs are simplified
//! (no EIP-2929 access sets, no EIP-150 63/64 rule) and the CREATE address
//! derivation skips RLP; both simplifications are documented where they
//! occur. What is *not* simplified is the execution model: a contract runs in
//! a frame with its own `pc`, stack, and memory, and [`execute`] drives the
//! top-level call, returning an [`ExecutionResult`] with output bytes and gas
//! usage, exactly like `eth_call`.
//!
//! ## Implemented opcodes
//!
//! - **Halting**: `STOP`, `RETURN`, `REVERT`, `INVALID`, `SELFDESTRUCT`
//! - **Arithmetic** (all modulo 2²⁵⁶): `ADD`, `MUL`, `SUB`, `DIV`, `MOD`,
//!   `EXP`
//! - **Comparison / bitwise**: `LT`, `GT`, `EQ`, `ISZERO`, `AND`, `OR`,
//!   `XOR`, `NOT`, `BYTE`
//! - **Keccak**: `KECCAK256` (memory range)
//! - **Environment**: `ADDRESS`, `BALANCE`, `ORIGIN`, `CALLER`, `CALLVALUE`,
//!   `CALLDATALOAD/SIZE/COPY`, `CODESIZE/COPY`, `GASPRICE`, `EXTCODESIZE`,
//!   `RETURNDATASIZE/COPY`
//! - **Stack/memory/storage**: `POP`, `MLOAD`, `MSTORE`, `MSTORE8`, `SLOAD`,
//!   `SSTORE`, `PC`, `MSIZE`, `GAS`, `JUMP`, `JUMPI`, `JUMPDEST`,
//!   `PUSH0`–`PUSH32`, `DUP1`–`DUP16`, `SWAP1`–`SWAP16`
//! - **Calls / creation**: `CALL`, `CALLCODE`, `DELEGATECALL`, `STATICCALL`,
//!   `CREATE`
//!
//! Not implemented (raise [`ExitReason::InvalidOpcode`]): `SDIV`, `SMOD`,
//! `ADDMOD`, `MULMOD`, `SIGNEXTEND`, `SLT`, `SGT`, `SHL/SHR/SAR`, `LOG*`,
//! `EXTCODEHASH`, `BALANCE`-style precompiles, `CREATE2`.
//!
//! ## Example
//!
//! ```no_run
//! use chain::evm::{execute, Account, Address, CallContext, WorldState};
//! use primitive_types::U256;
//!
//! let mut world = WorldState::default();
//! let alice: Address = [0xaa; 20];
//! world.accounts.insert(alice, Account { balance: U256::from(1000), ..Default::default() });
//!
//! let ctx = CallContext::top(alice);
//! let result = execute(&mut world, &ctx, 100_000);
//! assert_eq!(result.reason.to_string(), "stop");
//! ```

use std::collections::HashMap;
use std::sync::LazyLock;

use crypto_core::hash::keccak256;
use primitive_types::U256;

/// A 20-byte account address (same width as our chain's `script_pubkey`).
pub type Address = [u8; 20];

/// An account: balance, nonce, code, and persistent key-value storage.
#[derive(Debug, Clone, Default)]
pub struct Account {
    pub nonce: u64,
    pub balance: U256,
    /// The runtime bytecode at this address.
    pub code: Vec<u8>,
    /// Storage is a simple `slot -> value` map (32-byte keys and values).
    pub storage: HashMap<U256, U256>,
}

/// The world state: every account an execution can see.
#[derive(Debug, Clone, Default)]
pub struct WorldState {
    pub accounts: HashMap<Address, Account>,
}

impl WorldState {
    fn account(&self, addr: &Address) -> &Account {
        self.accounts.get(addr).unwrap_or(&EMPTY_ACCOUNT)
    }
    fn account_mut(&mut self, addr: Address) -> &mut Account {
        self.accounts.entry(addr).or_default()
    }
}

static EMPTY_ACCOUNT: LazyLock<Account> = LazyLock::new(Account::default);

/// Everything a frame knows about the outside world.
#[derive(Debug, Clone)]
pub struct CallContext {
    /// The address that signed the original transaction.
    pub origin: Address,
    /// The address that invoked this frame (immediate caller).
    pub caller: Address,
    /// The address whose code is running (also where value is credited).
    pub address: Address,
    /// Wei transferred into this frame.
    pub value: U256,
    /// The calldata bytes.
    pub calldata: Vec<u8>,
    /// In static mode all state writes are forbidden.
    pub is_static: bool,
    /// Call depth; the EVM stops recursing past [`MAX_CALL_DEPTH`].
    pub depth: usize,
}

/// EVM call-depth limit (1024 in Ethereum).
pub const MAX_CALL_DEPTH: usize = 1024;

impl CallContext {
    /// A top-level transaction call: caller == origin.
    pub fn top(address: Address) -> CallContext {
        CallContext {
            origin: address,
            caller: address,
            address,
            value: U256::zero(),
            calldata: Vec::new(),
            is_static: false,
            depth: 0,
        }
    }
}

/// Why execution ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitReason {
    /// `STOP`.
    Stop,
    /// `RETURN` — normal termination with output bytes.
    Return,
    /// `REVERT` — state changes are kept, but the call reports failure.
    Revert,
    /// `SELFDESTRUCT` to the given beneficiary.
    SelfDestruct(Address),
    /// Ran out of gas.
    OutOfGas,
    /// An opcode we don't implement (or `INVALID`).
    InvalidOpcode(u8),
    /// Popped from an empty stack.
    StackUnderflow,
    /// Pushed past the 1024-slot stack limit.
    StackOverflow,
    /// `JUMP`/`JUMPI` target is not a `JUMPDEST`.
    InvalidJump,
    /// Exceeded [`MAX_CALL_DEPTH`].
    CallDepthExceeded,
    /// A state write in a static context.
    StaticViolation,
    /// Read past the end of code (pc ran off the bytecode).
    CodeOverrun,
    /// A memory/calldata/returndata read went out of bounds.
    OutOfBounds,
}

impl std::fmt::Display for ExitReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExitReason::Stop => write!(f, "stop"),
            ExitReason::Return => write!(f, "return"),
            ExitReason::Revert => write!(f, "revert"),
            ExitReason::SelfDestruct(a) => write!(f, "selfdestruct({})", hex::encode(a)),
            ExitReason::OutOfGas => write!(f, "out of gas"),
            ExitReason::InvalidOpcode(op) => write!(f, "invalid opcode 0x{op:02x}"),
            ExitReason::StackUnderflow => write!(f, "stack underflow"),
            ExitReason::StackOverflow => write!(f, "stack overflow"),
            ExitReason::InvalidJump => write!(f, "invalid jump destination"),
            ExitReason::CallDepthExceeded => write!(f, "call depth exceeded"),
            ExitReason::StaticViolation => write!(f, "static violation"),
            ExitReason::CodeOverrun => write!(f, "code overrun"),
            ExitReason::OutOfBounds => write!(f, "out of bounds read"),
        }
    }
}

/// The outcome of executing one frame (top-level or nested call).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    pub reason: ExitReason,
    /// Bytes returned by `RETURN`/`REVERT`.
    pub output: Vec<u8>,
    /// Gas consumed by this frame (including nested calls).
    pub gas_used: u64,
    /// Gas left over.
    pub gas_remaining: u64,
}

impl ExecutionResult {
    /// True if the call completed normally (`STOP`/`RETURN`/`SELFDESTRUCT`).
    pub fn is_success(&self) -> bool {
        matches!(
            self.reason,
            ExitReason::Stop | ExitReason::Return | ExitReason::SelfDestruct(_)
        )
    }
}

/// Gas accounting. Costs are simplified but in the right ballpark:
///
/// | op | cost | | op | cost |
/// |---|---|---|---|---|
/// | `ADD/SUB/LT/...` | 3 | | `MUL/DIV/MOD` | 5 |
/// | `EXP` | 10 + 10/byte of exponent | | `KECCAK256` | 30 + 6/word |
/// | `SLOAD` | 800 | | `SSTORE` | 20_000 set / 5_000 reset |
/// | `MLOAD/MSTORE` | 3 + memory | | `CALLDATACOPY/...COPY` | 3/word |
/// | `JUMP/JUMPI/JUMPDEST` | 2 | | `PUSH/DUP/SWAP` | 3 |
/// | `CALL` | 700 + 9_000 if value ≠ 0 | | `CREATE` | 32_000 |
/// | `RETURN/REVERT` | 0 + memory | | `SELFDESTRUCT` | 5_000 |
struct GasMeter {
    limit: u64,
    used: u64,
}

impl GasMeter {
    fn charge(&mut self, amount: u64) -> Result<(), ExitReason> {
        self.used = self.used.checked_add(amount).ok_or(ExitReason::OutOfGas)?;
        if self.used > self.limit {
            return Err(ExitReason::OutOfGas);
        }
        Ok(())
    }

    /// Charge memory expansion to `new_size` bytes, minus what was already
    /// paid for. Cost per 32-byte word is `3·w + w²/512` (the quadratic term
    /// is Ethereum's "memory is not free" rule).
    fn expand_memory(&mut self, memory: &[u8], new_size: usize) -> Result<(), ExitReason> {
        if new_size <= memory.len() {
            return Ok(());
        }
        let words = new_size.div_ceil(32);
        let words_u64 = words as u64;
        let new_cost = 3 * words_u64 + words_u64 * words_u64 / 512;
        let old_words = memory.len().div_ceil(32);
        let old_cost = 3 * old_words as u64 + (old_words as u64) * (old_words as u64) / 512;
        self.charge(new_cost.saturating_sub(old_cost))
    }
}

/// Stack limit, as in Ethereum.
const STACK_LIMIT: usize = 1024;

/// One execution frame.
struct Frame<'a> {
    world: &'a mut WorldState,
    ctx: CallContext,
    /// Snapshot of the running account's code at frame start.
    code: Vec<u8>,
    gas: GasMeter,
    pc: usize,
    stack: Vec<U256>,
    memory: Vec<u8>,
    /// Return data of the most recent child call (`RETURNDATACOPY`).
    return_data: Vec<u8>,
    halted: Option<ExitReason>,
    output: Vec<u8>,
}

impl<'a> Frame<'a> {
    fn new(world: &'a mut WorldState, ctx: CallContext, gas_limit: u64) -> Frame<'a> {
        let code = world.account(&ctx.address).code.clone();
        Frame {
            world,
            ctx,
            code,
            gas: GasMeter {
                limit: gas_limit,
                used: 0,
            },
            pc: 0,
            stack: Vec::new(),
            memory: Vec::new(),
            return_data: Vec::new(),
            halted: None,
            output: Vec::new(),
        }
    }

    fn gas_remaining(&self) -> U256 {
        U256::from(self.gas.limit.saturating_sub(self.gas.used))
    }

    // --- stack helpers -------------------------------------------------

    fn push(&mut self, v: U256) -> Result<(), ExitReason> {
        if self.stack.len() >= STACK_LIMIT {
            return Err(ExitReason::StackOverflow);
        }
        self.stack.push(v);
        Ok(())
    }

    fn pop(&mut self) -> Result<U256, ExitReason> {
        self.stack.pop().ok_or(ExitReason::StackUnderflow)
    }

    fn peek(&self, n: usize) -> Result<U256, ExitReason> {
        let len = self.stack.len();
        if len <= n {
            return Err(ExitReason::StackUnderflow);
        }
        Ok(self.stack[len - 1 - n])
    }

    // --- memory helpers ------------------------------------------------

    fn ensure_memory(&mut self, offset: usize, size: usize) -> Result<(), ExitReason> {
        let new_size = offset.checked_add(size).ok_or(ExitReason::OutOfGas)?;
        self.gas.expand_memory(&self.memory, new_size)?;
        if new_size > self.memory.len() {
            self.memory.resize(new_size, 0);
        }
        Ok(())
    }

    fn mload(&mut self, offset: usize) -> Result<U256, ExitReason> {
        self.ensure_memory(offset, 32)?;
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&self.memory[offset..offset + 32]);
        Ok(U256::from_big_endian(&buf))
    }

    fn mstore(&mut self, offset: usize, value: U256) -> Result<(), ExitReason> {
        self.ensure_memory(offset, 32)?;
        let mut buf = [0u8; 32];
        value.to_big_endian(&mut buf);
        self.memory[offset..offset + 32].copy_from_slice(&buf);
        Ok(())
    }

    fn memory_slice(&mut self, offset: usize, size: usize) -> Result<Vec<u8>, ExitReason> {
        self.ensure_memory(offset, size)?;
        Ok(self.memory[offset..offset + size].to_vec())
    }

    // --- running -------------------------------------------------------

    /// Run until halt or error. Returns the frame's exit reason.
    fn run(&mut self) -> ExitReason {
        loop {
            // Halting checks first: pc past code, or a previous halt signal.
            if self.halted.is_some() {
                return self.halted.take().unwrap();
            }
            if self.pc >= self.code.len() {
                // Calling an account with no code is a no-op success.
                return if self.code.is_empty() {
                    ExitReason::Stop
                } else {
                    ExitReason::CodeOverrun
                };
            }
            let op = self.code[self.pc];
            self.pc += 1;
            if let Err(reason) = self.step(op) {
                return reason;
            }
        }
    }

    /// Execute one opcode. On success `pc` has already advanced past the
    /// opcode (and its immediate data for `PUSH*`).
    fn step(&mut self, op: u8) -> Result<(), ExitReason> {
        // Base cost for the common arithmetic/logic ops.
        let simple = match op {
            0x01 | 0x03 | 0x10 | 0x11 | 0x14 | 0x15 | 0x16 | 0x17 | 0x18 | 0x19 | 0x1a => 3,
            0x02 | 0x04 | 0x06 => 5,
            _ => 0,
        };
        if simple > 0 {
            self.gas.charge(simple)?;
        }

        match op {
            0x00 => {
                self.halted = Some(ExitReason::Stop);
            }
            // --- arithmetic -------------------------------------------
            0x01 => {
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(a.overflowing_add(b).0)?;
            }
            0x02 => {
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(a.overflowing_mul(b).0)?;
            }
            0x03 => {
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(a.overflowing_sub(b).0)?;
            }
            0x04 => {
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(if b.is_zero() { U256::zero() } else { a / b })?;
            }
            0x06 => {
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(if b.is_zero() { U256::zero() } else { a % b })?;
            }
            0x0a => {
                let exp = self.pop()?;
                let base = self.pop()?;
                // EXP: 10 gas + 10 per byte of the exponent.
                let exp_bytes = exp.bits().div_ceil(8) as u64;
                self.gas.charge(10 + 10 * exp_bytes)?;
                self.push(exp_u256(base, exp))?;
            }
            // --- comparison / bitwise ---------------------------------
            0x10 => {
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(if a < b { U256::one() } else { U256::zero() })?;
            }
            0x11 => {
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(if a > b { U256::one() } else { U256::zero() })?;
            }
            0x14 => {
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(if a == b { U256::one() } else { U256::zero() })?;
            }
            0x15 => {
                let a = self.pop()?;
                self.push(if a.is_zero() {
                    U256::one()
                } else {
                    U256::zero()
                })?;
            }
            0x16 => {
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(a & b)?;
            }
            0x17 => {
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(a | b)?;
            }
            0x18 => {
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(a ^ b)?;
            }
            0x19 => {
                let a = self.pop()?;
                self.push(!a)?;
            }
            0x1a => {
                // BYTE(i, x): byte i of x (0 = most significant) or 0 if i ≥ 32.
                let i = self.pop()?;
                let x = self.pop()?;
                let i = i.low_u64();
                if i >= 32 {
                    self.push(U256::zero())?;
                } else {
                    // `U256::byte` indexes from the least significant byte,
                    // so the i-th byte from the most significant end is 31-i.
                    self.push(U256::from(x.byte(31 - i as usize)))?;
                }
            }
            // --- keccak -----------------------------------------------
            0x20 => {
                // KECCAK256: pop offset, pop size → hash of memory range.
                let offset = self.pop()?;
                let size = self.pop()?;
                let size = usize::try_from(size).map_err(|_| ExitReason::OutOfGas)?;
                let offset = usize::try_from(offset).map_err(|_| ExitReason::OutOfGas)?;
                self.gas.charge(30 + 6 * size.div_ceil(32) as u64)?;
                let data = self.memory_slice(offset, size)?;
                let hash = keccak256(&data);
                self.push(U256::from_big_endian(&hash))?;
            }
            // --- environment ------------------------------------------
            0x30 => self.push(U256::from_big_endian(&self.ctx.address))?,
            0x31 => {
                let addr = self.pop()?;
                let balance = self.world.account(&addr_to_bytes(addr)).balance;
                self.push(balance)?;
            }
            0x32 => self.push(U256::from_big_endian(&self.ctx.origin))?,
            0x33 => self.push(U256::from_big_endian(&self.ctx.caller))?,
            0x34 => self.push(self.ctx.value)?,
            0x35 => {
                // CALLDATALOAD(i): calldata[i..i+32] zero-padded.
                let i = self.pop()?;
                let i = usize::try_from(i).map_err(|_| ExitReason::OutOfGas)?;
                let mut buf = [0u8; 32];
                let data = &self.ctx.calldata;
                if i < data.len() {
                    let take = (data.len() - i).min(32);
                    buf[..take].copy_from_slice(&data[i..i + take]);
                }
                self.push(U256::from_big_endian(&buf))?;
            }
            0x36 => self.push(U256::from(self.ctx.calldata.len()))?,
            0x37 => {
                // CALLDATACOPY(dst, src, len): pop dst, src, len; 3 gas/word.
                let dst = self.pop()?;
                let src = self.pop()?;
                let len = self.pop()?;
                let (dst, src, len) = usize_triple(dst, src, len)?;
                self.gas.charge(3 * len.div_ceil(32) as u64)?;
                let data = if src >= self.ctx.calldata.len() {
                    vec![0u8; len]
                } else {
                    let take = (self.ctx.calldata.len() - src).min(len);
                    let mut d = vec![0u8; len];
                    d[..take].copy_from_slice(&self.ctx.calldata[src..src + take]);
                    d
                };
                self.ensure_memory(dst, len)?;
                self.memory[dst..dst + len].copy_from_slice(&data);
            }
            0x38 => self.push(U256::from(self.code.len()))?,
            0x39 => {
                // CODECOPY(dst, src, len): pop dst, src, len.
                let dst = self.pop()?;
                let src = self.pop()?;
                let len = self.pop()?;
                let (dst, src, len) = usize_triple(dst, src, len)?;
                self.gas.charge(3 * len.div_ceil(32) as u64)?;
                let data = if src >= self.code.len() {
                    vec![0u8; len]
                } else {
                    let take = (self.code.len() - src).min(len);
                    let mut d = vec![0u8; len];
                    d[..take].copy_from_slice(&self.code[src..src + take]);
                    d
                };
                self.ensure_memory(dst, len)?;
                self.memory[dst..dst + len].copy_from_slice(&data);
            }
            0x3a => self.push(U256::zero())?, // GASPRICE — we don't model fees
            0x3b => {
                let addr = self.pop()?;
                let code = self.world.account(&addr_to_bytes(addr)).code.len();
                self.push(U256::from(code))?;
            }
            0x3d => self.push(U256::from(self.return_data.len()))?,
            0x3e => {
                // RETURNDATACOPY(dst, src, len): pop dst, src, len.
                let dst = self.pop()?;
                let src = self.pop()?;
                let len = self.pop()?;
                let (dst, src, len) = usize_triple(dst, src, len)?;
                self.gas.charge(3 * len.div_ceil(32) as u64)?;
                if src + len > self.return_data.len() {
                    return Err(ExitReason::OutOfBounds);
                }
                let data = self.return_data[src..src + len].to_vec();
                self.ensure_memory(dst, len)?;
                self.memory[dst..dst + len].copy_from_slice(&data);
            }
            // --- stack -------------------------------------------------
            0x50 => {
                self.pop()?;
            }
            0x51 => {
                let offset = self.pop()?;
                let offset = usize::try_from(offset).map_err(|_| ExitReason::OutOfGas)?;
                self.gas.charge(3)?;
                let v = self.mload(offset)?;
                self.push(v)?;
            }
            0x52 => {
                // MSTORE: pop offset first, then value.
                let offset = self.pop()?;
                let value = self.pop()?;
                let offset = usize::try_from(offset).map_err(|_| ExitReason::OutOfGas)?;
                self.gas.charge(3)?;
                self.mstore(offset, value)?;
            }
            0x53 => {
                // MSTORE8: pop offset first, then value (stores low byte).
                let offset = self.pop()?;
                let value = self.pop()?;
                let offset = usize::try_from(offset).map_err(|_| ExitReason::OutOfGas)?;
                self.memory[offset] = value.byte(0);
            }
            0x54 => {
                self.gas.charge(800)?;
                let key = self.pop()?;
                let value = self
                    .world
                    .account(&self.ctx.address)
                    .storage
                    .get(&key)
                    .copied()
                    .unwrap_or_default();
                self.push(value)?;
            }
            0x55 => {
                if self.ctx.is_static {
                    return Err(ExitReason::StaticViolation);
                }
                // SSTORE: pop key first, then value.
                let key = self.pop()?;
                let value = self.pop()?;
                let slot = self.world.account_mut(self.ctx.address).storage.entry(key);
                let is_new = match slot {
                    std::collections::hash_map::Entry::Vacant(_) => true,
                    std::collections::hash_map::Entry::Occupied(e) => e.get().is_zero(),
                };
                // 20k to set a zero slot, 5k to overwrite a nonzero one.
                self.gas.charge(if is_new { 20_000 } else { 5_000 })?;
                self.world
                    .account_mut(self.ctx.address)
                    .storage
                    .insert(key, value);
            }
            0x56 => {
                self.gas.charge(2)?;
                let dest = self.pop()?;
                self.jump_to(dest)?;
            }
            0x57 => {
                self.gas.charge(2)?;
                // JUMPI pops destination first (top), then the condition.
                let dest = self.pop()?;
                let cond = self.pop()?;
                if !cond.is_zero() {
                    self.jump_to(dest)?;
                }
            }
            0x58 => self.push(U256::from(self.pc - 1))?,
            0x59 => self.push(U256::from(self.memory.len()))?,
            0x5a => self.push(self.gas_remaining())?,
            0x5b => {
                self.gas.charge(2)?; // JUMPDEST
            }
            // --- pushes ------------------------------------------------
            0x5f => {
                self.gas.charge(2)?; // PUSH0
                self.push(U256::zero())?;
            }
            0x60..=0x7f => {
                self.gas.charge(3)?;
                let n = (op - 0x5f) as usize; // bytes to push
                if self.pc + n > self.code.len() {
                    return Err(ExitReason::CodeOverrun);
                }
                let mut buf = [0u8; 32];
                buf[32 - n..].copy_from_slice(&self.code[self.pc..self.pc + n]);
                self.pc += n;
                self.push(U256::from_big_endian(&buf))?;
            }
            // --- dup / swap -------------------------------------------
            0x80..=0x8f => {
                self.gas.charge(3)?;
                let n = (op - 0x7f) as usize; // DUP1..DUP16
                let v = self.peek(n - 1)?;
                self.push(v)?;
            }
            0x90..=0x9f => {
                self.gas.charge(3)?;
                let n = (op - 0x8f) as usize; // SWAP1..SWAP16
                let len = self.stack.len();
                if len <= n {
                    return Err(ExitReason::StackUnderflow);
                }
                self.stack.swap(len - 1, len - 1 - n);
            }
            // --- calls / creation -------------------------------------
            0xf0 => self.op_create()?,
            0xf1 => self.op_call(CallKind::Call)?,
            0xf2 => self.op_call(CallKind::CallCode)?,
            0xf3 => {
                // RETURN: pop offset first, then size.
                let offset = self.pop()?;
                let size = self.pop()?;
                let (size, offset) = usize_pair(size, offset)?;
                self.output = self.memory_slice(offset, size)?;
                self.halted = Some(ExitReason::Return);
            }
            0xf4 => self.op_call(CallKind::DelegateCall)?,
            0xfa => self.op_call(CallKind::StaticCall)?,
            0xfd => {
                // REVERT: like RETURN, but reports failure.
                let offset = self.pop()?;
                let size = self.pop()?;
                let (size, offset) = usize_pair(size, offset)?;
                self.output = self.memory_slice(offset, size)?;
                self.halted = Some(ExitReason::Revert);
            }
            0xfe => return Err(ExitReason::InvalidOpcode(0xfe)), // INVALID
            0xff => {
                // SELFDESTRUCT(beneficiary)
                if self.ctx.is_static {
                    return Err(ExitReason::StaticViolation);
                }
                self.gas.charge(5_000)?;
                let beneficiary = self.pop()?;
                let beneficiary = addr_to_bytes(beneficiary);
                let balance = self.world.account(&self.ctx.address).balance;
                let to = self.world.account_mut(beneficiary);
                to.balance = to.balance.overflowing_add(balance).0;
                self.world.accounts.remove(&self.ctx.address);
                self.halted = Some(ExitReason::SelfDestruct(beneficiary));
            }
            _ => return Err(ExitReason::InvalidOpcode(op)),
        }
        Ok(())
    }

    fn jump_to(&mut self, dest: U256) -> Result<(), ExitReason> {
        let dest = usize::try_from(dest).map_err(|_| ExitReason::InvalidJump)?;
        if dest >= self.code.len() || self.code[dest] != 0x5b {
            return Err(ExitReason::InvalidJump);
        }
        self.pc = dest;
        Ok(())
    }

    /// The `CREATE` opcode: deploy a contract from memory.
    ///
    /// Simplified address derivation: `keccak256(sender ‖ nonce_be)` instead
    /// of Ethereum's `keccak(rlp([sender, nonce]))`.
    fn op_create(&mut self) -> Result<(), ExitReason> {
        if self.ctx.is_static {
            return Err(ExitReason::StaticViolation);
        }
        self.gas.charge(32_000)?;
        if self.ctx.depth >= MAX_CALL_DEPTH {
            return Err(ExitReason::CallDepthExceeded);
        }
        // CREATE: pop value, pop offset, pop size.
        let value = self.pop()?;
        let offset = self.pop()?;
        let size = self.pop()?;
        let (size, offset) = usize_pair(size, offset)?;

        let sender = self.ctx.address;
        let nonce = self.world.account(&sender).nonce;
        let sender_balance = self.world.account(&sender).balance;
        if value > sender_balance {
            self.push(U256::zero())?; // insufficient funds
            return Ok(());
        }

        let init_code = self.memory_slice(offset, size)?;
        let mut nonce_bytes = [0u8; 8];
        nonce_bytes.copy_from_slice(&nonce.to_be_bytes());
        let mut preimage = Vec::with_capacity(28);
        preimage.extend_from_slice(&sender);
        preimage.extend_from_slice(&nonce_bytes);
        let new_address: Address = keccak256(&preimage)[..20].try_into().expect("20 bytes");

        // Snapshot *before* any state change: a failed creation rolls
        // everything back (sender nonce, the new account, value transfer).
        let snapshot = self.world.clone();
        // Nonce is incremented whether or not creation succeeds.
        self.world.account_mut(sender).nonce = nonce + 1;
        // The new account starts out running the init code, which returns the
        // runtime bytecode we store as its final code — real deployment.
        self.world.account_mut(new_address).code = init_code;

        // Run the init code as a message call to the new address.
        let child_ctx = CallContext {
            origin: self.ctx.origin,
            caller: sender,
            address: new_address,
            value,
            calldata: Vec::new(),
            is_static: false,
            depth: self.ctx.depth + 1,
        };
        let child_gas = self.gas.limit.saturating_sub(self.gas.used);
        let (reason, gas_used, output) = {
            let mut frame = Frame::new(self.world, child_ctx, child_gas);
            let reason = frame.run();
            let gas_used = frame.gas.used;
            let output = frame.output;
            (reason, gas_used, output)
        };
        self.gas.used = self.gas.used.saturating_add(gas_used);
        self.return_data = output.clone();

        match reason {
            ExitReason::Stop | ExitReason::Return => {
                self.world.account_mut(new_address).code = output;
                self.world.account_mut(new_address).nonce = 1;
                if !value.is_zero() {
                    let sender = self.world.account_mut(sender);
                    sender.balance = sender.balance.overflowing_sub(value).0;
                    let new = self.world.account_mut(new_address);
                    new.balance = new.balance.overflowing_add(value).0;
                }
                self.push(U256::from_big_endian(&new_address))?;
            }
            _ => {
                *self.world = snapshot; // creation failed — roll back
                self.push(U256::zero())?;
            }
        }
        Ok(())
    }

    /// The `CALL`/`CALLCODE`/`DELEGATECALL`/`STATICCALL` opcodes.
    ///
    /// Simplified gas: the child gets `min(requested, remaining)` and the
    /// parent pays exactly what the child used (no EIP-150 63/64 rule).
    fn op_call(&mut self, kind: CallKind) -> Result<(), ExitReason> {
        let carries_value = matches!(kind, CallKind::Call | CallKind::CallCode);
        self.gas.charge(700)?;
        if self.ctx.depth >= MAX_CALL_DEPTH {
            return Err(ExitReason::CallDepthExceeded);
        }
        let gas_requested = self.pop()?;
        let to = self.pop()?;
        let value = if carries_value {
            self.pop()?
        } else {
            U256::zero()
        };
        // Value-carrying calls pay a 9_000 surcharge (the "new account / value"
        // cost, simplified).
        if carries_value && !value.is_zero() {
            self.gas.charge(9_000)?;
        }
        let args_offset = self.pop()?;
        let args_size = self.pop()?;
        let ret_offset = self.pop()?;
        let ret_size = self.pop()?;
        let (args_offset, args_size) = usize_pair(args_offset, args_size)?;
        let (ret_offset, ret_size) = usize_pair(ret_offset, ret_size)?;

        let to_addr = addr_to_bytes(to);
        let calldata = self.memory_slice(args_offset, args_size)?;

        // A CALL that carries value is static-violating.
        if matches!(kind, CallKind::Call | CallKind::CallCode)
            && self.ctx.is_static
            && !value.is_zero()
        {
            self.push(U256::zero())?;
            return Ok(());
        }

        // Sufficient funds for the value transfer (DELEGATECALL/STATICCALL
        // carry no value).
        if matches!(kind, CallKind::Call | CallKind::CallCode)
            && value > self.world.account(&self.ctx.address).balance
        {
            self.push(U256::zero())?;
            return Ok(());
        }

        let (child_addr, child_caller, child_value, child_static) = match kind {
            CallKind::Call => (to_addr, self.ctx.address, value, self.ctx.is_static),
            // CALLCODE: run `to`'s code in *our* account context.
            CallKind::CallCode => (
                self.ctx.address,
                self.ctx.address,
                value,
                self.ctx.is_static,
            ),
            // DELEGATECALL: run `to`'s code, keep caller/value of the parent.
            CallKind::DelegateCall => (
                self.ctx.address,
                self.ctx.caller,
                self.ctx.value,
                self.ctx.is_static,
            ),
            CallKind::StaticCall => (to_addr, self.ctx.address, U256::zero(), true),
        };

        let child_ctx = CallContext {
            origin: self.ctx.origin,
            caller: child_caller,
            address: child_addr,
            value: child_value,
            calldata,
            is_static: child_static,
            depth: self.ctx.depth + 1,
        };

        let child_limit = gas_requested
            .min(U256::from(self.gas_remaining().low_u64()))
            .low_u64();
        // Snapshot so a failed call (revert, out-of-gas, ...) rolls the world
        // back: the EVM guarantees failed calls leave no state behind.
        let snapshot = self.world.clone();
        let (reason, gas_used, output) = {
            let mut frame = Frame::new(self.world, child_ctx, child_limit);
            let reason = frame.run();
            let gas_used = frame.gas.used;
            let output = frame.output;
            (reason, gas_used, output)
        };
        self.gas.used = self.gas.used.saturating_add(gas_used);
        self.return_data = output.clone();

        if matches!(
            reason,
            ExitReason::Stop | ExitReason::Return | ExitReason::SelfDestruct(_)
        ) {
            // Transfer value on CALL (CALLCODE/DELEGATECALL/STATICCALL don't).
            if matches!(kind, CallKind::Call) && !value.is_zero() {
                let sender = self.world.account_mut(self.ctx.address);
                sender.balance = sender.balance.overflowing_sub(value).0;
                let to_acct = self.world.account_mut(to_addr);
                to_acct.balance = to_acct.balance.overflowing_add(value).0;
            }
            // Copy return data into our memory.
            let copy = output.len().min(ret_size);
            if copy > 0 {
                self.ensure_memory(ret_offset, copy)?;
                self.memory[ret_offset..ret_offset + copy].copy_from_slice(&output[..copy]);
            }
            self.push(U256::one())?;
        } else {
            *self.world = snapshot; // call failed — roll back
            self.push(U256::zero())?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallKind {
    Call,
    CallCode,
    DelegateCall,
    StaticCall,
}

fn addr_to_bytes(v: U256) -> Address {
    let mut buf = [0u8; 32];
    v.to_big_endian(&mut buf);
    buf[12..].try_into().expect("20 bytes")
}

/// Exponentiation modulo 2²⁵⁶ (EVM arithmetic wraps).
fn exp_u256(base: U256, exp: U256) -> U256 {
    let mut result = U256::one();
    let mut base = base;
    let mut exp = exp;
    while !exp.is_zero() {
        if (exp & U256::one()) == U256::one() {
            result = result.overflowing_mul(base).0;
        }
        base = base.overflowing_mul(base).0;
        exp >>= 1;
    }
    result
}

fn usize_pair(a: U256, b: U256) -> Result<(usize, usize), ExitReason> {
    let a = usize::try_from(a).map_err(|_| ExitReason::OutOfGas)?;
    let b = usize::try_from(b).map_err(|_| ExitReason::OutOfGas)?;
    Ok((a, b))
}

fn usize_triple(a: U256, b: U256, c: U256) -> Result<(usize, usize, usize), ExitReason> {
    Ok((
        usize::try_from(a).map_err(|_| ExitReason::OutOfGas)?,
        usize::try_from(b).map_err(|_| ExitReason::OutOfGas)?,
        usize::try_from(c).map_err(|_| ExitReason::OutOfGas)?,
    ))
}

/// Execute a top-level call against `world` with `gas_limit` gas.
///
/// Mirrors `eth_call`: the world state is mutated by the execution (including
/// nested calls), and the returned [`ExecutionResult`] tells you whether the
/// call succeeded and what it returned.
pub fn execute(world: &mut WorldState, ctx: &CallContext, gas_limit: u64) -> ExecutionResult {
    let mut frame = Frame::new(world, ctx.clone(), gas_limit);
    let reason = frame.run();
    ExecutionResult {
        reason,
        output: frame.output,
        gas_used: frame.gas.used,
        gas_remaining: frame.gas.limit.saturating_sub(frame.gas.used),
    }
}

/// A convenience error wrapper for tests (kept separate from `ExitReason`
/// because callers usually want the structured `ExecutionResult` instead).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EvmError {
    #[error("execution halted: {0}")]
    Halted(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble bytecode from a hex string, e.g. `6001600201` = PUSH1 1 PUSH1 2 ADD.
    fn code(hex_str: &str) -> Vec<u8> {
        hex::decode(hex_str).unwrap()
    }

    fn run_code(
        world: &mut WorldState,
        address: Address,
        bytecode: &[u8],
        gas: u64,
    ) -> ExecutionResult {
        world.accounts.insert(
            address,
            Account {
                code: bytecode.to_vec(),
                ..Default::default()
            },
        );
        let ctx = CallContext::top(address);
        execute(world, &ctx, gas)
    }

    #[test]
    fn arithmetic_and_return() {
        let mut world = WorldState::default();
        // PUSH1 2, PUSH1 3, ADD, PUSH0, MSTORE, PUSH1 32, PUSH1 0, RETURN
        let result = run_code(
            &mut world,
            [0x11; 20],
            &code("600260030160005260206000f3"),
            100_000,
        );
        assert_eq!(result.reason, ExitReason::Return);
        assert!(result.is_success());
        assert_eq!(result.output.len(), 32);
        assert_eq!(U256::from_big_endian(&result.output), U256::from(5));
        assert!(result.gas_used < 100_000);
    }

    #[test]
    fn subtraction_wraps_mod_2_256() {
        let mut world = WorldState::default();
        // PUSH1 0, PUSH1 1, SUB, PUSH0, MSTORE, PUSH1 32, PUSH1 0, RETURN
        //   → top(1) - second(0) = 0 - 1 = 2^256 - 1
        let result = run_code(
            &mut world,
            [0x13; 20],
            &code("600060010360005260206000f3"),
            100_000,
        );
        assert!(result.is_success());
        assert_eq!(U256::from_big_endian(&result.output), U256::max_value());
    }

    #[test]
    fn storage_counter_increments_across_calls() {
        let mut world = WorldState::default();
        let counter: Address = [0x42; 20];
        // Runtime: CALLVALUE, PUSH1 0, SLOAD, ADD, PUSH1 0, SSTORE,
        //          PUSH1 0, SLOAD, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
        let rt = code("346000540160005560005460005260206000f3");
        world.accounts.insert(
            counter,
            Account {
                code: rt,
                ..Default::default()
            },
        );

        let ctx = CallContext {
            origin: counter,
            caller: counter,
            address: counter,
            value: U256::from(7),
            calldata: Vec::new(),
            is_static: false,
            depth: 0,
        };
        let r1 = execute(&mut world, &ctx, 100_000);
        assert!(r1.is_success());
        assert_eq!(U256::from_big_endian(&r1.output), U256::from(7));

        let ctx = CallContext {
            value: U256::from(5),
            ..ctx.clone()
        };
        let r2 = execute(&mut world, &ctx, 100_000);
        assert!(r2.is_success());
        assert_eq!(U256::from_big_endian(&r2.output), U256::from(12));

        // Storage persisted: slot 0 == 12.
        assert_eq!(
            world.accounts[&counter].storage[&U256::zero()],
            U256::from(12)
        );
    }

    #[test]
    fn jump_loop_sums_1_to_10() {
        // A hand-assembled loop that sums 1..=10 (answer: 55).
        //   sum = 0; i = 1
        //   LOOP: if i >= 11 goto EXIT; sum += i; i += 1; goto LOOP
        //   EXIT: return sum
        // Stack discipline (JUMPI pops destination first, then condition):
        //   compute cond, push dest on top → [.., cond, dest]
        // Layout:
        //   0x00 PUSH0 (sum=0)  0x01 PUSH1 1 (i)
        //   0x03 JUMPDEST (LOOP)
        //   0x04 PUSH1 11  0x06 DUP2 (i)  0x07 GT (11>i)  0x08 ISZERO (i>=11)
        //   0x09 PUSH1 0x16 (EXIT dest)  0x0b JUMPI
        //   0x0c DUP1 (i)  0x0d SWAP2  0x0e ADD  0x0f SWAP1
        //   0x10 PUSH1 1  0x12 ADD  0x13 PUSH1 0x03 (LOOP)  0x15 JUMP
        //   0x16 JUMPDEST (EXIT)  0x17 POP  0x18 PUSH0 MSTORE
        //   0x1b PUSH1 32  0x1d PUSH1 0  0x1f RETURN
        let bytecode = code("5f60015b600b811115601657809101906001016003565b5060005260206000f3");
        let mut world = WorldState::default();
        let result = run_code(&mut world, [0x21; 20], &bytecode, 100_000);
        assert!(result.is_success(), "loop failed: {}", result.reason);
        assert_eq!(U256::from_big_endian(&result.output), U256::from(55));
    }

    #[test]
    fn call_returns_child_output() {
        let mut world = WorldState::default();
        // Child: returns 42. PUSH1 42, PUSH0, MSTORE, PUSH1 32, PUSH1 0, RETURN
        let child_code = code("602a60005260206000f3");
        // PUSH1 0x77 right-aligns into the 20-byte address 0x…0077, so the
        // child account must live at that address.
        let child: Address = addr_to_bytes(U256::from(0x77));
        world.accounts.insert(
            child,
            Account {
                code: child_code,
                ..Default::default()
            },
        );

        // Parent: CALL(0x77, value=0, args=[], ret=[0, 32]), POP the success
        // flag, then RETURN mem[0..32] — which holds the child's 42.
        //   PUSH1 32 (ret_size), PUSH1 0 (ret_offset), PUSH1 0 (args_size),
        //   PUSH1 0 (args_offset), PUSH1 0 (value), PUSH1 0x77 (to),
        //   PUSH2 0xffff (gas), CALL, POP, PUSH1 32, PUSH1 0, RETURN
        let parent_code = code("60206000600060006000607761fffff15060206000f3");
        let parent: Address = [0x66; 20];
        world.accounts.insert(
            parent,
            Account {
                code: parent_code,
                ..Default::default()
            },
        );

        let ctx = CallContext::top(parent);
        let result = execute(&mut world, &ctx, 200_000);
        assert!(result.is_success(), "parent failed: {}", result.reason);
        assert_eq!(U256::from_big_endian(&result.output), U256::from(42));
    }

    #[test]
    fn failed_call_rolls_back_child_writes() {
        let mut world = WorldState::default();
        // Child: writes slot 0 = 1, then REVERTs.
        //   PUSH1 1, PUSH1 0, SSTORE, PUSH0, PUSH0, REVERT
        let child_code = code("600160005560006000fd");
        let child: Address = addr_to_bytes(U256::from(0x77));
        world.accounts.insert(
            child,
            Account {
                code: child_code,
                ..Default::default()
            },
        );

        // Parent: CALL(0x77), then STOP.
        //   PUSH1 0 (ret_size), PUSH1 0 (ret_offset), PUSH1 0 (args_size),
        //   PUSH1 0 (args_offset), PUSH1 0 (value), PUSH1 0x77 (to),
        //   PUSH2 0xffff (gas), CALL, POP, STOP
        let parent_code = code("60006000600060006000607761fffff15000");
        let parent: Address = [0x66; 20];
        world.accounts.insert(
            parent,
            Account {
                code: parent_code,
                ..Default::default()
            },
        );

        let result = execute(&mut world, &CallContext::top(parent), 200_000);
        assert!(result.is_success(), "parent failed: {}", result.reason);
        // The child's SSTORE must be rolled back after its REVERT.
        assert!(world.accounts[&child].storage.is_empty());
    }

    #[test]
    fn static_call_cannot_write() {
        let mut world = WorldState::default();
        // Code: PUSH1 1, PUSH1 0, SSTORE  (writes slot 0)
        let bytecode = code("6001600055");
        world.accounts.insert(
            [0x31; 20],
            Account {
                code: bytecode,
                ..Default::default()
            },
        );
        let ctx = CallContext {
            is_static: true,
            ..CallContext::top([0x31; 20])
        };
        let result = execute(&mut world, &ctx, 100_000);
        assert_eq!(result.reason, ExitReason::StaticViolation);
        // Storage untouched.
        assert!(world.accounts[&[0x31; 20]].storage.is_empty());
    }

    #[test]
    fn create_deploys_runtime_code() {
        let mut world = WorldState::default();
        let deployer: Address = [0xaa; 20];
        world.accounts.insert(
            deployer,
            Account {
                balance: U256::from(1_000_000),
                ..Default::default()
            },
        );

        // Runtime code the new contract will run: PUSH1 9, PUSH1 0, SSTORE
        //   = 6009600055  (5 bytes)
        // Init code: MSTORE the runtime word at memory 0 (so its last 5
        // bytes land on mem[27..32]), then RETURN mem[27..32].
        //   PUSH5 0x6009600055, PUSH0, MSTORE, PUSH1 5, PUSH1 27, RETURN
        let init_code = code("6460096000556000526005601bf3");
        let init_len = init_code.len();

        // Creator code: CODECOPY(init → mem[0..len]), then CREATE(value=0,
        // offset=0, size=len), then RETURN the created address.
        // The init code is appended last, so CODECOPY's source is the fixed
        // 22 bytes of creator code that precede it.
        //   PUSH1 len, PUSH1 0x11 (src), PUSH0 (dst), CODECOPY
        //   PUSH1 len (size), PUSH0 (offset), PUSH0 (value), CREATE
        //   PUSH0, MSTORE, PUSH1 32, PUSH1 0, RETURN
        let init_offset: usize = 22; // 7 (codecopy) + 7 (create) + 8 (return)
        let mut creator = Vec::new();
        creator.extend_from_slice(&code(&format!(
            "60{:02x}60{:02x}600039",
            init_len, init_offset
        )));
        creator.extend_from_slice(&code(&format!("60{:02x}60006000f0", init_len)));
        creator.extend_from_slice(&code("60005260206000f3"));
        creator.extend_from_slice(&init_code);
        world.accounts.insert(
            deployer,
            Account {
                code: creator,
                ..Default::default()
            },
        );

        let ctx = CallContext::top(deployer);
        let result = execute(&mut world, &ctx, 200_000);
        assert!(result.is_success(), "create failed: {}", result.reason);

        let new_addr: Address = {
            let mut buf = [0u8; 32];
            U256::from_big_endian(&result.output).to_big_endian(&mut buf);
            buf[12..].try_into().unwrap()
        };
        assert!(
            world.accounts.contains_key(&new_addr),
            "new contract missing"
        );
        assert_eq!(world.accounts[&new_addr].code, code("6009600055"));
        assert_eq!(world.accounts[&new_addr].nonce, 1);
    }

    #[test]
    fn out_of_gas_halts() {
        let mut world = WorldState::default();
        // Infinite-ish loop: JUMPDEST, PUSH1 0, JUMP
        let bytecode = code("5b600056");
        let result = run_code(&mut world, [0x41; 20], &bytecode, 5_000);
        assert_eq!(result.reason, ExitReason::OutOfGas);
    }

    #[test]
    fn div_by_zero_is_zero() {
        let mut world = WorldState::default();
        // PUSH1 0, PUSH1 7, DIV, PUSH0, MSTORE, PUSH1 32, PUSH1 0, RETURN
        let result = run_code(
            &mut world,
            [0x14; 20],
            &code("600060070460005260206000f3"),
            100_000,
        );
        assert_eq!(U256::from_big_endian(&result.output), U256::zero());
    }
}
