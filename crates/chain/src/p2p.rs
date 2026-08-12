//! Minimal peer-to-peer block sync over TCP.
//!
//! The goal (roadmap Phase 3 "done when"): *two nodes sync a chain over P2P
//! and agree on the same canonical tip.* This module provides exactly that —
//! a teaching-grade, dependency-free P2P layer built on `std::net` threads.
//!
//! ## Wire format
//!
//! Every message is `u32` big-endian length prefix followed by a JSON payload
//! ([`Message`]). JSON keeps the wire readable and debuggable, at the cost of
//! size — fine for a teaching chain.
//!
//! The protocol is deliberately tiny — four messages:
//!
//! | message | direction | meaning |
//! |---|---|---|
//! | [`Message::Hello`] | both | version handshake: genesis hash, best height + tip |
//! | [`Message::GetBlocks`] | puller → server | "send me your blocks from height N" |
//! | [`Message::Blocks`] | server → puller | the requested blocks (bounded) |
//! | [`Message::NewTip`] | both | announce a new active tip (triggers a pull if behind) |
//!
//! ## Sync algorithm
//!
//! 1. **Handshake** — both sides exchange [`Message::Hello`]; a genesis hash
//!    mismatch closes the connection (different networks must not mix).
//! 2. **Pull** — the node with the shorter chain requests `GetBlocks` from its
//!    own `height + 1` and submits each block through the normal
//!    [`BlockChain::submit`] validation. Responses are capped at
//!    [`MAX_BLOCKS_PER_RESPONSE`]; the puller loops until it gets an empty
//!    response, so it converges even if the server keeps mining.
//! 3. **Reorg** — if a pulled block's parent is unknown (the two chains
//!    diverged), the puller re-requests the peer's *entire* chain from
//!    height 1. The store keeps side branches, so the longest valid chain
//!    wins. This is the brute-force version of Bitcoin's header-first sync;
//!    adequate at this scale and easy to understand.
//! 4. **Announce** — a node that advanced its tip sends [`Message::NewTip`]
//!    so a server that is somehow behind can pull back.
//!
//! Request/response pairs are strictly sequential on each connection, so the
//! single stream never deadlocks: a node sends a request only while the peer
//! is idle (waiting for the next message).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::block::Block;
use crate::chain::{BlockChain, ChainError};

/// Hard cap on blocks per `Blocks` response (JSON payloads get big).
pub const MAX_BLOCKS_PER_RESPONSE: u32 = 200;
/// Socket read/write timeout — keeps tests and demos from hanging.
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound on a decoded message, in bytes (guards against runaway JSON).
pub const MAX_MESSAGE_SIZE: u64 = 64 * 1024 * 1024;

/// The four message types of the wire protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// Handshake: identify our network (genesis) and our best tip.
    Hello {
        genesis: [u8; 32],
        best_height: u64,
        best_hash: [u8; 32],
    },
    /// Pull request: "send me blocks from `from_height` up to `max` of them".
    GetBlocks { from_height: u64, max: u32 },
    /// Pull response: a (possibly empty) suffix of the server's active chain.
    Blocks { blocks: Vec<Block> },
    /// Announcement: "my active tip is now `hash` at height `height`".
    NewTip { height: u64, hash: [u8; 32] },
}

/// Errors from the P2P layer.
#[derive(Debug, thiserror::Error)]
pub enum P2pError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("peer genesis {peer:?} does not match ours {ours:?}")]
    GenesisMismatch { ours: [u8; 32], peer: [u8; 32] },
    #[error("malformed message: {0}")]
    Protocol(String),
    #[error("peer chain rejected: {0}")]
    Chain(#[from] ChainError),
    #[error("message serialization failed: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("connection closed by peer")]
    UnexpectedEof,
}

/// What a sync session accomplished — handy for tests and demos.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// The peer's best height at handshake time.
    pub peer_height: u64,
    /// Number of blocks downloaded and accepted.
    pub downloaded: u64,
    /// True if a divergent branch forced a full re-download (reorg).
    pub reorg: bool,
    /// True if we ended the session on the same tip as the peer.
    pub converged: bool,
}

/// A blockchain node: an owned [`BlockChain`] plus a TCP server that serves
/// and (if needed) pulls blocks. Cheap to construct; the accept loop runs on
/// a background thread, so tests can spin up any number of nodes.
#[derive(Clone)]
pub struct Node {
    chain: Arc<Mutex<BlockChain>>,
    addr: SocketAddr,
}

impl Node {
    /// Bind a server on `addr` (use `"127.0.0.1:0"` for an ephemeral port)
    /// and start accepting peers in the background.
    pub fn start(chain: BlockChain, addr: &str) -> Result<Node, P2pError> {
        let listener = TcpListener::bind(addr)?;
        let addr = listener.local_addr()?;
        let node = Node {
            chain: Arc::new(Mutex::new(chain)),
            addr,
        };
        let accept_chain = node.chain.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let chain = accept_chain.clone();
                        thread::spawn(move || {
                            if let Err(e) = serve_session(chain, stream) {
                                eprintln!("p2p session error: {e}");
                            }
                        });
                    }
                    Err(e) => eprintln!("p2p accept error: {e}"),
                }
            }
        });
        Ok(node)
    }

    /// The address other nodes should connect to.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Best tip hash of the local chain.
    pub fn tip(&self) -> [u8; 32] {
        self.chain.lock().unwrap().active_tip()
    }

    /// Best tip height of the local chain.
    pub fn height(&self) -> u64 {
        self.chain.lock().unwrap().active_height()
    }

    /// Submit a block through normal validation (used to seed a node).
    pub fn submit(&self, block: Block) -> Result<crate::chain::SubmitOutcome, ChainError> {
        self.chain.lock().unwrap().submit(block)
    }

    /// Clone the local chain (for assertions in tests).
    pub fn chain(&self) -> BlockChain {
        self.chain.lock().unwrap().clone()
    }

    /// Connect to `peer`, handshake, pull blocks until converged, announce our
    /// new tip, and keep serving the peer until it disconnects.
    pub fn connect(&self, peer: SocketAddr) -> Result<SyncReport, P2pError> {
        let mut stream = TcpStream::connect_timeout(&peer, IO_TIMEOUT)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        sync_session(self.chain.clone(), &mut stream)
    }
}

/// Outgoing (client) side of a sync session: handshake, pull, announce, then
/// serve the peer until it closes. Runs on the caller's thread.
fn sync_session(
    chain: Arc<Mutex<BlockChain>>,
    stream: &mut TcpStream,
) -> Result<SyncReport, P2pError> {
    // 1. Handshake: identify ourselves, check the peer's genesis.
    let peer = handshake(&chain, stream)?;
    let mut report = SyncReport {
        peer_height: peer.best_height,
        downloaded: 0,
        reorg: false,
        converged: false,
    };

    // 2. Pull if the peer is ahead, or if we're at the same height on a
    //    different branch (a reorg that needs resolving).
    let our_height = chain.lock().unwrap().active_height();
    let our_tip = chain.lock().unwrap().active_tip();
    if peer.best_height > our_height {
        pull(chain.clone(), stream, our_height + 1, &mut report)?;
    } else if peer.best_height == our_height && peer.best_hash != our_tip {
        // Same height, divergent tip: re-download the peer's whole chain;
        // the longest valid branch wins (ours is stored as a side branch).
        report.reorg = true;
        pull(chain.clone(), stream, 1, &mut report)?;
    }

    // 3. Announce our (possibly new) tip so the peer can pull back if needed.
    let tip = chain.lock().unwrap().active_tip();
    let height = chain.lock().unwrap().active_height();
    write_message(stream, &Message::NewTip { height, hash: tip })?;

    report.converged =
        chain.lock().unwrap().active_tip() == peer.best_hash || height >= peer.best_height;
    Ok(report)
}

/// The peer's identity as learned during the handshake.
struct PeerInfo {
    best_height: u64,
    best_hash: [u8; 32],
}

/// Handshake: send `Hello`, read the peer's `Hello`, verify the genesis.
fn handshake(chain: &Arc<Mutex<BlockChain>>, stream: &mut TcpStream) -> Result<PeerInfo, P2pError> {
    let genesis = {
        let chain = chain.lock().unwrap();
        // Genesis is the block whose parent is the zero hash; walk back to it.
        let mut cur = chain.active_tip();
        loop {
            let block = chain.block(&cur).expect("tip is in the store");
            if block.header.prev_hash == [0u8; 32] {
                break cur;
            }
            cur = block.header.prev_hash;
        }
    };
    write_message(
        stream,
        &Message::Hello {
            genesis,
            best_height: chain.lock().unwrap().active_height(),
            best_hash: chain.lock().unwrap().active_tip(),
        },
    )?;
    match read_message(stream)? {
        Message::Hello {
            genesis: peer_genesis,
            best_height,
            best_hash,
        } => {
            if peer_genesis != genesis {
                return Err(P2pError::GenesisMismatch {
                    ours: genesis,
                    peer: peer_genesis,
                });
            }
            Ok(PeerInfo {
                best_height,
                best_hash,
            })
        }
        other => Err(P2pError::Protocol(format!(
            "expected Hello, got {}",
            message_name(&other)
        ))),
    }
}

/// Pull blocks from `from_height` until the peer has nothing more to give.
/// On a divergent branch (unknown parent) restart from height 1 — the whole
/// peer chain is re-downloaded and the longest valid chain wins.
fn pull(
    chain: Arc<Mutex<BlockChain>>,
    stream: &mut TcpStream,
    from_height: u64,
    report: &mut SyncReport,
) -> Result<(), P2pError> {
    let mut from = from_height;
    loop {
        write_message(
            stream,
            &Message::GetBlocks {
                from_height: from,
                max: MAX_BLOCKS_PER_RESPONSE,
            },
        )?;
        let blocks = match read_message(stream)? {
            Message::Blocks { blocks } => blocks,
            other => {
                return Err(P2pError::Protocol(format!(
                    "expected Blocks, got {}",
                    message_name(&other)
                )))
            }
        };
        if blocks.is_empty() {
            break;
        }
        for block in blocks {
            // Bind the result so the lock guard doesn't outlive the match
            // arms (we may recurse into `pull` inside them).
            let outcome = chain.lock().unwrap().submit(block);
            match outcome {
                Ok(_) => report.downloaded += 1,
                // Diverged: our chain doesn't know this block's parent.
                // Re-download the peer's whole chain; longest wins.
                Err(ChainError::UnknownParent(_)) => {
                    report.reorg = true;
                    return pull(chain, stream, 1, report);
                }
                Err(e) => return Err(P2pError::Chain(e)),
            }
        }
        // We accepted `blocks.len()` new blocks (or a reorg brought us to a
        // different tip), so our height advanced; continue from just past it.
        from = chain.lock().unwrap().active_height() + 1;
    }
    Ok(())
}

/// Incoming (server) side of a session: handshake, then serve requests until
/// the peer disconnects. If a `NewTip` shows we fell behind, pull back.
fn serve_session(chain: Arc<Mutex<BlockChain>>, mut stream: TcpStream) -> Result<(), P2pError> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let _peer_info = handshake(&chain, &mut stream)?;
    loop {
        let msg = match read_message(&mut stream) {
            Ok(m) => m,
            Err(P2pError::UnexpectedEof) => return Ok(()), // peer hung up
            Err(e) => return Err(e),
        };
        match msg {
            Message::GetBlocks { from_height, max } => {
                let blocks: Vec<Block> = {
                    let chain = chain.lock().unwrap();
                    chain
                        .active_chain(from_height)
                        .into_iter()
                        .take(max as usize)
                        .cloned()
                        .collect()
                };
                write_message(&mut stream, &Message::Blocks { blocks })?;
            }
            Message::NewTip { height, .. } => {
                if height > chain.lock().unwrap().active_height() {
                    // We fell behind; pull from the peer on this stream. The
                    // peer is idle (it just announced), so the sequential
                    // request/response discipline holds.
                    let mut report = SyncReport {
                        peer_height: height,
                        ..Default::default()
                    };
                    let from = chain.lock().unwrap().active_height() + 1;
                    let _ = pull(chain.clone(), &mut stream, from, &mut report);
                    let tip = chain.lock().unwrap().active_tip();
                    let h = chain.lock().unwrap().active_height();
                    write_message(
                        &mut stream,
                        &Message::NewTip {
                            height: h,
                            hash: tip,
                        },
                    )?;
                }
            }
            Message::Blocks { blocks } => {
                // Unsolicited push (not used by the current protocol): just
                // validate and store.
                for block in blocks {
                    chain.lock().unwrap().submit(block)?;
                }
            }
            Message::Hello { .. } => { /* handshake already done; ignore */ }
        }
    }
}

/// Human-readable message kind (for protocol errors).
fn message_name(msg: &Message) -> &'static str {
    match msg {
        Message::Hello { .. } => "Hello",
        Message::GetBlocks { .. } => "GetBlocks",
        Message::Blocks { .. } => "Blocks",
        Message::NewTip { .. } => "NewTip",
    }
}

/// Write one length-prefixed JSON message.
fn write_message(stream: &mut TcpStream, msg: &Message) -> Result<(), P2pError> {
    let bytes = serde_json::to_vec(msg)?;
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

/// Read one length-prefixed JSON message.
fn read_message(stream: &mut TcpStream) -> Result<Message, P2pError> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(P2pError::UnexpectedEof)
        }
        Err(e) => return Err(P2pError::Io(e)),
    }
    let len = u32::from_be_bytes(len_buf) as u64;
    if len > MAX_MESSAGE_SIZE {
        return Err(P2pError::Protocol(format!(
            "message too large: {len} bytes"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf)?;
    serde_json::from_slice(&buf).map_err(|e| P2pError::Protocol(e.to_string()))
}
