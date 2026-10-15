//! The Rust client for Link, protocol version 1 (`spec/protocol.md`): keys, signed rosters,
//! pairing with a short code (SPAKE2), and end-to-end encrypted sessions (Noise IK) over one
//! outbound WebSocket to a relay that only routes.
//!
//! ```no_run
//! use link_client::{create_network, pair, Identity, Member, MemberKind, MemberOptions, PairOptions, PairTarget, Primary};
//!
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! // The primary: create the network once, then persist the seed and the roster.
//! let me = Identity::generate();
//! let roster = create_network(&me, "wss://frontierengineer.link/v1", link_client::unix_ms())?;
//! let primary = Primary::connect(MemberOptions::new(me, roster)).await?;
//! let code = primary.open_pairing_code(MemberKind::Worker, Default::default())?;
//!
//! // The newcomer: pair once, then connect as a member from then on.
//! let id = Identity::generate();
//! let paired = pair(PairOptions { target: PairTarget::Link(code.link), identity: id.clone(), timeout: None }).await?;
//! let member = Member::connect(MemberOptions::new(id, paired.roster)).await?;
//! member.send(primary.id(), &b"hello"[..]).await?;
//! let got = primary.recv().await;
//! # Ok(()) }
//! ```

#![forbid(unsafe_code)]

mod bytes;
mod code;
mod core;
mod crypto;
mod directory;
mod errors;
mod frames;
mod http;
mod identity;
mod json;
mod member;
mod newcomer;
mod noise;
mod pairing;
mod roster;
mod signed;
mod socket;
mod spake2;
mod types;

pub use crate::code::{
    PairingLink, build_pairing_link, format_code, generate_code, normalize_code, parse_pairing_link,
};
pub use crate::core::sessions::SessionInfo;
pub use crate::core::{Observation, close_code};
pub use crate::directory::{
    DirectoryRegion, DirectorySource, Fetch, FetchResponse, MAX_SHARDS, PickRelayOptions, PickedRelay, RelayDirectory,
    parse_directory, pick_relay, shard_of,
};
pub use crate::errors::{ErrorCode, LinkError};
pub use crate::identity::{Identity, is_node_id, node_id_from_ed25519};
pub use crate::json::{Json, JsonError};
pub use crate::member::{CodeOptions, Member, MemberOptions, Primary, ResolveRelay};
pub use crate::newcomer::{PairOptions, PairResult, PairTarget, pair};
pub use crate::roster::{
    MAX_ROSTER_BYTES, MemberKind, Roster, RosterMember, UnsignedRoster, acceptance_problem, create_network,
    roster_problem, roster_signing_bytes, sign_roster,
};
pub use crate::types::*;

/// The current time in Unix milliseconds, as rosters and pairing codes carry it.
pub fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The protocol's building blocks, exposed for the vector tests and for tools: encodings, the
/// signed statements, frames and session messages, the Noise engine, SPAKE2 and the pairing
/// state machines. Applications need none of it.
pub mod wire {
    pub use crate::bytes::{b32, b64u, from_b32, from_b64u, from_hex, to_hex};
    pub use crate::core::sessions::session_prologue;
    pub use crate::crypto::ed25519_verify;
    pub use crate::frames::*;
    pub use crate::identity::{node_id_bytes, node_id_from_bytes, node_id_to_bytes};
    pub use crate::noise::{
        CipherState, HandshakeOptions, HandshakeState, IK, KK, KeyPair, NN, NoiseError, Pattern, Transport, XX,
    };
    pub use crate::pairing::{NewcomerExchange, NewcomerKeys, PrimaryExchange, transport_keys};
    pub use crate::roster::signed_size;
    pub use crate::signed::{Resignation, origin_of, register_signing_bytes, resign_signing_bytes};
    pub use crate::spake2::{
        Keys as Spake2Keys, Role as Spake2Role, SPAKE2_ID_A, SPAKE2_ID_B, Spake2, derive_w, scalar_from_random,
    };
    pub use p256::Scalar as P256Scalar;

    /// A P-256 scalar from 32 big-endian bytes, reduced mod n (for vectors that give x, y, w).
    pub fn p256_scalar(bytes: &[u8]) -> P256Scalar {
        crate::spake2::scalar_mod_n(bytes)
    }
}
