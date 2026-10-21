//! The newcomer's side of pairing (sections 5.2 and 5.3): find the primary through the relay,
//! prove the code with SPAKE2, hand over the node's keys and receive the roster that includes it.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

use crate::bytes::from_b64u_array;
use crate::code::{PairingLink, normalize_code, parse_pairing_link};
use crate::errors::LinkError;
use crate::frames::{decode_frame, encode_frame, frame_type};
use crate::identity::Identity;
use crate::json::Json;
use crate::pairing::{NewcomerExchange, NewcomerKeys};
use crate::roster::{Roster, roster_problem};
use crate::socket::{Ws, close_info, connect};

/// Where to pair: a `frontier://pair?...` link, or its parts.
#[derive(Clone, Debug)]
pub enum PairTarget {
    Link(String),
    /// `code` as typed: `XXXX-XXXX` or any spelling `normalize_code` accepts; `code_id` b64u.
    Parts {
        network: String,
        code: String,
        code_id: String,
        relay: String,
    },
}

#[derive(Clone, Debug)]
pub struct PairOptions {
    pub target: PairTarget,
    pub identity: Identity,
    /// Whole-exchange timeout (60 s, the relay's channel lifetime).
    pub timeout: Option<Duration>,
}

#[derive(Clone, Debug)]
pub struct PairResult {
    /// The roster that includes this node. Persist it with the identity.
    pub roster: Roster,
    /// The network key, pinned from the roster: `roster.networkKey` (b64u).
    pub pinned_network_key: String,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd)]
enum Stage {
    Hello,
    Pairing,
    P2,
    P4,
    P6,
}

/// Pairs `identity` into the network the target names. Fails with `pairing`, `unreachable`
/// (the primary is not connected) or `timeout`.
pub async fn pair(opts: PairOptions) -> Result<PairResult, LinkError> {
    let target = match opts.target {
        PairTarget::Link(link) => parse_pairing_link(&link).map_err(LinkError::pairing)?,
        PairTarget::Parts { network, code, code_id, relay } => {
            PairingLink { network, code: normalize_code(&code).map_err(LinkError::pairing)?, code_id, relay }
        }
    };
    let code_id =
        from_b64u_array::<8>(&target.code_id).ok_or_else(|| LinkError::pairing("code id: expected 8 bytes"))?;
    let exchange = NewcomerExchange::new(&target.code, &code_id, None).map_err(LinkError::pairing)?;
    let timeout = opts.timeout.unwrap_or(Duration::from_secs(60));
    let mut ws: Option<Ws> = None;
    let run = exchange_with_relay(&target, &opts.identity, exchange, &mut ws);
    let result = match tokio::time::timeout(timeout, run).await {
        Ok(r) => r,
        Err(_) => Err(LinkError::timeout("pairing")),
    };
    if let Some(mut ws) = ws {
        let _ = ws.close(Some(CloseFrame { code: CloseCode::Normal, reason: "".into() })).await;
    }
    result
}

async fn exchange_with_relay(
    target: &PairingLink,
    identity: &Identity,
    mut exchange: NewcomerExchange,
    slot: &mut Option<Ws>,
) -> Result<PairResult, LinkError> {
    let ended = |stage: Stage, code: u16| {
        LinkError::pairing(if stage == Stage::P4 {
            "the primary rejected the code".to_string()
        } else {
            format!("the relay ended pairing (close {code}) before it finished")
        })
    };
    let ws = match connect(&target.relay).await {
        Ok(ws) => slot.insert(ws),
        Err(_) => return Err(ended(Stage::Hello, 1006)),
    };
    let mut stage = Stage::Hello;
    let mut channel = [0u8; 16];
    let mine = NewcomerKeys { ed25519: identity.ed25519_public(), x25519: identity.x25519_public() };
    loop {
        let msg = match ws.next().await {
            Some(Ok(m)) => m,
            Some(Err(_)) | None => return Err(ended(stage, 1006)),
        };
        match msg {
            Message::Text(t) => {
                let Ok(m) = Json::parse(t.as_str()) else {
                    continue;
                };
                match m.get("type").and_then(Json::as_str) {
                    Some("hello") if stage == Stage::Hello => {
                        let version = m.get("version").and_then(Json::as_safe_uint);
                        if version != Some(1) {
                            let shown = m
                                .get("version")
                                .map_or("undefined".to_string(), |v| v.to_json_string().unwrap_or_default());
                            return Err(LinkError::pairing(format!("relay speaks version {shown}")));
                        }
                        stage = Stage::Pairing;
                        let pair = Json::object([
                            ("type", Json::str("pair")),
                            ("network", Json::str(&target.network)),
                            ("code", Json::str(&target.code_id)),
                        ]);
                        send_text(ws, &pair).await?;
                    }
                    Some("pairing") if stage == Stage::Pairing => {
                        channel = m
                            .get("channel")
                            .and_then(Json::as_str)
                            .and_then(from_b64u_array::<16>)
                            .ok_or_else(|| LinkError::pairing("channel: expected 16 bytes"))?;
                        stage = Stage::P2;
                        send_pair(ws, &channel, &exchange.p1()).await?;
                    }
                    Some("pairEnd") if stage != Stage::Hello => {
                        return Err(LinkError::pairing(if stage == Stage::P4 {
                            "the primary rejected the code"
                        } else {
                            "the primary ended pairing before it finished"
                        }));
                    }
                    Some("error") => {
                        let code = m.get("code").and_then(Json::as_str).unwrap_or("undefined");
                        return Err(if code == "unreachable" {
                            LinkError::unreachable(&target.network)
                        } else {
                            LinkError::pairing(format!("relay answered {code}"))
                        });
                    }
                    _ => {}
                }
            }
            Message::Binary(b) => {
                let Ok(f) = decode_frame(&b) else {
                    continue;
                };
                if f.kind != frame_type::PAIR || stage < Stage::P2 || f.peer != channel {
                    continue;
                }
                match stage {
                    Stage::P2 => {
                        stage = Stage::P4;
                        let p3 = exchange.on_p2(f.body).map_err(LinkError::pairing)?;
                        send_pair(ws, &channel, &p3).await?;
                    }
                    Stage::P4 => {
                        stage = Stage::P6;
                        let p5 = exchange.on_p4(f.body, &mine).map_err(LinkError::pairing)?;
                        send_pair(ws, &channel, &p5).await?;
                    }
                    Stage::P6 => {
                        let roster = exchange.on_p6(f.body).map_err(LinkError::pairing)?;
                        return check_roster(roster, &target.network, identity);
                    }
                    Stage::Hello | Stage::Pairing => {}
                }
            }
            Message::Close(f) => return Err(ended(stage, close_info(f).0)),
            _ => {}
        }
    }
}

async fn send_text(ws: &mut Ws, msg: &Json) -> Result<(), LinkError> {
    let text = msg.to_json_string().map_err(|e| LinkError::pairing(e.to_string()))?;
    ws.send(Message::text(text)).await.map_err(|_| LinkError::pairing("the relay connection failed"))
}

async fn send_pair(ws: &mut Ws, channel: &[u8; 16], body: &[u8]) -> Result<(), LinkError> {
    let frame = encode_frame(frame_type::PAIR, channel, body).map_err(LinkError::pairing)?;
    ws.send(Message::binary(frame)).await.map_err(|_| LinkError::pairing("the relay connection failed"))
}

fn check_roster(value: Json, network: &str, id: &Identity) -> Result<PairResult, LinkError> {
    if let Some(problem) = roster_problem(&value) {
        return Err(LinkError::pairing(format!("the primary sent an invalid roster: {problem}")));
    }
    let roster = Roster::from_json(value).map_err(LinkError::pairing)?;
    if roster.network() != network {
        return Err(LinkError::pairing("the roster is for a different network"));
    }
    let listed = roster
        .member(id.id())
        .is_some_and(|m| *m.ed25519() == id.ed25519_public() && *m.x25519() == id.x25519_public());
    if !listed {
        return Err(LinkError::pairing("the roster does not list this node with its keys"));
    }
    let pinned_network_key = roster.network_key_b64u();
    Ok(PairResult { roster, pinned_network_key })
}
