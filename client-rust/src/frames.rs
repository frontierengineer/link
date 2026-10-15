//! Routed frames (section 6) and session messages (section 7.3): the two binary layouts of the
//! protocol, encoded and decoded strictly. Decoding never panics: every length is checked.

use crate::bytes::{read_u32be, u32be};

pub const FRAME_VERSION: u8 = 1;
pub const FRAME_HEADER: usize = 18;
/// The maximum binary frame, header included.
pub const MAX_FRAME: usize = 1_048_576;

pub mod frame_type {
    pub const HANDSHAKE_INIT: u8 = 0x01;
    pub const HANDSHAKE_RESP: u8 = 0x02;
    pub const DATA: u8 = 0x03;
    pub const UNREACHABLE: u8 = 0x04;
    pub const REFUSED: u8 = 0x05;
    pub const PAIR: u8 = 0x06;
    pub const RESET: u8 = 0x07;
    /// As DATA, carrying a session message other than `message`; sent only to a relay that
    /// lists the `control` feature, which delivers it as DATA (section 6).
    pub const CONTROL: u8 = 0x08;
}

/// `refused` reason 1: not on my roster.
pub const REFUSED_NOT_ON_ROSTER: u8 = 1;

/// A routed frame. `peer` is a raw node id, or a pairing channel id for `pair` frames.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub kind: u8,
    pub peer: [u8; 16],
    pub body: &'a [u8],
}

pub fn encode_frame(kind: u8, peer: &[u8; 16], body: &[u8]) -> Result<Vec<u8>, String> {
    let len = FRAME_HEADER + body.len();
    if len > MAX_FRAME {
        return Err("frame exceeds 1 MiB".into());
    }
    let mut out = Vec::with_capacity(len);
    out.push(FRAME_VERSION);
    out.push(kind);
    out.extend_from_slice(peer);
    out.extend_from_slice(body);
    Ok(out)
}

pub fn decode_frame(b: &[u8]) -> Result<Frame<'_>, String> {
    if b.len() > MAX_FRAME {
        return Err("frame exceeds 1 MiB".into());
    }
    let (Some(&version), Some(&kind), Some(peer), Some(body)) =
        (b.first(), b.get(1), b.get(2..FRAME_HEADER), b.get(FRAME_HEADER..))
    else {
        return Err("frame shorter than its header".into());
    };
    if version != FRAME_VERSION {
        return Err(format!("unknown frame version {version}"));
    }
    let peer: [u8; 16] = peer.try_into().map_err(|_| "frame shorter than its header".to_string())?;
    Ok(Frame { kind, peer, body })
}

/// `u32be(sender index) || Noise message 1`.
pub fn handshake_init_body(sender_index: u32, noise: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + noise.len());
    out.extend_from_slice(&u32be(sender_index));
    out.extend_from_slice(noise);
    out
}

pub fn parse_handshake_init(body: &[u8]) -> Option<(u32, &[u8])> {
    Some((read_u32be(body, 0)?, body.get(4..)?))
}

/// The payload of Noise message 1: `u64be(roster version) || u64be(stamp)`, the stamp being the
/// initiator's Unix milliseconds, strictly increasing per node, so a responder can refuse a
/// replayed message 1 (section 7.1).
pub fn init_payload(version: u64, stamp: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&version.to_be_bytes());
    out[8..].copy_from_slice(&stamp.to_be_bytes());
    out
}

/// `(roster version, stamp)` from a message-1 payload, which is exactly 16 bytes.
pub fn parse_init_payload(payload: &[u8]) -> Option<(u64, u64)> {
    let (version, stamp) = <&[u8; 16]>::try_from(payload).ok()?.split_at(8);
    Some((u64::from_be_bytes(version.try_into().ok()?), u64::from_be_bytes(stamp.try_into().ok()?)))
}

/// `u32be(sender index) || u32be(receiver index) || Noise message 2`.
pub fn handshake_resp_body(sender_index: u32, receiver_index: u32, noise: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + noise.len());
    out.extend_from_slice(&u32be(sender_index));
    out.extend_from_slice(&u32be(receiver_index));
    out.extend_from_slice(noise);
    out
}

pub fn parse_handshake_resp(body: &[u8]) -> Option<(u32, u32, &[u8])> {
    Some((read_u32be(body, 0)?, read_u32be(body, 4)?, body.get(8..)?))
}

/// `u32be(receiver index) || ciphertext`.
pub fn data_body(receiver_index: u32, ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + ciphertext.len());
    out.extend_from_slice(&u32be(receiver_index));
    out.extend_from_slice(ciphertext);
    out
}

pub fn parse_data(body: &[u8]) -> Option<(u32, &[u8])> {
    Some((read_u32be(body, 0)?, body.get(4..)?))
}

// ── Session messages (section 7.3) ──

pub mod session_type {
    pub const MESSAGE: u8 = 0x01;
    pub const CREDIT: u8 = 0x02;
    pub const ROSTER_REQUEST: u8 = 0x03;
    pub const ROSTER: u8 = 0x04;
    pub const RESIGN: u8 = 0x05;
}

pub const FLAG_MORE: u8 = 0x01;

/// A decrypted session message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionMessage<'a> {
    Message {
        more: bool,
        bytes: &'a [u8],
    },
    Credit(u32),
    RosterRequest,
    /// UTF-8 JSON roster.
    Roster(&'a str),
    /// UTF-8 JSON resignation.
    Resign(&'a str),
}

impl SessionMessage<'_> {
    pub fn is_message(&self) -> bool {
        matches!(self, SessionMessage::Message { .. })
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            SessionMessage::Message { more, bytes } => {
                let mut out = Vec::with_capacity(2 + bytes.len());
                out.push(session_type::MESSAGE);
                out.push(if *more { FLAG_MORE } else { 0 });
                out.extend_from_slice(bytes);
                out
            }
            SessionMessage::Credit(n) => {
                let mut out = vec![session_type::CREDIT];
                out.extend_from_slice(&u32be(*n));
                out
            }
            SessionMessage::RosterRequest => vec![session_type::ROSTER_REQUEST],
            SessionMessage::Roster(json) => [&[session_type::ROSTER][..], json.as_bytes()].concat(),
            SessionMessage::Resign(json) => [&[session_type::RESIGN][..], json.as_bytes()].concat(),
        }
    }

    /// Strict: an unknown type, a credit that is not 4 bytes, a roster-request with a body, or
    /// text that is not UTF-8 is refused.
    pub fn decode(p: &[u8]) -> Result<SessionMessage<'_>, String> {
        let (&kind, rest) = p.split_first().ok_or("empty session message")?;
        let text = |b| std::str::from_utf8(b).map_err(|_| "session message text is not UTF-8".to_string());
        match kind {
            session_type::MESSAGE => {
                let (&flags, bytes) = rest.split_first().ok_or("message without flags")?;
                Ok(SessionMessage::Message { more: flags & FLAG_MORE != 0, bytes })
            }
            session_type::CREDIT => {
                let n: [u8; 4] = rest.try_into().map_err(|_| "credit must carry 4 bytes".to_string())?;
                Ok(SessionMessage::Credit(u32::from_be_bytes(n)))
            }
            session_type::ROSTER_REQUEST if rest.is_empty() => Ok(SessionMessage::RosterRequest),
            session_type::ROSTER_REQUEST => Err("roster-request must be empty".into()),
            session_type::ROSTER => Ok(SessionMessage::Roster(text(rest)?)),
            session_type::RESIGN => Ok(SessionMessage::Resign(text(rest)?)),
            other => Err(format!("unknown session message type {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_frames_and_messages_are_refused() {
        assert!(decode_frame(&[1, 3]).is_err());
        assert!(decode_frame(&[2; 18]).is_err(), "version 2");
        assert!(decode_frame(&vec![1; MAX_FRAME + 1]).is_err());
        let f = decode_frame(&[1; 18]).unwrap();
        assert!(f.body.is_empty());
        assert!(encode_frame(3, &[0; 16], &vec![0; MAX_FRAME - FRAME_HEADER + 1]).is_err());
        assert!(encode_frame(3, &[0; 16], &vec![0; MAX_FRAME - FRAME_HEADER]).is_ok());
        assert_eq!(parse_handshake_init(&[0, 0, 1]), None);
        assert_eq!(parse_handshake_resp(&[0; 7]), None);
        assert_eq!(parse_data(&[0; 3]), None);
        assert_eq!(parse_data(&[0, 0, 0, 9]), Some((9, &[][..])));
        assert!(SessionMessage::decode(&[]).is_err());
        assert!(SessionMessage::decode(&[1]).is_err());
        assert!(SessionMessage::decode(&[2, 0, 0, 0]).is_err());
        assert!(SessionMessage::decode(&[2, 0, 0, 0, 0, 0]).is_err());
        assert!(SessionMessage::decode(&[3, 0]).is_err());
        assert!(SessionMessage::decode(&[4, 0xff]).is_err());
        assert!(SessionMessage::decode(&[9]).is_err());
        assert_eq!(SessionMessage::decode(&[1, 0xff, 7]), Ok(SessionMessage::Message { more: true, bytes: &[7] }));
    }
}
