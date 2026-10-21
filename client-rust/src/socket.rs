//! The WebSocket seam: dialling a relay (ws:// or wss://), and a writer task that tells the core
//! how much it has handed the socket that is not yet on the network, so data waits in the
//! client's own queue rather than in the socket.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::SinkExt;
use futures_util::stream::SplitSink;
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::core::Wire;
use crate::frames::MAX_FRAME;
use crate::types::SOCKET_LOW_WATER;

pub(crate) type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// How long a dial (TCP, TLS and the WebSocket upgrade) may take before it counts as failed.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Dials `url`. Messages and frames over 1 MiB (the largest the relay ever sends) end the
/// connection rather than being buffered.
pub(crate) async fn connect(url: &str) -> Result<Ws, String> {
    // Serialised as WHATWG URL parsing does (a non-ASCII host becomes punycode), as the
    // TypeScript client's WebSocket dials it and as the registration origin is computed.
    let url = url::Url::parse(url).map_err(|e| format!("not a URL: {e}"))?;
    if !matches!(url.scheme(), "ws" | "wss") {
        return Err(format!("not a WebSocket URL: {}", url.scheme()));
    }
    let config = WebSocketConfig::default().max_message_size(Some(MAX_FRAME)).max_frame_size(Some(MAX_FRAME));
    let dial = tokio_tungstenite::connect_async_with_config(url.as_str(), Some(config), true);
    match tokio::time::timeout(CONNECT_TIMEOUT, dial).await {
        Ok(Ok((ws, _response))) => Ok(ws),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("connecting timed out".into()),
    }
}

enum Out {
    Msg(Message, usize),
    Close(u16, String),
}

/// How long the reader waits for the relay to finish a closing handshake this side started.
pub(crate) const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// The most a connection may hold queued and not yet written. The largest honest burst is a
/// primary publishing a full roster (65000 bytes) to every member (about 440): some 29 MB. Past
/// the bound the queue refuses, and the connection is dropped and redialled rather than grown or
/// waited on: a peer or relay that stops draining cannot make this node hold more.
pub(crate) const MAX_OUTBOUND_BYTES: usize = 64 * 1024 * 1024;

/// What a connection's tasks share with the core's handle on it.
pub(crate) struct WireShared {
    /// Bytes queued and not yet written.
    buffered: AtomicUsize,
    /// Bytes written to the socket since the connection began.
    written: AtomicU64,
    /// The queue passed its bound; the connection is to be dropped at once.
    overflowed: AtomicBool,
    /// Wakes the reader: this side closed (or overflowed).
    pub(crate) closing: Notify,
}

impl WireShared {
    pub(crate) fn overflowed(&self) -> bool {
        self.overflowed.load(Ordering::SeqCst)
    }
}

/// The core's handle on a live connection: a bounded queue to the writer task.
pub(crate) struct WsWire {
    tx: mpsc::UnboundedSender<Out>,
    shared: Arc<WireShared>,
    /// Bytes queued since the connection began.
    queued: u64,
}

impl WsWire {
    fn queue(&mut self, m: Message, n: usize) -> bool {
        if self.shared.overflowed() {
            return false;
        }
        if self.shared.buffered.load(Ordering::SeqCst).saturating_add(n) > MAX_OUTBOUND_BYTES {
            self.shared.overflowed.store(true, Ordering::SeqCst);
            return false;
        }
        self.shared.buffered.fetch_add(n, Ordering::SeqCst);
        if self.tx.send(Out::Msg(m, n)).is_err() {
            self.shared.buffered.fetch_sub(n, Ordering::SeqCst);
            return false;
        }
        self.queued += n as u64;
        true
    }
}

impl Wire for WsWire {
    fn send_text(&mut self, text: String) -> bool {
        let n = text.len();
        self.queue(Message::text(text), n)
    }

    fn send_binary(&mut self, bytes: Vec<u8>) -> bool {
        let n = bytes.len();
        self.queue(Message::binary(bytes), n)
    }

    fn buffered(&self) -> usize {
        self.shared.buffered.load(Ordering::SeqCst)
    }

    fn queued_total(&self) -> u64 {
        self.queued
    }

    fn written_total(&self) -> u64 {
        self.shared.written.load(Ordering::SeqCst)
    }

    fn overflowed(&self) -> bool {
        self.shared.overflowed()
    }

    fn close(&mut self, code: u16, reason: &str) {
        // An overflowed queue is not drained first: the reader drops the connection at once.
        if !self.shared.overflowed() {
            let _ = self.tx.send(Out::Close(code, reason.to_owned()));
        }
        self.shared.closing.notify_one();
    }
}

/// Starts the writer for `sink` and returns the core's handle on it, what it shares with the
/// reader, and the writer task (aborted when the connection is dropped). `drained` is woken each
/// time the bytes waiting fall to the low-water mark.
pub(crate) fn spawn_writer(
    sink: SplitSink<Ws, Message>,
    drained: Arc<Notify>,
) -> (WsWire, Arc<WireShared>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let shared = Arc::new(WireShared {
        buffered: AtomicUsize::new(0),
        written: AtomicU64::new(0),
        overflowed: AtomicBool::new(false),
        closing: Notify::new(),
    });
    let task = tokio::spawn(writer(sink, rx, shared.clone(), drained));
    (WsWire { tx, shared: shared.clone(), queued: 0 }, shared, task)
}

async fn writer(
    mut sink: SplitSink<Ws, Message>,
    mut rx: mpsc::UnboundedReceiver<Out>,
    shared: Arc<WireShared>,
    drained: Arc<Notify>,
) {
    let buffered = &shared.buffered;
    while let Some(out) = rx.recv().await {
        match out {
            Out::Msg(m, n) => {
                let r = sink.send(m).await;
                shared.written.fetch_add(n as u64, Ordering::SeqCst);
                let before = buffered.fetch_sub(n, Ordering::SeqCst);
                if before > SOCKET_LOW_WATER && before - n <= SOCKET_LOW_WATER {
                    drained.notify_one();
                }
                if r.is_err() {
                    break;
                }
            }
            Out::Close(code, reason) => {
                let frame = CloseFrame { code: CloseCode::from(code), reason: reason.into() };
                let _ = sink.send(Message::Close(Some(frame))).await;
                break;
            }
        }
    }
    // Whatever was never written no longer matters: the connection is gone, and the core
    // learns so from the reader.
    drained.notify_one();
}

/// The close code and reason of a received close frame (1005 when it carried none).
pub(crate) fn close_info(frame: Option<CloseFrame>) -> (u16, String) {
    match frame {
        Some(f) => (u16::from(f.code), f.reason.to_string()),
        None => (1005, String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire() -> (WsWire, mpsc::UnboundedReceiver<Out>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let shared = Arc::new(WireShared {
            buffered: AtomicUsize::new(0),
            written: AtomicU64::new(0),
            overflowed: AtomicBool::new(false),
            closing: Notify::new(),
        });
        (WsWire { tx, shared, queued: 0 }, rx)
    }

    #[test]
    fn the_queue_refuses_past_its_bound_and_stays_refused() {
        // A writer that never drains: the receiver is held, never read.
        let (mut w, _rx) = wire();
        let frame = vec![0u8; 65_536];
        let mut taken = 0usize;
        while w.send_binary(frame.clone()) {
            taken += frame.len();
            assert!(taken <= MAX_OUTBOUND_BYTES);
        }
        assert!(taken + frame.len() > MAX_OUTBOUND_BYTES, "everything up to the bound was taken");
        assert!(w.overflowed());
        assert!(w.buffered() <= MAX_OUTBOUND_BYTES);
        assert!(!w.send_text("x".into()), "nothing more, however small");
        assert!(!w.send_binary(vec![1]));
        assert_eq!(w.queued_total(), taken as u64);
        assert_eq!(w.written_total(), 0);
    }

    #[tokio::test]
    async fn closing_an_overflowed_wire_wakes_the_reader_without_queueing_a_close() {
        let (mut w, mut rx) = wire();
        w.shared.overflowed.store(true, Ordering::SeqCst);
        let shared = w.shared.clone();
        w.close(1006, "");
        tokio::time::timeout(std::time::Duration::from_secs(1), shared.closing.notified()).await.unwrap();
        assert!(rx.try_recv().is_err(), "no close frame queued behind a queue that will not drain");
        // An ordinary close queues the close frame after what is queued.
        let (mut w, mut rx) = wire();
        assert!(w.send_text("hello".into()));
        w.close(1000, "");
        assert!(matches!(rx.try_recv(), Ok(Out::Msg(..))));
        assert!(matches!(rx.try_recv(), Ok(Out::Close(1000, _))));
    }
}
