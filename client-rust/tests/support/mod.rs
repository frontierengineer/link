//! The real relay for integration tests: built once per test binary from `../relay` with
//! `go build` into Cargo's test temporary directory (or taken from `LINK_RELAY_BIN`), then started as a
//! child process on a random loopback port, configured only through `LINK_*` variables.

#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use link_client::*;

static BINARY: OnceLock<PathBuf> = OnceLock::new();

/// The relay binary: LINK_RELAY_BIN when set, else a static build into Cargo's temporary
/// directory for tests (`target/tmp`), one file per test binary, rebuilt over on every run.
pub fn relay_binary() -> PathBuf {
    BINARY
        .get_or_init(|| {
            if let Ok(given) = std::env::var("LINK_RELAY_BIN") {
                return PathBuf::from(given);
            }
            // Cargo's temporary directory for integration tests (under target/), so nothing is
            // left behind elsewhere; `go build` caches, so each test binary's build is quick.
            let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
            std::fs::create_dir_all(&dir).unwrap();
            let out = dir.join(format!("link-relay-{}", env!("CARGO_CRATE_NAME")));
            let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("relay");
            let status = Command::new("go")
                .args(["build", "-o"])
                .arg(&out)
                .arg("./cmd/link-relay")
                .current_dir(&src)
                .env("CGO_ENABLED", "0")
                .status()
                .expect("go build runs");
            assert!(status.success(), "go build of the relay failed");
            out
        })
        .clone()
}

pub struct Relay {
    child: Child,
    pub port: u16,
    pub url: String,
    pub log: Arc<Mutex<String>>,
}

impl Relay {
    /// Starts the relay with `env` (LINK_* variables) on a random loopback port.
    pub fn start(env: &[(&str, &str)]) -> Relay {
        let mut cmd = Command::new(relay_binary());
        for (k, _) in std::env::vars() {
            if k.starts_with("LINK_") {
                cmd.env_remove(k);
            }
        }
        cmd.env("LINK_ADDR", "127.0.0.1:0");
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("the relay starts");
        let stderr = child.stderr.take().unwrap();
        let log = Arc::new(Mutex::new(String::new()));
        let (tx, rx) = std::sync::mpsc::channel();
        let log2 = log.clone();
        std::thread::spawn(move || {
            let mut sent = false;
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                if !sent && let Some(i) = line.find("listening on 127.0.0.1:") {
                    let port: u16 = line[i + "listening on 127.0.0.1:".len()..].trim().parse().unwrap();
                    let _ = tx.send(port);
                    sent = true;
                }
                log2.lock().unwrap().push_str(&line);
                log2.lock().unwrap().push('\n');
            }
        });
        let port = rx.recv_timeout(Duration::from_secs(15)).expect("the relay listens");
        Relay { child, port, url: format!("ws://127.0.0.1:{port}/v1"), log }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Short reconnect and request timers, as the TypeScript suite's FAST.
pub fn fast() -> Timing {
    Timing {
        backoff_initial: Duration::from_millis(20),
        backoff_max: Duration::from_millis(200),
        request_timeout: Duration::from_secs(2),
        ..Timing::default()
    }
}

pub struct Net {
    pub relay: Relay,
    pub primary: Primary,
    pub timing: Timing,
    /// The network's key (its seed included), as the application creating it would keep it.
    pub network_key: NetworkKey,
}

impl Net {
    pub async fn start(env: &[(&str, &str)], timing: Timing) -> Net {
        Net::start_with(env, timing, |_| {}).await
    }

    /// As `start`, with `f` given the primary's options before it starts.
    pub async fn start_with(env: &[(&str, &str)], timing: Timing, f: impl FnOnce(&mut MemberOptions)) -> Net {
        let relay = Relay::start(env);
        let id = Identity::generate();
        let (roster, network_key) = create_network(&id, &relay.url, unix_ms()).unwrap();
        let mut opts = MemberOptions::new(id, roster);
        opts.timing = timing;
        opts.network_seed = Some(*network_key.seed());
        f(&mut opts);
        let primary = Primary::new(opts).unwrap();
        primary.wait_connected(Some(Duration::from_secs(15))).await.unwrap();
        Net { relay, primary, timing, network_key }
    }

    /// Pairs a new node and returns its identity and roster without connecting it.
    pub async fn pair_only(&self) -> (Identity, Roster) {
        let identity = Identity::generate();
        let code = self.primary.open_pairing_code(CodeOptions::default()).unwrap();
        let r = pair(PairOptions { target: PairTarget::Link(code.link), identity: identity.clone(), timeout: None })
            .await
            .unwrap();
        (identity, r.roster)
    }

    /// Pairs a new node and connects it as a member; waits for the others to learn the roster.
    pub async fn add(&self, others: &[&Member]) -> Member {
        self.add_with(others, |_| {}).await
    }

    pub async fn add_with(&self, others: &[&Member], f: impl FnOnce(&mut MemberOptions)) -> Member {
        let (identity, roster) = self.pair_only().await;
        let version = roster.version();
        let mut opts = MemberOptions::new(identity, roster);
        opts.timing = self.timing;
        f(&mut opts);
        let m = Member::connect(opts).await.unwrap();
        // The primary pushes the new roster to the others over their sessions, which takes a
        // moment: until it lands, they do not know the newcomer and would refuse to send to it.
        let mut all: Vec<&Member> = others.to_vec();
        all.push(&self.primary);
        until(
            || all.iter().all(|o| o.state() != MemberState::Connected || o.roster().version() >= version),
            "the others to learn the roster",
        )
        .await;
        m
    }
}

pub async fn until(mut cond: impl FnMut() -> bool, what: &str) {
    until_for(&mut cond, what, Duration::from_secs(10)).await
}

pub async fn until_for(cond: &mut impl FnMut() -> bool, what: &str, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !cond() {
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

pub async fn recv_within(m: &Member, t: Duration) -> InboundMessage {
    tokio::time::timeout(t, m.recv()).await.expect("a message in time").expect("the member is open")
}

pub fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| ((i * 131) as u8).wrapping_add(seed)).collect()
}

pub async fn sleep_ms(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await
}

/// Events from now on: the backlog since creation, which the first subscriber gets, is dropped.
pub fn events_from_now(m: &Member) -> tokio::sync::broadcast::Receiver<Event> {
    let mut r = m.events();
    while r.try_recv().is_ok() {}
    r
}

/// A member that speaks the protocol by hand, for what the library never sends.
pub struct RawMember {
    pub ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    pub id: Identity,
    pub roster: Roster,
}

impl RawMember {
    /// Connects and registers `id` with `roster` at the relay at `port`.
    pub async fn connect(port: u16, id: Identity, roster: Roster) -> RawMember {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/v1")).await.unwrap();
        let hello = loop {
            if let Some(Ok(Message::Text(t))) = ws.next().await {
                break Json::parse(t.as_str()).unwrap();
            }
        };
        let challenge: [u8; 32] =
            wire::from_b64u(hello.get("challenge").and_then(Json::as_str).unwrap()).unwrap().try_into().unwrap();
        let ts = unix_ms();
        let origin = format!("127.0.0.1:{port}");
        let sig = id.sign(&wire::register_signing_bytes(roster.network(), id.id(), &challenge, ts, &origin));
        let reg = Json::object([
            ("type", Json::str("register")),
            ("network", Json::str(roster.network())),
            ("node", Json::str(id.id())),
            ("ed25519", Json::str(wire::b64u(&id.ed25519_public()))),
            ("ts", Json::int(ts)),
            ("sig", Json::str(wire::b64u(&sig))),
            ("roster", roster.json().clone()),
        ]);
        ws.send(Message::text(reg.to_json_string().unwrap())).await.unwrap();
        loop {
            if let Some(Ok(Message::Text(t))) = ws.next().await {
                let m = Json::parse(t.as_str()).unwrap();
                assert_eq!(m.get("type").and_then(Json::as_str), Some("registered"), "{t}");
                break;
            }
        }
        RawMember { ws, id, roster }
    }

    /// Queues a frame without flushing (for floods).
    pub async fn feed(&mut self, kind: u8, peer: &str, body: &[u8]) {
        use futures_util::SinkExt;
        let f = wire::encode_frame(kind, &wire::node_id_to_bytes(peer).unwrap(), body).unwrap();
        self.ws.feed(tokio_tungstenite::tungstenite::Message::binary(f)).await.unwrap();
    }

    pub async fn flush(&mut self) {
        use futures_util::SinkExt;
        self.ws.flush().await.unwrap();
    }

    /// A Noise IK handshake as initiator with `peer`: (send state, the peer's index).
    pub async fn handshake(&mut self, peer: &str, version: u64) -> (wire::CipherState, u32) {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message;
        let member = self.roster.member(peer).unwrap().clone();
        let prologue = wire::session_prologue(self.roster.network());
        let mut hs = wire::HandshakeState::new(wire::HandshakeOptions {
            pattern: &wire::IK,
            initiator: true,
            prologue: &prologue,
            s: Some(wire::KeyPair::from_private(&self.id.x25519_private())),
            rs: Some(*member.x25519()),
            fixed_ephemeral: None,
        })
        .unwrap();
        let (m1, _) = hs.write_message(&wire::init_payload(version, stamp())).unwrap();
        self.feed(wire::frame_type::HANDSHAKE_INIT, peer, &wire::handshake_init_body(0x0102_0304, &m1)).await;
        self.flush().await;
        loop {
            let Some(Ok(Message::Binary(b))) = self.ws.next().await else { continue };
            let f = wire::decode_frame(&b).unwrap();
            if f.kind != wire::frame_type::HANDSHAKE_RESP {
                continue;
            }
            let (theirs, mine, m2) = wire::parse_handshake_resp(f.body).unwrap();
            assert_eq!(mine, 0x0102_0304);
            let (_, t) = hs.read_message(m2).unwrap();
            return (t.unwrap().send, theirs);
        }
    }
}

/// A handshake-init stamp, as a node makes them: Unix milliseconds, strictly increasing.
pub fn stamp() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(0);
    let mut last = LAST.load(Ordering::SeqCst);
    loop {
        let next = unix_ms().max(last + 1);
        match LAST.compare_exchange(last, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return next,
            Err(seen) => last = seen,
        }
    }
}

/// This process's resident memory, in MiB.
pub fn rss_mib() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let kb: u64 = s
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    kb / 1024
}

impl RawMember {
    /// The next binary frame within `t`, if any.
    pub async fn next_frame_within(&mut self, t: Duration) -> Option<Vec<u8>> {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message;
        let deadline = tokio::time::Instant::now() + t;
        loop {
            match tokio::time::timeout_at(deadline, self.ws.next()).await {
                Ok(Some(Ok(Message::Binary(b)))) => return Some(b.to_vec()),
                Ok(Some(Ok(_))) => continue,
                _ => return None,
            }
        }
    }
}
