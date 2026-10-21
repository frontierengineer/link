//! The Rust client's driver: one node of a Link network, steered over stdin and stdout as
//! `test/drivers/PROTOCOL.md` describes. Test equipment only: it uses the library's public API
//! and is not part of it.
//!
//!   cargo build --release --bin link-driver && target/release/link-driver

#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use link_client::{
    ErrorCode, Event, Identity, InboundMessage, Json, LinkError, Member, MemberOptions, MemberState, Observed,
    PairOptions, PairTarget, Primary, Roster, Timing, TrafficReport, create_network, pair, unix_ms,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};

/// A failed command: a client error code (with the refusal's reason byte for `refused`), or
/// `invalid` / `internal` for what the driver itself refuses or cannot do.
struct Failure {
    code: &'static str,
    message: String,
    reason: Option<u8>,
}

impl From<LinkError> for Failure {
    fn from(e: LinkError) -> Failure {
        Failure { code: e.code().as_str(), message: e.message().to_owned(), reason: e.reason() }
    }
}

fn invalid(message: impl Into<String>) -> Failure {
    Failure { code: ErrorCode::Invalid.as_str(), message: message.into(), reason: None }
}

type Reply = Result<Json, Failure>;

/// What goes to stdout, in order: everything the node raises is queued the moment it happens,
/// so an event raised before a command completed is written before that command's reply.
enum Out {
    Line(Json),
    Message(InboundMessage),
    Flush(oneshot::Sender<()>),
}

#[derive(Clone)]
enum Node {
    Member(Member),
    Primary(Primary),
}

impl Node {
    fn member(&self) -> &Member {
        match self {
            Node::Member(m) => m,
            Node::Primary(p) => p.member(),
        }
    }
}

struct State {
    identity: Option<Identity>,
    node: Option<Node>,
    auto_take: bool,
}

struct Driver {
    state: Mutex<State>,
    out: mpsc::UnboundedSender<Out>,
    /// Takes run one after another, so two never count the same waiting messages.
    takes: tokio::sync::Mutex<()>,
}

impl Driver {
    fn write(&self, obj: Json) {
        let _ = self.out.send(Out::Line(obj));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn identity(&self) -> Result<Identity, Failure> {
        self.lock().identity.clone().ok_or_else(|| invalid("no identity: send `identity` first"))
    }

    fn node(&self) -> Result<Node, Failure> {
        self.lock().node.clone().ok_or_else(|| invalid("no node: send `connect` or `start` first"))
    }

    /// The node, when it is the primary now (whichever way it started).
    fn primary(&self) -> Result<Member, Failure> {
        let m = self.node()?.member().clone();
        if !m.is_primary() {
            return Err(invalid("only the primary can do this"));
        }
        Ok(m)
    }
}

// ── Arguments ──

fn str_arg<'a>(args: &'a Json, key: &str) -> Result<&'a str, Failure> {
    args.get(key).and_then(Json::as_str).ok_or_else(|| invalid(format!("{key} must be a string")))
}

fn opt_str<'a>(args: &'a Json, key: &str) -> Result<Option<&'a str>, Failure> {
    match args.get(key) {
        None => Ok(None),
        Some(_) => str_arg(args, key).map(Some),
    }
}

fn opt_int(args: &Json, key: &str) -> Result<Option<u64>, Failure> {
    match args.get(key) {
        None => Ok(None),
        Some(v) => v.as_safe_uint().map(Some).ok_or_else(|| invalid(format!("{key} must be a non-negative integer"))),
    }
}

fn opt_ms(args: &Json, key: &str) -> Result<Option<Duration>, Failure> {
    Ok(opt_int(args, key)?.map(Duration::from_millis))
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64, with padding.
fn b64(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let at = |i: usize| u32::from(c.get(i).copied().unwrap_or(0));
        let n = (at(0) << 16) | (at(1) << 8) | at(2);
        let sym = |shift: u32| char::from(B64[((n >> shift) & 63) as usize]);
        s.push(sym(18));
        s.push(sym(12));
        s.push(if c.len() > 1 { sym(6) } else { '=' });
        s.push(if c.len() > 2 { sym(0) } else { '=' });
    }
    s
}

/// Standard base64 with padding.
fn from_b64(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let pad = bytes.iter().rev().take_while(|c| **c == b'=').count();
    if pad > 2 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0;
    for &c in bytes.get(..bytes.len() - pad)? {
        let v = B64.iter().position(|x| *x == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn b64_arg(args: &Json, key: &str) -> Result<Vec<u8>, Failure> {
    from_b64(str_arg(args, key)?).ok_or_else(|| invalid(format!("{key} must be standard base64")))
}

fn timing_of(v: Option<&Json>) -> Result<Timing, Failure> {
    let mut t = Timing::default();
    let Some(v) = v else {
        return Ok(t);
    };
    if v.as_object().is_none() {
        return Err(invalid("timing must be an object"));
    }
    if let Some(d) = opt_ms(v, "handshakeTimeoutMs")? {
        t.handshake_timeout = d;
    }
    if let Some(d) = opt_ms(v, "rekeyIntervalMs")? {
        t.rekey_interval = d;
    }
    if let Some(n) = opt_int(v, "rekeyMessages")? {
        t.rekey_messages = n;
    }
    if let Some(d) = opt_ms(v, "retireGraceMs")? {
        t.retire_grace = d;
    }
    if let Some(d) = opt_ms(v, "idleMs")? {
        t.idle = d;
    }
    if let Some(d) = opt_ms(v, "backoffInitialMs")? {
        t.backoff_initial = d;
    }
    if let Some(d) = opt_ms(v, "backoffMaxMs")? {
        t.backoff_max = d;
    }
    if let Some(d) = opt_ms(v, "requestTimeoutMs")? {
        t.request_timeout = d;
    }
    Ok(t)
}

/// `size` bytes where byte i is (fill + i * 31) mod 256.
fn generated(size: usize, fill: u64) -> Vec<u8> {
    (0..size).map(|i| (fill.wrapping_add((i as u64).wrapping_mul(31)) & 0xff) as u8).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn obj(members: Vec<(&str, Json)>) -> Json {
    Json::object(members)
}

/// The body of a `message` event, and of each message `take` returns.
fn message_body(m: &InboundMessage) -> Vec<(&'static str, Json)> {
    let mut body = vec![
        ("from", Json::str(&m.from)),
        ("size", Json::int(m.bytes.len() as u64)),
        ("sha256", Json::str(hex(&Sha256::digest(&m.bytes)))),
    ];
    if m.bytes.len() <= 65536 {
        body.push(("bytes", Json::str(b64(&m.bytes))));
    }
    body
}

fn event(name: &str, body: Vec<(&str, Json)>) -> Json {
    let mut members = vec![("event".to_string(), Json::str(name))];
    members.extend(body.into_iter().map(|(k, v)| (k.to_string(), v)));
    Json::Object(members)
}

fn event_json(e: &Event) -> Json {
    match e {
        Event::State(s) => event("state", vec![("state", Json::str(s.as_str()))]),
        Event::Roster(r) => event("roster", vec![("roster", r.json().clone())]),
        Event::Disconnect { code, reason } => {
            event("disconnect", vec![("code", Json::int(u64::from(*code))), ("reason", Json::str(reason))])
        }
        Event::Moved { network } => event("moved", vec![("network", Json::str(network))]),
        Event::RelayError { code, message, .. } => event(
            "relayError",
            vec![("code", Json::str(code)), ("message", Json::str(message.clone().unwrap_or_default()))],
        ),
        Event::Paired { member, code_id, roster } => event(
            "paired",
            vec![
                ("node", Json::str(member.id())),
                ("codeId", Json::str(code_id)),
                ("version", Json::int(roster.version())),
            ],
        ),
        Event::PairingFailed { code_id, reason, .. } => {
            event("pairingFailed", vec![("codeId", Json::str(code_id)), ("reason", Json::str(reason.as_str()))])
        }
    }
}

fn traffic_json(t: &TrafficReport) -> Json {
    let dir = |d: &link_client::Traffic| {
        obj(vec![
            ("messages", Json::int(d.messages)),
            ("bytes", Json::int(d.bytes)),
            ("frames", Json::int(d.frames)),
            ("frameBytes", Json::int(d.frame_bytes)),
        ])
    };
    let peer = |p: &link_client::PeerTraffic| obj(vec![("sent", dir(&p.sent)), ("received", dir(&p.received))]);
    obj(vec![
        ("since", Json::int(t.since)),
        ("total", peer(&t.total)),
        ("relay", obj(vec![("sent", Json::int(t.relay.sent)), ("received", Json::int(t.relay.received))])),
        ("peers", Json::Object(t.peers.iter().map(|(id, p)| (id.clone(), peer(p))).collect())),
    ])
}

// ── The node ──

fn open(driver: &Arc<Driver>, args: &Json) -> Result<Node, Failure> {
    // Held throughout (nothing here waits), so two concurrent `connect`s cannot both start a node.
    let mut st = driver.lock();
    let identity = st.identity.clone().ok_or_else(|| invalid("no identity: send `identity` first"))?;
    if st.node.as_ref().is_some_and(|n| n.member().state() != MemberState::Closed) {
        return Err(invalid("a node is already running: `close` it first"));
    }
    let role = str_arg(args, "role")?;
    if role != "member" && role != "primary" {
        return Err(invalid("role must be member or primary"));
    }
    let roster =
        args.get("roster").filter(|r| r.as_object().is_some()).ok_or_else(|| invalid("roster must be an object"))?;
    let roster = Roster::from_json(roster.clone()).map_err(|_| invalid("the roster is not valid"))?;
    let network_seed: Option<[u8; 32]> = match args.get("networkSeed") {
        None => None,
        Some(_) => Some(b64_arg(args, "networkSeed")?.try_into().map_err(|_| invalid("networkSeed must be 32 bytes"))?),
    };
    let mut opts = MemberOptions::new(identity, roster);
    opts.pinned_network_key = opt_str(args, "pinnedNetworkKey")?.map(str::to_owned);
    opts.network_seed = network_seed;
    opts.relay_url = opt_str(args, "relayUrl")?.map(str::to_owned);
    opts.credit_window = opt_int(args, "creditWindow")?;
    opts.timing = timing_of(args.get("timing"))?;
    let auto_take = match args.get("autoTake") {
        None => true,
        Some(v) => v.as_bool().ok_or_else(|| invalid("autoTake must be a boolean"))?,
    };
    // Everything the node raises is queued for stdout the moment it happens, from its first
    // event on; the message bodies (a hash, some base64) are made by the writer.
    let out = driver.out.clone();
    opts.observer = Some(Arc::new(move |o: &Observed| {
        let _ = out.send(match o {
            Observed::Event(e) => Out::Line(event_json(e)),
            Observed::Message(m) => Out::Message(m.clone()),
            // Never given to a callback: only an `Observation` stream drops items.
            Observed::Lagged(_) => return,
        });
    }));
    let node = if role == "primary" { Node::Primary(Primary::new(opts)?) } else { Node::Member(Member::new(opts)?) };
    // With autoTake, taking at once is what credits each message back to its sender.
    if auto_take {
        let m = node.member().clone();
        tokio::spawn(async move { while m.recv().await.is_some() {} });
    }
    st.auto_take = auto_take;
    st.node = Some(node.clone());
    Ok(node)
}

// ── Commands ──

async fn command(driver: &Arc<Driver>, cmd: &str, args: &Json) -> Reply {
    match cmd {
        "identity" => {
            let identity = match args.get("seed") {
                None => Identity::generate(),
                Some(_) => {
                    let seed: [u8; 32] =
                        b64_arg(args, "seed")?.try_into().map_err(|_| invalid("seed must be 32 bytes"))?;
                    Identity::from_seed(&seed)
                }
            };
            let reply = obj(vec![
                ("seed", Json::str(b64(identity.seed()))),
                ("node", Json::str(identity.id())),
                ("ed25519", Json::str(link_client::wire::b64u(&identity.ed25519_public()))),
            ]);
            driver.lock().identity = Some(identity);
            Ok(reply)
        }
        "createNetwork" => {
            let (roster, key) =
                create_network(&driver.identity()?, str_arg(args, "relay")?, unix_ms()).map_err(invalid)?;
            Ok(obj(vec![("roster", roster.json().clone()), ("networkSeed", Json::str(b64(key.seed())))]))
        }
        "pair" => {
            let identity = driver.identity()?;
            let target = match args.get("link") {
                Some(_) => PairTarget::Link(str_arg(args, "link")?.to_owned()),
                None => PairTarget::Parts {
                    network: str_arg(args, "network")?.to_owned(),
                    code: str_arg(args, "code")?.to_owned(),
                    code_id: str_arg(args, "codeId")?.to_owned(),
                    relay: str_arg(args, "relay")?.to_owned(),
                },
            };
            let timeout = opt_ms(args, "timeoutMs")?;
            let r = pair(PairOptions { target, identity, timeout }).await?;
            Ok(obj(vec![("roster", r.roster.json().clone()), ("pinnedNetworkKey", Json::str(r.pinned_network_key))]))
        }
        "connect" => {
            let timeout = opt_ms(args, "timeoutMs")?;
            let node = open(driver, args)?;
            node.member().wait_connected(timeout).await?;
            Ok(obj(vec![]))
        }
        "start" => {
            open(driver, args)?;
            Ok(obj(vec![]))
        }
        "waitConnected" => {
            let timeout = opt_ms(args, "timeoutMs")?;
            driver.node()?.member().wait_connected(timeout).await?;
            Ok(obj(vec![]))
        }
        "state" => {
            let node = driver.node()?;
            let m = node.member();
            Ok(obj(vec![
                ("state", Json::str(m.state().as_str())),
                ("roster", m.roster().json().clone()),
                ("primary", Json::Bool(m.is_primary())),
            ]))
        }
        "sessions" => {
            let node = driver.node()?;
            let only = opt_str(args, "peer")?;
            let all = match only {
                Some(p) => node.member().session_info(p),
                None => node.member().sessions(),
            };
            let list = all
                .iter()
                .map(|s| {
                    obj(vec![
                        ("peer", Json::str(&s.peer)),
                        ("localIndex", Json::int(u64::from(s.local_index))),
                        ("remoteIndex", Json::int(u64::from(s.remote_index))),
                        ("initiator", Json::Bool(s.initiator)),
                        ("current", Json::Bool(s.current)),
                    ])
                })
                .collect();
            Ok(obj(vec![("sessions", Json::Array(list))]))
        }
        "send" => {
            let node = driver.node()?;
            let peer = str_arg(args, "peer")?;
            let bytes = match args.get("bytes") {
                Some(_) => b64_arg(args, "bytes")?,
                None => match (opt_int(args, "size")?, opt_int(args, "fill")?) {
                    (Some(size), Some(fill)) => {
                        // Bounded before allocating: the client refuses anything over 64 MiB anyway.
                        let size = usize::try_from(size).ok().filter(|s| *s <= link_client::MAX_MESSAGE);
                        generated(
                            size.ok_or_else(|| LinkError::new(ErrorCode::Invalid, "message exceeds 64 MiB"))?,
                            fill,
                        )
                    }
                    _ => return Err(invalid("send needs bytes, or size and fill")),
                },
            };
            node.member().send(peer, bytes).await?;
            Ok(obj(vec![]))
        }
        "take" => {
            let node = driver.node()?;
            if driver.lock().auto_take {
                return Err(invalid("take needs autoTake: false"));
            }
            let count = opt_int(args, "count")?.unwrap_or(1);
            let count = usize::try_from(count).map_err(|_| invalid("count is too large"))?;
            let timeout = opt_ms(args, "timeoutMs")?;
            let _turn = driver.takes.lock().await;
            let m = node.member();
            let taken = match timeout {
                Some(t) => match tokio::time::timeout(t, m.recv_many(count)).await {
                    Ok(r) => r?,
                    Err(_) => {
                        let ms = t.as_millis();
                        let message = format!("{} of {count} messages waiting after {ms} ms", m.waiting());
                        return Err(LinkError::new(ErrorCode::Timeout, message).into());
                    }
                },
                None => m.recv_many(count).await?,
            };
            Ok(obj(vec![("messages", Json::Array(taken.iter().map(|m| obj(message_body(m))).collect()))]))
        }
        "syncRoster" => {
            let node = driver.node()?;
            node.member().sync_roster().await?;
            Ok(obj(vec![("roster", node.member().roster().json().clone())]))
        }
        "resign" => {
            driver.node()?.member().resign().await?;
            Ok(obj(vec![]))
        }
        "traffic" => Ok(traffic_json(&driver.node()?.member().traffic())),
        "resetTraffic" => {
            driver.node()?.member().reset_traffic();
            Ok(obj(vec![]))
        }
        "openPairingCode" => {
            let p = driver.primary()?;
            let opts = link_client::CodeOptions {
                lifetime: opt_ms(args, "lifetimeMs")?,
                code: opt_str(args, "code")?.map(str::to_owned),
            };
            let c = p.open_pairing_code(opts)?;
            Ok(obj(vec![
                ("code", Json::str(c.code)),
                ("codeId", Json::str(c.code_id)),
                ("link", Json::str(c.link)),
                ("expiresAt", Json::int(c.expires_at)),
            ]))
        }
        "cancelPairingCode" => {
            driver.primary()?.cancel_pairing_code(str_arg(args, "codeId")?);
            Ok(obj(vec![]))
        }
        "revoke" => {
            let roster = driver.primary()?.revoke(str_arg(args, "node")?)?;
            Ok(obj(vec![("roster", roster.json().clone())]))
        }
        "usage" => {
            let u = driver.primary()?.usage().await?;
            let num = Json::float;
            let limits = obj(vec![
                ("rateBps", num(u.limits.rate_bps)),
                ("quotaBytesHour", num(u.limits.quota_bytes_hour)),
                ("trickleBps", num(u.limits.trickle_bps)),
            ]);
            Ok(obj(vec![(
                "network",
                obj(vec![
                    ("bytesHour", num(u.bytes_hour)),
                    ("connections", num(u.connections)),
                    ("limits", limits),
                    ("quotaUsed", num(u.quota_used)),
                    ("slowed", Json::Bool(u.slowed)),
                ]),
            )]))
        }
        "close" => {
            let node = driver.lock().node.clone();
            if let Some(n) = node {
                n.member().close();
            }
            Ok(obj(vec![]))
        }
        "exit" => Ok(obj(vec![])),
        other => Err(Failure { code: "internal", message: format!("unknown command {other}"), reason: None }),
    }
}

async fn run(driver: Arc<Driver>, line: String) {
    let Ok(msg) = Json::parse(&line) else {
        eprintln!("driver: not JSON: {line}");
        return;
    };
    let id = msg.get("id").filter(|v| v.as_f64().is_some_and(|n| n.is_finite() && n.fract() == 0.0)).cloned();
    let (Some(id), Some(cmd)) = (id, msg.get("cmd").and_then(Json::as_str)) else {
        eprintln!("driver: not a command: {line}");
        return;
    };
    let mut members: Vec<(String, Json)> = Vec::new();
    match command(&driver, cmd, &msg).await {
        Ok(result) => {
            // No result field is named `id`; written last all the same, the command's id wins.
            if let Json::Object(m) = result {
                members.extend(m.into_iter().filter(|(k, _)| k != "id" && k != "ok"));
            }
            members.push(("id".into(), id));
            members.push(("ok".into(), Json::Bool(true)));
        }
        Err(f) => {
            let mut error = vec![("code", Json::str(f.code)), ("message", Json::str(f.message))];
            if let Some(r) = f.reason {
                error.push(("reason", Json::int(u64::from(r))));
            }
            members.push(("id".into(), id));
            members.push(("ok".into(), Json::Bool(false)));
            members.push(("error".into(), obj(error)));
        }
    }
    driver.write(Json::Object(members));
    if cmd == "exit" {
        shutdown(&driver).await;
    }
}

/// Closes the node, lets stdout drain, and exits 0.
async fn shutdown(driver: &Driver) {
    let node = driver.lock().node.clone();
    if let Some(n) = node {
        n.member().close();
    }
    let (tx, rx) = oneshot::channel();
    let _ = driver.out.send(Out::Flush(tx));
    let _ = tokio::time::timeout(Duration::from_secs(5), rx).await;
    std::process::exit(0);
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let (tx, mut rx) = mpsc::unbounded_channel::<Out>();
    // One writer, in queue order, so every line reaches stdout whole and in order.
    tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(o) = rx.recv().await {
            let line = match o {
                Out::Line(j) => j,
                Out::Message(m) => event("message", message_body(&m)),
                Out::Flush(done) => {
                    let _ = stdout.flush().await;
                    let _ = done.send(());
                    continue;
                }
            };
            let Ok(mut text) = line.to_json_string() else {
                continue;
            };
            text.push('\n');
            if stdout.write_all(text.as_bytes()).await.is_err() {
                break;
            }
            let _ = stdout.flush().await;
        }
    });
    let driver = Arc::new(Driver {
        state: Mutex::new(State { identity: None, node: None, auto_take: true }),
        out: tx,
        takes: tokio::sync::Mutex::new(()),
    });
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    // Each command runs on its own: a slow one never holds up the next.
    while let Ok(Some(line)) = lines.next_line().await {
        if !line.trim().is_empty() {
            tokio::spawn(run(driver.clone(), line));
        }
    }
    shutdown(&driver).await;
}
