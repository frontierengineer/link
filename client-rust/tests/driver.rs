//! The driver binary against test/drivers/PROTOCOL.md: framing, replies, error codes, and the
//! order of events and replies. The cross-implementation suite in test/ drives it further.

mod support;

use std::process::Stdio;
use std::time::Duration;

use link_client::Json;
use support::Relay;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout};

struct D {
    child: Child,
    stdin: ChildStdin,
    lines: Lines<BufReader<ChildStdout>>,
    next: u64,
    /// Every line read, in order.
    seen: Vec<Json>,
}

impl D {
    fn start() -> D {
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_link-driver"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let lines = BufReader::new(child.stdout.take().unwrap()).lines();
        D { child, stdin, lines, next: 1, seen: Vec::new() }
    }

    async fn raw(&mut self, line: &str) {
        self.stdin.write_all(format!("{line}\n").as_bytes()).await.unwrap();
    }

    /// Sends a command and reads until its reply, keeping every line read.
    async fn call(&mut self, cmd: &str, args: Vec<(&str, Json)>) -> Json {
        let id = self.next;
        self.next += 1;
        let mut members = vec![("id", Json::int(id)), ("cmd", Json::str(cmd))];
        members.extend(args);
        self.raw(&Json::object(members).to_json_string().unwrap()).await;
        loop {
            let line =
                tokio::time::timeout(Duration::from_secs(20), self.lines.next_line()).await.unwrap().unwrap().unwrap();
            let j = Json::parse(&line).unwrap();
            self.seen.push(j.clone());
            if j.get("id").and_then(Json::as_safe_uint) == Some(id) {
                return j;
            }
        }
    }
}

fn s<'a>(j: &'a Json, k: &str) -> &'a str {
    j.get(k).and_then(Json::as_str).unwrap_or_default()
}

fn error_code(j: &Json) -> &str {
    j.get("error").map(|e| s(e, "code")).unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_driver_speaks_the_protocol() {
    let relay = Relay::start(&[]);
    let mut d = D::start();
    // Lines that are not commands get no reply.
    d.raw("not json").await;
    d.raw(r#"{"cmd":"identity"}"#).await;
    d.raw(r#"{"id":1.5,"cmd":"identity"}"#).await;
    let r = d.call("nonsense", vec![]).await;
    assert_eq!(d.seen.len(), 1, "the three lines before it got no reply: {:?}", d.seen);
    assert_eq!(error_code(&r), "internal");
    assert_eq!(r.get("ok"), Some(&Json::Bool(false)));
    assert_eq!(error_code(&d.call("state", vec![]).await), "invalid", "no node yet");
    assert_eq!(
        error_code(&d.call("createNetwork", vec![("relay", Json::str(&relay.url))]).await),
        "invalid",
        "no identity"
    );

    // A seed gives the identity the vectors give it.
    let r = d.call("identity", vec![("seed", Json::str("EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8="))]).await;
    assert_eq!(s(&r, "node"), "ixldtk3yi32p4qs53iko7652ae");
    assert_eq!(s(&r, "ed25519"), "xm-MHKl7MUYkDXPGAx3pZo-Tq19UXMIVmR71k8dWoZ8");
    assert_eq!(s(&r, "seed"), "EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8=");
    assert_eq!(r.get("ok"), Some(&Json::Bool(true)));
    let created = d.call("createNetwork", vec![("relay", Json::str(&relay.url))]).await;
    let roster = created.get("roster").unwrap().clone();
    assert_eq!(roster.get("version").and_then(Json::as_safe_uint), Some(1));
    let seed = created.get("networkSeed").unwrap().clone();
    assert_eq!(s(&created, "networkSeed").len(), 44, "32 bytes, standard base64");
    assert_ne!(s(&roster, "network"), "ixldtk3yi32p4qs53iko7652ae", "the network id is not the node id");
    let r = d.call("connect", vec![("role", Json::str("primary")), ("roster", roster.clone())]).await;
    assert_eq!(error_code(&r), "invalid", "a primary without the network seed");
    let wrong = Json::str("EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8=");
    let r = d
        .call("connect", vec![("role", Json::str("member")), ("roster", roster.clone()), ("networkSeed", wrong)])
        .await;
    assert_eq!(error_code(&r), "invalid", "a seed that does not derive the network key");

    // Events raised before a command completes are written before its reply.
    let before = d.seen.len();
    let r = d
        .call(
            "connect",
            vec![
                ("role", Json::str("primary")),
                ("roster", roster.clone()),
                ("networkSeed", seed.clone()),
                ("autoTake", Json::Bool(false)),
            ],
        )
        .await;
    assert_eq!(r.get("ok"), Some(&Json::Bool(true)), "{r:?}");
    let states: Vec<&str> =
        d.seen[before..].iter().filter(|j| s(j, "event") == "state").map(|j| s(j, "state")).collect();
    assert_eq!(states, ["connecting", "connected"]);
    assert_eq!(
        error_code(
            &d.call("connect", vec![("role", Json::str("primary")), ("roster", roster), ("networkSeed", seed.clone())])
                .await
        ),
        "invalid",
        "already running"
    );

    let st = d.call("state", vec![]).await;
    assert_eq!(st.get("primary"), Some(&Json::Bool(true)));
    let r = d.call("take", vec![("count", Json::int(1)), ("timeoutMs", Json::int(50))]).await;
    assert_eq!(error_code(&r), "timeout");
    let r = d.call("sessions", vec![]).await;
    assert_eq!(r.get("sessions"), Some(&Json::Array(vec![])));
    let r = d
        .call(
            "send",
            vec![("peer", Json::str("aaaaaaaaaaaaaaaaaaaaaaaaaa")), ("size", Json::int(10)), ("fill", Json::int(1))],
        )
        .await;
    assert_eq!(error_code(&r), "invalid", "not on the roster");
    let r = d.call("send", vec![("peer", Json::str("ixldtk3yi32p4qs53iko7652ae")), ("bytes", Json::str("AA="))]).await;
    assert_eq!(error_code(&r), "invalid", "not standard base64");
    let r = d.call("resign", vec![]).await;
    assert_eq!(error_code(&r), "invalid", "the primary cannot resign");
    let r = d.call("openPairingCode", vec![("code", Json::str("w0rd-c0de"))]).await;
    assert_eq!(s(&r, "code"), "W0RD-C0DE");
    let t = d.call("traffic", vec![]).await;
    assert!(t.get("relay").and_then(|r| r.get("received")).and_then(Json::as_safe_uint).unwrap() > 0);
    let r = d.call("usage", vec![]).await;
    assert_eq!(r.get("network").and_then(|n| n.get("connections")).and_then(Json::as_safe_uint), Some(1));
    let r = d.call("close", vec![]).await;
    assert_eq!(r.get("ok"), Some(&Json::Bool(true)));
    let r = d.call("exit", vec![]).await;
    assert_eq!(r.get("ok"), Some(&Json::Bool(true)));
    let status = tokio::time::timeout(Duration::from_secs(10), d.child.wait()).await.unwrap().unwrap();
    assert!(status.success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_driver_exits_0_when_stdin_closes() {
    let mut d = D::start();
    d.call("identity", vec![]).await;
    drop(d.stdin);
    let status = tokio::time::timeout(Duration::from_secs(10), d.child.wait()).await.unwrap().unwrap();
    assert!(status.success());
}

/// Reads lines until `pred` holds for one, keeping every line read.
async fn until_line(d: &mut D, pred: impl Fn(&Json) -> bool) -> Json {
    loop {
        let line = tokio::time::timeout(Duration::from_secs(20), d.lines.next_line()).await.unwrap().unwrap().unwrap();
        let j = Json::parse(&line).unwrap();
        d.seen.push(j.clone());
        if pred(&j) {
            return j;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_driver_started_with_the_network_seed_claims_the_network() {
    let relay = Relay::start(&[]);
    let (mut p, mut w) = (D::start(), D::start());
    p.call("identity", vec![]).await;
    w.call("identity", vec![]).await;
    let created = p.call("createNetwork", vec![("relay", Json::str(&relay.url))]).await;
    let seed = created.get("networkSeed").unwrap().clone();
    let r = p
        .call(
            "connect",
            vec![
                ("role", Json::str("primary")),
                ("roster", created.get("roster").unwrap().clone()),
                ("networkSeed", seed.clone()),
            ],
        )
        .await;
    assert_eq!(r.get("ok"), Some(&Json::Bool(true)), "{r:?}");
    let code = p.call("openPairingCode", vec![]).await;
    assert!(code.get("kind").is_none(), "codes carry no kind");
    let paired = w.call("pair", vec![("link", Json::str(s(&code, "link")))]).await;
    let roster = paired.get("roster").unwrap().clone();
    let roster_before = roster.clone();
    assert_eq!(s(&paired, "pinnedNetworkKey"), s(&roster, "networkKey"));
    let version = roster.get("version").and_then(Json::as_safe_uint).unwrap();
    // The second driver starts with the first's network seed, under a roster naming the first
    // primary: it claims once registered.
    let before = p.seen.len();
    let r = w
        .call("connect", vec![("role", Json::str("primary")), ("roster", roster), ("networkSeed", seed.clone())])
        .await;
    assert_eq!(r.get("ok"), Some(&Json::Bool(true)), "{r:?}");
    let claimed = until_line(&mut p, |j| {
        s(j, "event") == "roster"
            && j.get("roster").and_then(|r| r.get("version")).and_then(Json::as_safe_uint) == Some(version + 1)
    })
    .await;
    let ws = w.call("state", vec![]).await;
    assert_eq!(ws.get("primary"), Some(&Json::Bool(true)));
    // The claimed roster names the second driver's node primary.
    let new_primary = s(claimed.get("roster").unwrap(), "primary").to_owned();
    assert_eq!(s(ws.get("roster").unwrap(), "primary"), new_primary);
    assert_ne!(new_primary, s(&roster_before, "primary"));
    // The first is no longer the primary, in place: no disconnect, still connected, its
    // primary-only commands refused.
    assert!(
        !p.seen[before..].iter().any(|j| s(j, "event") == "disconnect" || s(j, "event") == "state"),
        "no disconnect: {:?}",
        &p.seen[before..]
    );
    let ps = p.call("state", vec![]).await;
    assert_eq!(s(&ps, "state"), "connected");
    assert_eq!(ps.get("primary"), Some(&Json::Bool(false)));
    assert_eq!(ps.get("networkSeed"), None, "the driver keeps no seed store");
    assert_eq!(error_code(&p.call("openPairingCode", vec![]).await), "invalid");
    assert_eq!(error_code(&p.call("usage", vec![]).await), "invalid");
    assert!(w.call("openPairingCode", vec![]).await.get("code").is_some());
}
