//! Choosing a relay from a directory: the shard hash, the directory's shape, and picking the
//! closest accepting region.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use link_client::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn shard_of_hashes_the_id_onto_the_shards() {
    assert_eq!(shard_of("aaaaaaaaaaaaaaaaaaaaaaaaaa", 256).unwrap(), "49");
    assert_eq!(shard_of("7k3q2m8x4v9b1n6c5z0wtrpyhd", 256).unwrap(), "61");
    assert_eq!(shard_of("7k3q2m8x4v9b1n6c5z0wtrpyhd", 16).unwrap(), "1");
    assert_eq!(shard_of("7k3q2m8x4v9b1n6c5z0wtrpyhd", 4096).unwrap(), "d61");
    assert_eq!(shard_of("x", 1).unwrap(), "0");
    assert_eq!(shard_of("x", 0).unwrap_err().code(), ErrorCode::Invalid);
    assert_eq!(shard_of("x", 0x10001).unwrap_err().code(), ErrorCode::Invalid);
}

fn region(id: &str, probe: &str, relay: &str, shards: Option<u32>, accepting: bool) -> DirectoryRegion {
    DirectoryRegion { id: id.into(), name: None, probe: probe.into(), relay: relay.into(), shards, accepting }
}

fn dir() -> RelayDirectory {
    RelayDirectory {
        version: 1,
        regions: vec![
            region("use1", "https://use1.test/health", "wss://{shard}.use1.test/v1", Some(256), true),
            region("eu1", "https://eu1.test/health", "wss://{shard}.eu1.test/v1", Some(256), true),
            region("ap1", "https://ap1.test/health", "wss://{shard}.ap1.test/v1", Some(16), false),
            region("down", "https://down.test/health", "wss://down.test/v1", None, true),
        ],
    }
}

/// A fetch where each probe host takes its next delay, in real ms; any other host never answers.
struct FakeNet {
    calls: Arc<Mutex<Vec<String>>>,
    fetch: Fetch,
}

fn fake_net(delays: &[(&str, &[u64])]) -> FakeNet {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let queues: HashMap<String, Vec<u64>> = delays.iter().map(|(h, d)| (h.to_string(), d.to_vec())).collect();
    let queues = Arc::new(Mutex::new(queues));
    let log = calls.clone();
    let fetch: Fetch = Arc::new(move |url: String| {
        log.lock().unwrap().push(url.clone());
        let host = url::Url::parse(&url).unwrap().host_str().unwrap().to_owned();
        let delay = queues.lock().unwrap().get_mut(&host).filter(|q| !q.is_empty()).map(|q| q.remove(0));
        Box::pin(async move {
            let Some(ms) = delay else { return std::future::pending().await };
            tokio::time::sleep(Duration::from_millis(ms)).await;
            Ok(FetchResponse { status: 200, body: b"ok".to_vec() })
        })
    });
    FakeNet { calls, fetch }
}

fn opts(network: &str, directory: impl Into<DirectorySource>, net: &FakeNet, timeout_ms: u64) -> PickRelayOptions {
    PickRelayOptions {
        fetch: Some(net.fetch.clone()),
        timeout: Duration::from_millis(timeout_ms),
        ..PickRelayOptions::new(network, directory)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn picks_the_fastest_accepting_region_and_its_shard() {
    let net = fake_net(&[("use1.test", &[150, 120, 130]), ("eu1.test", &[60, 20, 25])]);
    let got = pick_relay(opts("7k3q2m8x4v9b1n6c5z0wtrpyhd", dir(), &net, 1000)).await.unwrap();
    assert_eq!((got.url.as_str(), got.region.as_str(), got.shard.as_str()), ("wss://61.eu1.test/v1", "eu1", "61"));
    assert!(
        got.rtt >= Duration::from_millis(19) && got.rtt < Duration::from_millis(60),
        "the fastest probe counts: {:?}",
        got.rtt
    );
    assert!(!net.calls.lock().unwrap().iter().any(|u| u.contains("ap1")), "a region not accepting is not timed");
}

/// A tiny HTTP/1.1 server: the directory behind a redirect, sent chunked; two probes that take
/// their region's time; 404 for anything else.
async fn serve(directory: impl Fn(u16) -> String + Send + Sync + 'static) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let directory = Arc::new(directory);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let directory = directory.clone();
            tokio::spawn(async move {
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let line = String::from_utf8_lossy(&req).lines().next().unwrap_or("").to_owned();
                let path = line.split(' ').nth(1).unwrap_or("");
                let resp = match path {
                    "/v1/relays" => {
                        "HTTP/1.1 302 Found\r\nLocation: /v1/relays.json\r\nContent-Length: 0\r\n\r\n".into()
                    }
                    "/v1/relays.json" => {
                        let body = directory(port);
                        let (a, b) = body.split_at(body.len() / 2);
                        format!(
                            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{a}\r\n{:x}\r\n{b}\r\n0\r\n\r\n",
                            a.len(),
                            b.len()
                        )
                    }
                    "/use1/health" | "/eu1/health" => {
                        let ms = if path.starts_with("/use1") { 5 } else { 80 };
                        tokio::time::sleep(Duration::from_millis(ms)).await;
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".into()
                    }
                    _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_owned(),
                };
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fetches_the_directory_from_a_url() {
    // The client's own HTTP GET against a real server.
    let port = serve(|port| {
        format!(
            r#"{{"version":1,"regions":[
              {{"id":"use1","probe":"http://127.0.0.1:{port}/use1/health","relay":"wss://{{shard}}.use1.test/v1","shards":256,"accepting":true}},
              {{"id":"eu1","probe":"http://127.0.0.1:{port}/eu1/health","relay":"wss://{{shard}}.eu1.test/v1","shards":256,"accepting":true}}]}}"#
        )
    })
    .await;
    let o = PickRelayOptions {
        timeout: Duration::from_secs(2),
        ..PickRelayOptions::new("aaaaaaaaaaaaaaaaaaaaaaaaaa", format!("http://127.0.0.1:{port}/v1/relays"))
    };
    let got = pick_relay(o).await.unwrap();
    assert_eq!(got.url, "wss://49.use1.test/v1");
    assert_eq!(got.region, "use1");

    let missing = PickRelayOptions::new("x", format!("http://127.0.0.1:{port}/missing"));
    let e = pick_relay(missing).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::Unreachable);
    assert!(e.message().contains("answered 404"), "{e}");

    // Through an injected fetch, as the TypeScript test does it.
    let net = fake_net(&[("use1.test", &[5, 5, 5]), ("eu1.test", &[80, 80, 80])]);
    let inner = net.fetch.clone();
    let text = r#"{"version":1,"regions":[
      {"id":"use1","probe":"https://use1.test/health","relay":"wss://{shard}.use1.test/v1","shards":256,"accepting":true},
      {"id":"eu1","probe":"https://eu1.test/health","relay":"wss://{shard}.eu1.test/v1","shards":256,"accepting":true}]}"#;
    let fetch: Fetch = Arc::new(move |url: String| {
        if url == "https://relays.test/v1/relays" {
            Box::pin(async move { Ok(FetchResponse { status: 200, body: text.as_bytes().to_vec() }) })
        } else {
            inner(url)
        }
    });
    let o = PickRelayOptions {
        fetch: Some(fetch),
        timeout: Duration::from_secs(1),
        ..PickRelayOptions::new("aaaaaaaaaaaaaaaaaaaaaaaaaa", "https://relays.test/v1/relays")
    };
    assert_eq!(pick_relay(o).await.unwrap().url, "wss://49.use1.test/v1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_region_hashes_over_its_own_shard_count() {
    let base = dir();
    let mut grown = RelayDirectory { version: 1, regions: vec![base.regions[1].clone(), base.regions[2].clone()] };
    grown.regions[0].shards = Some(4096);
    grown.regions[1].accepting = true;
    let near = fake_net(&[("eu1.test", &[5, 5, 5]), ("ap1.test", &[80, 80, 80])]);
    let got = pick_relay(opts("7k3q2m8x4v9b1n6c5z0wtrpyhd", grown.clone(), &near, 1000)).await.unwrap();
    assert_eq!(got.url, "wss://d61.eu1.test/v1");
    let far = fake_net(&[("eu1.test", &[80, 80, 80]), ("ap1.test", &[5, 5, 5])]);
    let got = pick_relay(opts("7k3q2m8x4v9b1n6c5z0wtrpyhd", grown, &far, 1000)).await.unwrap();
    assert_eq!(got.url, "wss://1.ap1.test/v1");

    let single = RelayDirectory {
        version: 1,
        regions: vec![region("one", "https://use1.test/health", "wss://relay.test/v1", None, true)],
    };
    let n = fake_net(&[("use1.test", &[1, 1, 1])]);
    let got = pick_relay(PickRelayOptions { fetch: Some(n.fetch.clone()), ..PickRelayOptions::new("x", single) })
        .await
        .unwrap();
    assert_eq!(
        PickedRelay { rtt: Duration::ZERO, ..got },
        PickedRelay { url: "wss://relay.test/v1".into(), region: "one".into(), shard: "0".into(), rtt: Duration::ZERO }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fails_when_no_accepting_region_answers() {
    let net = fake_net(&[]);
    let base = dir();
    let only = RelayDirectory { version: 1, regions: vec![base.regions[3].clone(), base.regions[2].clone()] };
    let t0 = Instant::now();
    let e = pick_relay(opts("x", only, &net, 50)).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::Unreachable);
    assert!(e.message().contains("no accepting region"), "{e}");
    assert!(t0.elapsed() < Duration::from_secs(2), "a region that never answers is cut off: {:?}", t0.elapsed());
    assert!(!net.calls.lock().unwrap().iter().any(|u| u.contains("ap1")));
}

#[test]
fn pick_relay_is_send() {
    fn send<T: Send>(_: T) {}
    send(pick_relay(PickRelayOptions::new("x", dir())));
}

fn to_json(d: &RelayDirectory) -> Json {
    let region = |r: &DirectoryRegion| {
        let mut m = vec![
            ("id".to_owned(), Json::String(r.id.clone())),
            ("probe".to_owned(), Json::String(r.probe.clone())),
            ("relay".to_owned(), Json::String(r.relay.clone())),
        ];
        if let Some(s) = r.shards {
            m.push(("shards".to_owned(), Json::Number(f64::from(s), true)));
        }
        m.push(("accepting".to_owned(), Json::Bool(r.accepting)));
        Json::Object(m)
    };
    Json::Object(vec![
        ("version".to_owned(), Json::Number(f64::from(d.version), true)),
        ("regions".to_owned(), Json::Array(d.regions.iter().map(region).collect())),
    ])
}

/// The directory with its first region alone, `key` set to `value` in it.
fn with(key: &str, value: Json) -> Json {
    let Json::Object(mut top) = to_json(&dir()) else { unreachable!() };
    let Json::Array(regions) = &top[1].1 else { unreachable!() };
    let Json::Object(mut r) = regions[0].clone() else { unreachable!() };
    r.retain(|(k, _)| k != key);
    r.push((key.to_owned(), value));
    top[1].1 = Json::Array(vec![Json::Object(r)]);
    Json::Object(top)
}

#[test]
fn parse_directory_refuses_what_it_cannot_use() {
    let good = to_json(&dir());
    let Json::Object(mut v2) = good.clone() else { unreachable!() };
    v2[0].1 = Json::Number(2.0, true);
    let bad = [
        Json::Null,
        Json::Array(vec![]),
        Json::Object(v2),
        with("shards", Json::Number(0.0, true)),
        with("shards", Json::Number(1.5, false)),
        with("shards", Json::Number(65537.0, true)),
        with("shards", Json::Null),
        Json::parse(r#"{"version":1,"regions":[]}"#).unwrap(),
        Json::parse(r#"{"version":1,"regions":[7]}"#).unwrap(),
        with("probe", Json::String("ftp://x".into())),
        with("relay", Json::String("https://x".into())),
        with("accepting", Json::String("yes".into())),
        with("id", Json::String(String::new())),
    ];
    for d in &bad {
        let e = parse_directory(d).expect_err(&d.to_json_string().unwrap());
        assert_eq!(e.code(), ErrorCode::Invalid);
    }
    assert_eq!(parse_directory(&good).unwrap(), dir());

    // Members this version does not define are ignored; a whole number written with a fraction
    // is still that number, as JSON.parse reads it.
    let extra = Json::parse(
        r#"{"version":1,"regions":[{"id":"a","name":"A","probe":"http://a/h","relay":"ws://a","shards":2.0,"accepting":false,"weight":3}],"x":1}"#,
    )
    .unwrap();
    let want = DirectoryRegion { name: Some("A".into()), ..region("a", "http://a/h", "ws://a", Some(2), false) };
    assert_eq!(parse_directory(&extra).unwrap(), RelayDirectory { version: 1, regions: vec![want] });
}

#[tokio::test]
async fn a_directory_built_in_code_is_held_to_the_same_rules() {
    let mut broken = dir();
    broken.regions[0].relay = "https://x".into();
    let net = fake_net(&[]);
    assert_eq!(pick_relay(opts("x", broken, &net, 1000)).await.unwrap_err().code(), ErrorCode::Invalid);
    let mut zero = dir();
    zero.regions[0].shards = Some(0);
    assert_eq!(pick_relay(opts("x", zero, &net, 1000)).await.unwrap_err().code(), ErrorCode::Invalid);
}
