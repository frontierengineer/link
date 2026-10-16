//! The client's own GET over https://: a local TLS server with a certificate made here, serving
//! a directory and its regions' probes, so the TLS path is driven end to end.

use std::sync::Arc;
use std::time::Duration;

use link_client::*;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const NETWORK: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaa"; // shard 49 of 256

fn cert() -> CertifiedKey<rcgen::KeyPair> {
    generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap()
}

/// Serves https://127.0.0.1:<port> with `cert` until the test ends; returns the port.
async fn serve(cert: &CertifiedKey<rcgen::KeyPair>) -> u16 {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let req = String::from_utf8_lossy(&req);
                let path = req.split(' ').nth(1).unwrap_or("");
                let directory = format!(
                    r#"{{"version":1,"regions":[
                      {{"id":"use1","probe":"https://127.0.0.1:{port}/use1/health","relay":"wss://{{shard}}.use1.test/v1","shards":256,"accepting":true}},
                      {{"id":"eu1","probe":"https://127.0.0.1:{port}/eu1/health","relay":"wss://{{shard}}.eu1.test/v1","shards":256,"accepting":true}}]}}"#
                );
                let response = match path {
                    "/v1/relays" => {
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{directory}", directory.len())
                    }
                    "/chunked" => {
                        let (a, b) = directory.split_at(directory.len() / 2);
                        format!(
                            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{a}\r\n{:x}\r\n{b}\r\n0\r\n\r\n",
                            a.len(),
                            b.len()
                        )
                    }
                    // No length: the body runs to the end, and the server drops the connection
                    // without close_notify.
                    "/until-closed" => format!("HTTP/1.1 200 OK\r\n\r\n{directory}"),
                    "/moved" => "HTTP/1.1 301 Moved\r\nLocation: /v1/relays\r\nContent-Length: 0\r\n\r\n".into(),
                    "/use1/health" => "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".into(),
                    "/eu1/health" => {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".into()
                    }
                    "/slow" => {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        return;
                    }
                    _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".into(),
                };
                let _ = tls.write_all(response.as_bytes()).await;
                if path == "/until-closed" {
                    let _ = tls.flush().await;
                    return; // dropped: no close_notify
                }
                let _ = tls.shutdown().await;
            });
        }
    });
    port
}

fn opts(fetch: Option<Fetch>, url: String, timeout_ms: u64) -> PickRelayOptions {
    PickRelayOptions { timeout: Duration::from_millis(timeout_ms), fetch, ..PickRelayOptions::new(NETWORK, url) }
}

#[tokio::test]
async fn fetches_and_probes_over_tls() {
    let cert = cert();
    let port = serve(&cert).await;
    let fetch = fetch_trusting(&[cert.cert.der().to_vec()]).unwrap();
    for path in ["/v1/relays", "/chunked", "/until-closed", "/moved"] {
        let picked = pick_relay(opts(Some(fetch.clone()), format!("https://127.0.0.1:{port}{path}"), 3000))
            .await
            .unwrap_or_else(|e| panic!("{path}: {e}"));
        assert_eq!(picked.region, "use1", "{path}");
        assert_eq!(picked.shard, "49", "{path}");
        assert_eq!(picked.url, "wss://49.use1.test/v1", "{path}");
    }
}

#[tokio::test]
async fn refuses_a_certificate_it_does_not_trust() {
    let cert = cert();
    let port = serve(&cert).await;
    let url = format!("https://127.0.0.1:{port}/v1/relays");
    // The default GET trusts the webpki roots, which did not sign this certificate.
    let err = pick_relay(opts(None, url.clone(), 3000)).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unreachable);
    assert!(err.to_string().contains("certificate"), "{err}");
    // Nor does a store holding some other certificate.
    let other = fetch_trusting(&[self::cert().cert.der().to_vec()]).unwrap();
    let err = pick_relay(opts(Some(other), url, 3000)).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unreachable);
    assert!(err.to_string().contains("certificate"), "{err}");
}

#[tokio::test]
async fn an_error_status_or_no_answer_is_unreachable() {
    let cert = cert();
    let port = serve(&cert).await;
    let fetch = fetch_trusting(&[cert.cert.der().to_vec()]).unwrap();
    let err =
        pick_relay(opts(Some(fetch.clone()), format!("https://127.0.0.1:{port}/missing"), 3000)).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unreachable);
    assert!(err.to_string().contains("answered 404"), "{err}");
    let err = pick_relay(opts(Some(fetch), format!("https://127.0.0.1:{port}/slow"), 300)).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unreachable);
    assert!(err.to_string().contains("timed out"), "{err}");
}

#[test]
fn refuses_roots_that_are_not_certificates() {
    assert!(fetch_trusting(&[b"not a certificate".to_vec()]).is_err());
}
