//! The one HTTP request the client makes: a GET of a relay directory or a region's probe, over
//! http:// or https:// (rustls, the webpki roots), HTTP/1.1 with the connection closed after the
//! response. Redirects are followed, as `fetch` follows them.

use std::sync::{Arc, OnceLock};

use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::{Host, Position, Url};

use crate::directory::{Fetch, FetchResponse};

/// A response (headers and body) larger than this fails; a directory is a few KiB.
const MAX_RESPONSE: usize = 1024 * 1024;
const MAX_REDIRECTS: usize = 5;

/// GETs `url` and reads the whole body.
pub(crate) async fn get(url: &str) -> Result<FetchResponse, String> {
    get_with(url, &connector()).await
}

/// This GET as a `Fetch`, trusting only `roots` (DER certificates) for https:// instead of the
/// webpki roots: for testing the TLS path against a local server.
#[doc(hidden)]
pub fn fetch_trusting(roots: &[Vec<u8>]) -> Result<Fetch, String> {
    let mut store = rustls::RootCertStore::empty();
    for der in roots {
        store.add(CertificateDer::from(der.clone())).map_err(|e| e.to_string())?;
    }
    let tls = TlsConnector::from(config(store));
    Ok(Arc::new(move |url: String| {
        let tls = tls.clone();
        Box::pin(async move { get_with(&url, &tls).await })
    }))
}

async fn get_with(url: &str, connector: &TlsConnector) -> Result<FetchResponse, String> {
    let mut url = Url::parse(url).map_err(|e| format!("not a URL: {e}"))?;
    for _ in 0..=MAX_REDIRECTS {
        let (response, location) = get_once(&url, connector).await?;
        match location {
            Some(to) if matches!(response.status, 301 | 302 | 303 | 307 | 308) => {
                url = url.join(&to).map_err(|e| format!("redirected to a bad URL: {e}"))?;
            }
            _ => return Ok(response),
        }
    }
    Err("too many redirects".into())
}

async fn get_once(url: &Url, connector: &TlsConnector) -> Result<(FetchResponse, Option<String>), String> {
    let tls = match url.scheme() {
        "http" => false,
        "https" => true,
        other => return Err(format!("not an http(s) URL: {other}")),
    };
    let host = match url.host() {
        Some(Host::Domain(d)) => d.to_owned(),
        Some(Host::Ipv4(a)) => a.to_string(),
        Some(Host::Ipv6(a)) => a.to_string(),
        None => return Err("the URL has no host".into()),
    };
    let port = url.port_or_known_default().unwrap_or(if tls { 443 } else { 80 });
    let authority = &url[Position::BeforeHost..Position::BeforePath];
    let target = &url[Position::BeforePath..Position::AfterQuery];
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: {authority}\r\nCache-Control: no-store\r\nConnection: close\r\n\
         User-Agent: link-client\r\n\r\n"
    );
    let tcp = TcpStream::connect((host.as_str(), port)).await.map_err(|e| e.to_string())?;
    if tls {
        let name = ServerName::try_from(host).map_err(|e| e.to_string())?;
        exchange(connector.connect(name, tcp).await.map_err(|e| e.to_string())?, &request).await
    } else {
        exchange(tcp, &request).await
    }
}

fn connector() -> TlsConnector {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let config =
        CONFIG.get_or_init(|| config(rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() }));
    TlsConnector::from(Arc::clone(config))
}

fn config(roots: rustls::RootCertStore) -> Arc<rustls::ClientConfig> {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

/// Sends the request and reads until the response is complete: its Content-Length, its last
/// chunk, or else the end of the connection.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    request: &str,
) -> Result<(FetchResponse, Option<String>), String> {
    stream.write_all(request.as_bytes()).await.map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = match stream.read(&mut chunk).await {
            Ok(n) => n,
            // A TLS peer that closes without close_notify: the end, if nothing else frames the body.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(e.to_string()),
        };
        buf.extend_from_slice(&chunk[..n]);
        if let Some(done) = complete(&buf, n == 0)? {
            return Ok(done);
        }
        if n == 0 {
            return Err("the connection closed mid-response".into());
        }
        if buf.len() > MAX_RESPONSE {
            return Err("the response is over 1 MiB".into());
        }
    }
}

/// The response in `buf` if it is complete (`eof`: nothing more will come).
fn complete(mut buf: &[u8], eof: bool) -> Result<Option<(FetchResponse, Option<String>)>, String> {
    loop {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut parsed = httparse::Response::new(&mut headers);
        let head = match parsed.parse(buf).map_err(|e| format!("bad response: {e}"))? {
            httparse::Status::Complete(n) => n,
            httparse::Status::Partial => return Ok(None),
        };
        let status = parsed.code.unwrap_or(0);
        if (100..200).contains(&status) {
            buf = &buf[head..]; // an interim response; the real one follows
            continue;
        }
        let header = |name: &str| {
            parsed.headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| String::from_utf8_lossy(h.value))
        };
        let location = header("location").map(|v| v.into_owned());
        let chunked = header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
        let length = header("content-length").map(|v| v.trim().parse::<usize>());
        let rest = &buf[head..];
        let body = if chunked {
            dechunk(rest)?
        } else if let Some(length) = length {
            let length = length.map_err(|_| "bad response: Content-Length is not a number")?;
            (rest.len() >= length).then(|| rest[..length].to_vec())
        } else if status == 204 || status == 304 {
            Some(Vec::new())
        } else {
            eof.then(|| rest.to_vec())
        };
        return Ok(body.map(|body| (FetchResponse { status, body }, location)));
    }
}

/// A chunked body, once its last chunk and trailers are in.
fn dechunk(mut rest: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let mut body = Vec::new();
    loop {
        let (start, size) = match httparse::parse_chunk_size(rest).map_err(|_| "bad response: bad chunk size")? {
            httparse::Status::Complete(v) => v,
            httparse::Status::Partial => return Ok(None),
        };
        rest = &rest[start..];
        if size == 0 {
            // Trailers, if any, end with an empty line.
            let done = rest.starts_with(b"\r\n") || rest.windows(4).any(|w| w == b"\r\n\r\n");
            return Ok(done.then_some(body));
        }
        let size = usize::try_from(size).ok().filter(|&s| s <= MAX_RESPONSE).ok_or("the response is over 1 MiB")?;
        if rest.len() < size + 2 {
            return Ok(None);
        }
        if &rest[size..size + 2] != b"\r\n" {
            return Err("bad response: a chunk does not end with CRLF".into());
        }
        body.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing() {
        let ok = |b: &[u8], eof| complete(b, eof).unwrap().map(|(r, l)| (r.status, r.body, l));
        assert_eq!(ok(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", false), Some((200, b"ok".to_vec(), None)));
        assert_eq!(ok(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nok", false), None);
        assert_eq!(ok(b"HTTP/1.1 200 OK\r\n\r\nuntil the end", false), None);
        assert_eq!(ok(b"HTTP/1.1 200 OK\r\n\r\nuntil the end", true), Some((200, b"until the end".to_vec(), None)));
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n3;x=y\r\n!!!\r\n0\r\n\r\n";
        assert_eq!(ok(chunked, false), Some((200, b"ok!!!".to_vec(), None)));
        assert_eq!(ok(&chunked[..chunked.len() - 2], false), None);
        let trailers = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\nX-T: 1\r\n\r\n";
        assert_eq!(ok(trailers, false), Some((200, b"a".to_vec(), None)));
        let interim = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(ok(interim, false), Some((404, Vec::new(), None)));
        let moved = b"HTTP/1.1 301 Moved\r\nLocation: /there\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(ok(moved, false), Some((301, Vec::new(), Some("/there".into()))));
        assert!(complete(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nokX\r\n", false).is_err());
        assert!(complete(b"nonsense\r\n\r\n", true).is_err());
    }
}
