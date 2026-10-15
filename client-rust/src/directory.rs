//! Choosing a relay for a new network. A relay operator may publish a directory: regions, each
//! with a URL to time and a relay URL template over its shards. The primary times every region
//! once, when it creates the network, takes the closest, and hashes the network id onto one of
//! its shards. The URL that comes out goes into the roster (section 3) and the network keeps it:
//! the directory is consulted at creation only, never on reconnect.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use crate::crypto::sha256;
use crate::errors::{ErrorCode, LinkError};
use crate::json::Json;

/// The most shards a region may have.
pub const MAX_SHARDS: u32 = 0x10000;

/// A relay operator's list of regions (version 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayDirectory {
    pub version: u32,
    pub regions: Vec<DirectoryRegion>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryRegion {
    pub id: String,
    pub name: Option<String>,
    /// An http(s) URL to time: a GET answered quickly from the region (a relay's `/health`).
    pub probe: String,
    /// The relay URL, with `{shard}` where the shard goes (or none, for a region of one relay).
    pub relay: String,
    /// The region's shards (default 1); `{shard}` in its template is one of them, in lowercase
    /// hex. Each region has its own count, so one region can grow without touching the others; a
    /// change only affects networks created afterwards, since a network keeps the URL it was given.
    pub shards: Option<u32>,
    /// False: the region takes no new networks; those already on it are unaffected.
    pub accepting: bool,
}

/// The directory, or the URL to fetch it from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectorySource {
    Directory(RelayDirectory),
    Url(String),
}

impl From<RelayDirectory> for DirectorySource {
    fn from(d: RelayDirectory) -> DirectorySource {
        DirectorySource::Directory(d)
    }
}

impl From<String> for DirectorySource {
    fn from(url: String) -> DirectorySource {
        DirectorySource::Url(url)
    }
}

impl From<&str> for DirectorySource {
    fn from(url: &str) -> DirectorySource {
        DirectorySource::Url(url.to_owned())
    }
}

/// What a GET answered: its status and its whole body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Makes one GET of a URL and reads the whole body, or says why it failed. `pick_relay` bounds
/// each call with its timeout, dropping the future when time is up.
pub type Fetch =
    Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<FetchResponse, String>> + Send>> + Send + Sync>;

/// What `pick_relay` needs. `PickRelayOptions::new(network, directory)` takes the defaults for
/// the rest.
#[derive(Clone)]
pub struct PickRelayOptions {
    /// The new network's id (its primary's node id).
    pub network: String,
    pub directory: DirectorySource,
    /// Requests timed per region; the fastest counts. Default 3.
    pub probes: u32,
    /// How long a region has for all of its probes (and the directory for its fetch). Default 3 s.
    pub timeout: Duration,
    /// Makes the requests; `None` uses the client's own HTTP/1.1 GET (http:// and https://).
    pub fetch: Option<Fetch>,
}

impl PickRelayOptions {
    pub fn new(network: impl Into<String>, directory: impl Into<DirectorySource>) -> PickRelayOptions {
        PickRelayOptions {
            network: network.into(),
            directory: directory.into(),
            probes: 3,
            timeout: Duration::from_secs(3),
            fetch: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PickedRelay {
    /// The relay URL for the network's roster.
    pub url: String,
    pub region: String,
    pub shard: String,
    /// The region's fastest probe.
    pub rtt: Duration,
}

/// The shard a network belongs to among `shards`: the first four bytes of SHA-256 of its id,
/// big-endian, modulo `shards`, in lowercase hex padded to the width of `shards - 1` (two digits
/// for 256). Fails with `Invalid` unless `shards` is from 1 to [`MAX_SHARDS`].
pub fn shard_of(network: &str, shards: u32) -> Result<String, LinkError> {
    if !(1..=MAX_SHARDS).contains(&shards) {
        return Err(LinkError::invalid("shards must be an integer from 1 to 65536"));
    }
    let h = sha256(network.as_bytes());
    let n = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
    let width = format!("{:x}", shards - 1).len();
    Ok(format!("{:0width$x}", n % shards))
}

fn fail(why: impl std::fmt::Display) -> LinkError {
    LinkError::invalid(format!("relay directory: {why}"))
}

fn is_http_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

fn is_ws_url(s: &str) -> bool {
    s.starts_with("ws://") || s.starts_with("wss://")
}

/// A number that is a whole number from 1 to 65536 (as JSON.parse reads it: `2.0` is 2).
fn shard_count(n: f64) -> Option<u32> {
    (n.fract() == 0.0 && (1.0..=f64::from(MAX_SHARDS)).contains(&n)).then_some(n as u32)
}

/// Checks a directory's shape; fails with `Invalid` on anything it cannot use. Members this
/// version does not define are ignored.
pub fn parse_directory(value: &Json) -> Result<RelayDirectory, LinkError> {
    if value.as_object().is_none() {
        return Err(fail("not an object"));
    }
    if value.get("version").and_then(Json::as_f64) != Some(1.0) {
        return Err(fail("version is not 1"));
    }
    let list =
        value.get("regions").and_then(Json::as_array).filter(|l| !l.is_empty()).ok_or_else(|| fail("no regions"))?;
    let regions = list
        .iter()
        .enumerate()
        .map(|(i, r)| {
            if r.as_object().is_none() {
                return Err(fail(format!("region {i} is not an object")));
            }
            let id = r.get("id").and_then(Json::as_str).filter(|s| !s.is_empty());
            let id = id.ok_or_else(|| fail(format!("region {i} has no id")))?;
            let probe = r.get("probe").and_then(Json::as_str).filter(|s| is_http_url(s));
            let probe = probe.ok_or_else(|| fail(format!("region {id}: probe is not an http(s) URL")))?;
            let relay = r.get("relay").and_then(Json::as_str).filter(|s| is_ws_url(s));
            let relay = relay.ok_or_else(|| fail(format!("region {id}: relay is not a ws(s) URL")))?;
            let accepting = r.get("accepting").and_then(Json::as_bool);
            let accepting = accepting.ok_or_else(|| fail(format!("region {id}: accepting is not a boolean")))?;
            let shards = match r.get("shards") {
                None => None,
                Some(s) => Some(
                    s.as_f64()
                        .and_then(shard_count)
                        .ok_or_else(|| fail(format!("region {id}: shards is not an integer from 1 to 65536")))?,
                ),
            };
            Ok(DirectoryRegion {
                id: id.to_owned(),
                name: r.get("name").and_then(Json::as_str).map(str::to_owned),
                probe: probe.to_owned(),
                relay: relay.to_owned(),
                shards,
                accepting,
            })
        })
        .collect::<Result<_, _>>()?;
    Ok(RelayDirectory { version: 1, regions })
}

/// Applies `parse_directory`'s rules to a directory built in code.
fn check(d: &RelayDirectory) -> Result<(), LinkError> {
    if d.version != 1 {
        return Err(fail("version is not 1"));
    }
    if d.regions.is_empty() {
        return Err(fail("no regions"));
    }
    for (i, r) in d.regions.iter().enumerate() {
        if r.id.is_empty() {
            return Err(fail(format!("region {i} has no id")));
        }
        if !is_http_url(&r.probe) {
            return Err(fail(format!("region {}: probe is not an http(s) URL", r.id)));
        }
        if !is_ws_url(&r.relay) {
            return Err(fail(format!("region {}: relay is not a ws(s) URL", r.id)));
        }
        if r.shards.is_some_and(|s| !(1..=MAX_SHARDS).contains(&s)) {
            return Err(fail(format!("region {}: shards is not an integer from 1 to 65536", r.id)));
        }
    }
    Ok(())
}

/// Times every accepting region of the directory and returns the relay URL for the network in
/// the closest. Fails with `Unreachable` when no region answers in time (or the directory cannot
/// be fetched), and `Invalid` on a directory it cannot use; the caller then falls back to a
/// relay of its own choosing. Needs a tokio runtime with the time driver.
pub async fn pick_relay(opts: PickRelayOptions) -> Result<PickedRelay, LinkError> {
    let fetch =
        opts.fetch.unwrap_or_else(|| Arc::new(|url: String| Box::pin(async move { crate::http::get(&url).await })));
    let probes = opts.probes.max(1);
    let timeout = opts.timeout;
    let dir = match opts.directory {
        DirectorySource::Url(url) => {
            let unreachable =
                |why: String| LinkError::new(ErrorCode::Unreachable, format!("relay directory: {url} {why}"));
            let resp = match tokio::time::timeout(timeout, fetch(url.clone())).await {
                Ok(Ok(resp)) => resp,
                Ok(Err(e)) => return Err(unreachable(format!("failed: {e}"))),
                Err(_) => return Err(unreachable("timed out".into())),
            };
            if !(200..300).contains(&resp.status) {
                return Err(unreachable(format!("answered {}", resp.status)));
            }
            let text = std::str::from_utf8(&resp.body).map_err(|_| fail("not UTF-8"))?;
            parse_directory(&Json::parse(text).map_err(fail)?)?
        }
        DirectorySource::Directory(dir) => {
            check(&dir)?;
            dir
        }
    };

    let accepting: Vec<&DirectoryRegion> = dir.regions.iter().filter(|r| r.accepting).collect();
    let rtts = futures_util::future::join_all(accepting.iter().map(|r| time(&fetch, &r.probe, probes, timeout))).await;
    let pick = (0..accepting.len()).filter_map(|i| rtts[i].map(|rtt| (rtt, i))).min_by_key(|&(rtt, i)| (rtt, i));
    let Some((rtt, i)) = pick else {
        return Err(LinkError::new(ErrorCode::Unreachable, "relay directory: no accepting region answered"));
    };
    let region = accepting[i];
    let shard = shard_of(&opts.network, region.shards.unwrap_or(1))?;
    Ok(PickedRelay { url: region.relay.replace("{shard}", &shard), region: region.id.clone(), shard, rtt })
}

/// GETs `probe` up to `probes` times, one after another, all within `timeout`; the fastest 2xx
/// answer read to its end, if any came.
async fn time(fetch: &Fetch, probe: &str, probes: u32, timeout: Duration) -> Option<Duration> {
    let deadline = Instant::now() + timeout;
    let mut best: Option<Duration> = None;
    for _ in 0..probes {
        let t0 = Instant::now();
        match tokio::time::timeout_at(deadline, fetch(probe.to_owned())).await {
            Ok(Ok(resp)) => {
                let rtt = t0.elapsed();
                if (200..300).contains(&resp.status) && best.is_none_or(|b| rtt < b) {
                    best = Some(rtt);
                }
            }
            Ok(Err(_)) | Err(_) => break, // timed out or unreachable: what was measured stands
        }
    }
    best
}
