//! `Member` and `Primary`: the async face of the node core. A member owns one relay connection
//! (reconnecting with backoff), its sessions with the other members, the roster it holds, and
//! the application's message stream. Being primary is a trait of a member (section 3.1): it
//! comes and goes in place, the connection untouched.
//!
//! One task per member runs the core's timers and dials; one task per connection reads the
//! socket, and one writes it. The core itself is a synchronous state machine behind a mutex,
//! never held across an `.await`.

use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::StreamExt;
use tokio::sync::{Notify, broadcast, oneshot, watch};
use tokio_tungstenite::tungstenite::Message;

use crate::core::sessions::{Ctl, SessionInfo};
use crate::core::{Clock, Node, NodeConfig, Observation, Outputs, close_code, primary};
use crate::errors::LinkError;
use crate::identity::Identity;
use crate::roster::Roster;
use crate::signed::Resignation;
use crate::socket::{CLOSE_GRACE, close_info, connect, spawn_writer};
use crate::types::{
    DEFAULT_CREDIT_WINDOW, Event, InboundMessage, MemberState, Observer, PairingCode, Shaping, Timing, TrafficReport,
    UsageReport,
};

/// On close code 4009: where the network lives now (`None` keeps the current URL).
pub type ResolveRelay = Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = Option<String>> + Send>> + Send + Sync>;

/// How many events a subscriber may fall behind before it misses some (it is told how many).
const EVENT_CAPACITY: usize = 1024;

/// What a member needs. `MemberOptions::new(identity, roster)` takes the defaults for the rest.
#[derive(Clone)]
pub struct MemberOptions {
    pub identity: Identity,
    /// The newest roster this member holds (persist it from every `Event::Roster`).
    pub roster: Roster,
    /// Defaults to the roster's `relay`. A roster whose network is not placed yet has none (`""`):
    /// a member of it needs this, or it is not started (`Invalid`).
    pub relay_url: Option<String>,
    /// The network key pinned at pairing (b64u); defaults to the roster's `networkKey`.
    pub pinned_network_key: Option<String>,
    /// The network seed, when this node is to be the primary (section 3.1). It must derive the
    /// roster's `networkKey`. Its custody is the caller's: Link never stores, sends or deletes
    /// it. A node started with it whose roster names another member primary claims the network
    /// once registered.
    pub network_seed: Option<[u8; 32]>,
    /// The receive window granted each session: 1 MiB (the initial credit) up to 2^32 - 1.
    pub credit_window: Option<u64>,
    pub timing: Timing,
    pub resolve_relay: Option<ResolveRelay>,
    /// Called with every event and every arriving message, in order, as they happen, from the
    /// member's creation (see [`Observer`] for what it may do).
    pub observer: Option<Observer>,
}

impl MemberOptions {
    pub fn new(identity: Identity, roster: Roster) -> MemberOptions {
        MemberOptions {
            identity,
            roster,
            relay_url: None,
            pinned_network_key: None,
            network_seed: None,
            credit_window: None,
            timing: Timing::default(),
            resolve_relay: None,
            observer: None,
        }
    }
}

/// Every budget, interval and timeout of the core runs on `now_ms`, from `Instant` (monotonic: a
/// wall clock stepped back would otherwise strand budgets and hold back roster offers). The wall
/// clock is read only for what is signed or shown.
struct RealClock {
    start: Instant,
}

impl Clock for RealClock {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn unix_ms(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
}

struct Shared {
    core: Mutex<Node>,
    /// Wakes the member's task: a timer may have changed, a dial may be wanted, the socket drained.
    wake: Arc<Notify>,
    events: broadcast::Sender<Event>,
    /// Subscribed at creation and handed to the first `events()` caller, so it sees every event
    /// from the start, as listeners attached right after the TypeScript constructor do.
    first_events: Mutex<Option<broadcast::Receiver<Event>>>,
    state: watch::Receiver<MemberState>,
    rosters_seen: watch::Receiver<u64>,
    inbox: Arc<Notify>,
    resolver: Option<ResolveRelay>,
    timing: Timing,
    id: String,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Node> {
        // The core never panics while locked; if it ever did, its state is still the best there is.
        self.core.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Runs `f` on the core, then wakes the member's task.
    fn with<R>(&self, f: impl FnOnce(&mut Node) -> R) -> R {
        let r = f(&mut self.lock());
        self.wake.notify_one();
        r
    }
}

/// Closes the node when the last handle goes.
struct Handle {
    shared: Arc<Shared>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.shared.with(Node::close);
    }
}

/// A member of a network. Cheap to clone; the member closes when the last clone is dropped.
#[derive(Clone)]
pub struct Member {
    handle: Arc<Handle>,
}

impl std::fmt::Debug for Member {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Member").field("id", &self.shared().id).field("state", &self.state()).finish()
    }
}

impl Member {
    /// Creates the member and starts connecting; it returns at once. Must be called within a
    /// tokio runtime.
    pub fn new(opts: MemberOptions) -> Result<Member, LinkError> {
        Member::start(opts, false)
    }

    /// Creates a member and resolves once it is registered with the relay.
    pub async fn connect(opts: MemberOptions) -> Result<Member, LinkError> {
        let m = Member::new(opts)?;
        m.wait_connected(None).await?;
        Ok(m)
    }

    fn start(opts: MemberOptions, primary: bool) -> Result<Member, LinkError> {
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| LinkError::invalid("a member needs a tokio runtime"))?;
        let (events, first_events) = broadcast::channel(EVENT_CAPACITY);
        let (state_tx, state_rx) = watch::channel(MemberState::Disconnected);
        let (seen_tx, seen_rx) = watch::channel(0u64);
        let inbox = Arc::new(Notify::new());
        let id = opts.identity.id().to_owned();
        let node = Node::new(
            NodeConfig {
                identity: opts.identity,
                roster: opts.roster,
                pinned_network_key: opts.pinned_network_key,
                network_seed: opts.network_seed,
                relay_url: opts.relay_url,
                credit_window: opts.credit_window.unwrap_or(DEFAULT_CREDIT_WINDOW),
                timing: opts.timing,
                primary,
                has_resolver: opts.resolve_relay.is_some(),
                clock: Arc::new(RealClock { start: Instant::now() }),
                observer: opts.observer,
            },
            Outputs { events: events.clone(), state: state_tx, rosters_seen: seen_tx, inbox: inbox.clone() },
        )?;
        let shared = Arc::new(Shared {
            core: Mutex::new(node),
            wake: Arc::new(Notify::new()),
            events,
            first_events: Mutex::new(Some(first_events)),
            state: state_rx,
            rosters_seen: seen_rx,
            inbox,
            resolver: opts.resolve_relay,
            timing: opts.timing,
            id,
        });
        shared.with(Node::start);
        runtime.spawn(run(shared.clone()));
        Ok(Member { handle: Arc::new(Handle { shared }) })
    }

    fn shared(&self) -> &Shared {
        &self.handle.shared
    }

    pub fn id(&self) -> &str {
        &self.shared().id
    }

    /// The member's identity (its secret keys included), as it was given.
    pub fn identity(&self) -> Identity {
        self.shared().lock().identity.clone()
    }

    pub fn network(&self) -> String {
        self.shared().lock().network().to_owned()
    }

    /// A copy of the newest roster held.
    pub fn roster(&self) -> Roster {
        self.shared().lock().roster().clone()
    }

    pub fn state(&self) -> MemberState {
        *self.shared().state.borrow()
    }

    pub fn relay_url(&self) -> String {
        self.shared().lock().relay_url().to_owned()
    }

    /// Events in order. The first call returns every event since the member was created (its
    /// first `State(Connecting)` included); later calls, every event from then on. A subscriber
    /// that falls more than 1024 events behind is told how many it missed (`RecvError::Lagged`).
    pub fn events(&self) -> broadcast::Receiver<Event> {
        let first = self.shared().first_events.lock().unwrap_or_else(|e| e.into_inner()).take();
        first.unwrap_or_else(|| self.shared().events.subscribe())
    }

    /// Resolves when registered with the relay. Fails with `revoked`, `replaced` or `closed` if
    /// the member reaches a terminal state, and with `timeout` after `timeout` when given.
    pub async fn wait_connected(&self, timeout: Option<Duration>) -> Result<(), LinkError> {
        let mut rx = self.shared().state.clone();
        let wait = async move {
            loop {
                let s = *rx.borrow_and_update();
                match s {
                    MemberState::Connected => return Ok(()),
                    MemberState::Revoked => return Err(LinkError::revoked()),
                    MemberState::Replaced => return Err(LinkError::replaced()),
                    MemberState::Closed => return Err(LinkError::member_closed()),
                    _ => {}
                }
                if rx.changed().await.is_err() {
                    return Err(LinkError::member_closed());
                }
            }
        };
        match timeout {
            Some(t) => tokio::time::timeout(t, wait)
                .await
                .unwrap_or_else(|_| Err(LinkError::timeout("connecting to the relay"))),
            None => wait.await,
        }
    }

    /// Registered, or waits up to the handshake timeout for it.
    async fn online(&self) -> Result<(), LinkError> {
        match self.state() {
            MemberState::Revoked => Err(LinkError::revoked()),
            MemberState::Replaced => Err(LinkError::replaced()),
            MemberState::Closed => Err(LinkError::member_closed()),
            MemberState::Connected => Ok(()),
            _ => self.wait_connected(Some(self.shared().timing.handshake_timeout)).await,
        }
    }

    /// Sends one message (up to 64 MiB) to a member. Resolves once every fragment is handed to
    /// the relay connection: delivery is at most once. Fails with `unreachable`, `refused`,
    /// `revoked`, `replaced`, `timeout`, `closed` or `invalid`. Dropping the future does not
    /// withdraw a message already queued.
    pub async fn send(&self, peer: &str, bytes: impl Into<Bytes>) -> Result<(), LinkError> {
        let bytes = bytes.into();
        self.online().await?;
        let (tx, rx) = oneshot::channel();
        self.shared().with(|c| c.send(peer, bytes, tx));
        rx.await.unwrap_or_else(|_| Err(LinkError::member_closed()))
    }

    /// Takes the next message, whole and in order per sender, waiting for one. A message is
    /// credited back to its sender when taken, so a slow reader slows its senders. `None` once
    /// the member is terminal and nothing is left.
    pub async fn recv(&self) -> Option<InboundMessage> {
        loop {
            let notified = self.shared().inbox.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut core = self.shared().lock();
                if let Some(m) = core.take_message() {
                    drop(core);
                    self.shared().wake.notify_one();
                    return Some(m);
                }
                if core.is_terminal() {
                    return None;
                }
            }
            notified.await;
        }
    }

    /// Waits until `n` messages are waiting, then takes them all at once, oldest first (so a
    /// cancelled call takes nothing). Fails with `revoked`, `replaced` or `closed` if the member
    /// reaches that state while fewer than `n` wait.
    pub async fn recv_many(&self, n: usize) -> Result<Vec<InboundMessage>, LinkError> {
        loop {
            let notified = self.shared().inbox.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut core = self.shared().lock();
                if let Some(ms) = core.take_messages(n) {
                    drop(core);
                    self.shared().wake.notify_one();
                    return Ok(ms);
                }
                if core.is_terminal() {
                    return Err(match self.state() {
                        MemberState::Revoked => LinkError::revoked(),
                        MemberState::Replaced => LinkError::replaced(),
                        _ => LinkError::member_closed(),
                    });
                }
            }
            notified.await;
        }
    }

    /// Takes the next message if one is waiting.
    pub fn try_recv(&self) -> Option<InboundMessage> {
        self.shared().with(Node::take_message)
    }

    /// Messages delivered and not yet taken.
    pub fn waiting(&self) -> usize {
        self.shared().lock().waiting_messages()
    }

    /// Every event and every arriving message from now on, in one ordered stream. Observing a
    /// message does not take it: it stays for `recv`, and is credited back when taken. The
    /// stream holds at most 1024 items: past that it drops its oldest and says how many with
    /// [`Observed::Lagged`].
    pub fn observe(&self) -> Observation {
        self.shared().with(Node::observe)
    }

    /// How the relay shapes this network now, from its last `shaping` notice (section 9): the
    /// rate in force and whether the network is slowed. Unshaped before any notice.
    /// [`Event::Shaping`] says when it changes, so there is no need to poll `usage` for it.
    pub fn shaping(&self) -> Shaping {
        self.shared().lock().shaping()
    }

    /// Whether this member is the primary now: it holds the network seed, and the roster it
    /// holds names it primary (section 3.1).
    pub fn is_primary(&self) -> bool {
        self.shared().lock().is_primary()
    }

    /// Whether this member was given the network seed.
    pub fn holds_network_seed(&self) -> bool {
        self.shared().lock().holds_network_seed()
    }

    /// Opens a code that admits one node. Fails with
    /// `roster-full` when no further member fits under the roster limit, and `invalid` unless
    /// this member is the primary.
    pub fn open_pairing_code(&self, opts: CodeOptions) -> Result<PairingCode, LinkError> {
        let lifetime = opts.lifetime.map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        self.shared().with(|c| primary::open_pairing_code(c, lifetime, opts.code.as_deref()))
    }

    /// Withdraws an open code.
    pub fn cancel_pairing_code(&self, code_id: &str) {
        self.shared().with(|c| primary::cancel_pairing_code(c, code_id));
    }

    /// Removes a member and publishes the roster. Returns the new roster. Primary only.
    pub fn revoke(&self, node_id: &str) -> Result<Roster, LinkError> {
        self.shared().with(|c| primary::revoke(c, node_id))
    }

    /// Asks the relay for this network's usage. The relay allows one ask per `USAGE_INTERVAL`
    /// (10 s) per network, with no burst; an ask sooner than that it refuses at once, and this
    /// fails with `rate-limited`. Ask rarely, and keep the answer; whether the network is slowed
    /// is [`Member::shaping`], which needs no ask. Primary only.
    pub async fn usage(&self) -> Result<UsageReport, LinkError> {
        let id = crate::bytes::b64u(&crate::crypto::random_array::<9>());
        let (tx, rx) = oneshot::channel();
        self.shared().with(|c| primary::usage_begin(c, &id, tx));
        match self.online().await {
            Ok(()) => self.shared().with(|c| primary::usage_send(c, &id)),
            Err(e) => self.shared().with(|c| primary::usage_finish(c, &id, Err(e))),
        }
        rx.await.unwrap_or_else(|_| Err(LinkError::member_closed()))
    }

    /// The node id the roster held names primary.
    fn primary_id(&self) -> String {
        self.shared().lock().roster().primary_id().to_owned()
    }

    /// Asks the primary for its newest roster. True when a newer one was accepted.
    pub async fn sync_roster(&self) -> Result<bool, LinkError> {
        let (me, network) = (self.id().to_owned(), self.primary_id());
        if me == network {
            return Ok(false);
        }
        self.online().await?;
        let before = self.roster().version();
        let t = self.shared().timing.request_timeout;
        let deadline = later(t);
        let retry = (t / 4).max(Duration::from_millis(50));
        let mut seen = self.shared().rosters_seen.clone();
        seen.borrow_and_update();
        // Delivery is at most once (a request on a session the primary lost is answered with
        // reset), so the idempotent request is repeated until answered.
        loop {
            let (tx, rx) = oneshot::channel();
            self.shared().with(|c| c.send_control(&network, Ctl::RosterRequest, tx));
            let answered = async {
                let _ = rx.await;
                tokio::select! {
                    r = seen.changed() => r.is_ok(),
                    _ = tokio::time::sleep(retry) => false,
                }
            };
            match tokio::time::timeout_at(deadline, answered).await {
                Ok(true) => break,
                Ok(false) => continue,
                Err(_) => return Err(LinkError::timeout("roster request")),
            }
        }
        Ok(self.roster().version() > before)
    }

    /// Leaves the network: sends a signed resignation to the primary and resolves once the relay
    /// has closed this member (state `revoked`).
    pub async fn resign(&self) -> Result<(), LinkError> {
        let network = self.network();
        let primary = self.primary_id();
        if self.id() == primary || self.holds_network_seed() {
            return Err(LinkError::invalid("the primary cannot resign"));
        }
        self.online().await?;
        let r = {
            let core = self.shared().lock();
            Resignation::sign(&core.identity, &network, core.unix_now())
        };
        let json = r.to_json().to_json_string().map_err(|e| LinkError::invalid(e.to_string()))?;
        let t = self.shared().timing.request_timeout;
        let deadline = later(t);
        let retry = (t / 4).max(Duration::from_millis(50));
        let mut state = self.shared().state.clone();
        let revoked = async move {
            loop {
                if *state.borrow_and_update() == MemberState::Revoked {
                    return;
                }
                if state.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
            }
        };
        tokio::pin!(revoked);
        // Repeated until the relay closes this member, since delivery is at most once.
        loop {
            if self.state() == MemberState::Connected {
                let (tx, rx) = oneshot::channel();
                let to = self.primary_id();
                self.shared().with(|c| c.send_control(&to, Ctl::Resign(json.clone()), tx));
                tokio::select! {
                    _ = &mut revoked => return Ok(()),
                    _ = tokio::time::sleep_until(deadline) => return Err(LinkError::timeout("resigning")),
                    _ = async { let _ = rx.await; tokio::time::sleep(retry).await } => {}
                }
            } else {
                tokio::select! {
                    _ = &mut revoked => return Ok(()),
                    _ = tokio::time::sleep_until(deadline) => return Err(LinkError::timeout("resigning")),
                }
            }
        }
    }

    /// What this member sent and received, per peer and in total, since creation or
    /// `reset_traffic`.
    pub fn traffic(&self) -> TrafficReport {
        self.shared().lock().traffic()
    }

    pub fn reset_traffic(&self) {
        self.shared().with(Node::reset_traffic);
    }

    /// The live sessions with `peer`: indices, counters and credit. For tests and diagnostics.
    pub fn session_info(&self, peer: &str) -> Vec<SessionInfo> {
        self.shared().lock().sessions.info(peer)
    }

    /// The live sessions with every peer.
    pub fn sessions(&self) -> Vec<SessionInfo> {
        self.shared().lock().sessions.all_info()
    }

    /// Closes the member for good. Messages already delivered can still be taken.
    pub fn close(&self) {
        self.shared().with(Node::close);
    }
}

/// A member started as the primary: it holds the network seed and its roster names it primary.
/// Every capability is [`Member`]'s; the primary ones answer only while it is the primary.
#[derive(Clone, Debug)]
pub struct Primary {
    member: Member,
}

impl Deref for Primary {
    type Target = Member;

    fn deref(&self) -> &Member {
        &self.member
    }
}

/// Options for [`Member::open_pairing_code`].
#[derive(Clone, Debug, Default)]
pub struct CodeOptions {
    /// How long the code admits a node (15 minutes by default).
    pub lifetime: Option<Duration>,
    /// A chosen code instead of a random one: 8 Crockford characters. A word is easier to say
    /// and easier to guess; like every code it burns after five wrong confirmations.
    pub code: Option<String>,
}

impl Primary {
    /// Creates the primary and starts connecting. `opts.network_seed` must be given; if the
    /// roster names another member primary, this node claims the network once registered.
    pub fn new(opts: MemberOptions) -> Result<Primary, LinkError> {
        Ok(Primary { member: Member::start(opts, true)? })
    }

    /// Creates the primary and resolves once it is registered with the relay.
    pub async fn connect(opts: MemberOptions) -> Result<Primary, LinkError> {
        let p = Primary::new(opts)?;
        p.wait_connected(None).await?;
        Ok(p)
    }

    pub fn member(&self) -> &Member {
        &self.member
    }
}

// ── The member's tasks ──

async fn run(shared: Arc<Shared>) {
    loop {
        let (deadline, dial, resolve, terminal, now) = {
            let mut core = shared.lock();
            core.poll();
            (core.next_deadline(), core.take_dial(), core.take_resolve(), core.is_terminal(), core.now())
        };
        if let Some((conn_id, url)) = dial {
            tokio::spawn(connection(shared.clone(), conn_id, url));
        }
        if let Some(network) = resolve {
            let shared = shared.clone();
            match shared.resolver.clone() {
                Some(resolver) => {
                    tokio::spawn(async move {
                        let url = resolver(network).await;
                        shared.with(|c| c.on_resolved(url));
                    });
                }
                None => shared.with(|c| c.on_resolved(None)),
            }
        }
        if terminal {
            return;
        }
        let wait = deadline.map(|d| Duration::from_millis(d.saturating_sub(now)));
        match wait {
            Some(w) => {
                tokio::select! {
                    _ = tokio::time::sleep(w) => {}
                    _ = shared.wake.notified() => {}
                }
            }
            None => shared.wake.notified().await,
        }
    }
}

/// Now plus `t`, saturating far in the future rather than overflowing.
fn later(t: Duration) -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    now.checked_add(t).unwrap_or_else(|| now + Duration::from_secs(86400 * 365 * 30))
}

async fn sleep_until_opt(t: Option<tokio::time::Instant>) {
    match t {
        Some(t) => tokio::time::sleep_until(t).await,
        None => std::future::pending().await,
    }
}

/// One relay connection: dial, hand the core a writer, then feed it everything read.
async fn connection(shared: Arc<Shared>, conn_id: u64, url: String) {
    let ws = match connect(&url).await {
        Ok(ws) => ws,
        Err(_) => {
            shared.with(|c| c.on_close(conn_id, close_code::ABNORMAL, ""));
            return;
        }
    };
    let (sink, mut stream) = ws.split();
    let (wire, wire_shared, writer) = spawn_writer(sink, shared.wake.clone());
    if !shared.with(|c| c.on_open(conn_id, Box::new(wire))) {
        writer.abort();
        return;
    }
    let mut closed: Option<(u16, String)> = None;
    // Once this side has closed, the relay gets CLOSE_GRACE to finish the closing handshake.
    let mut deadline: Option<tokio::time::Instant> = None;
    loop {
        let next = tokio::select! {
            item = stream.next() => item,
            _ = wire_shared.closing.notified(), if deadline.is_none() => {
                if wire_shared.overflowed() {
                    // Nothing queued will be written: drop the socket now, writer and all.
                    writer.abort();
                    break;
                }
                deadline = Some(tokio::time::Instant::now() + CLOSE_GRACE);
                continue;
            }
            _ = sleep_until_opt(deadline) => break,
        };
        let Some(item) = next else {
            break;
        };
        match item {
            Ok(Message::Text(t)) => shared.with(|c| c.on_text(conn_id, t.as_str())),
            Ok(Message::Binary(b)) => shared.with(|c| c.on_binary(conn_id, &b)),
            // Read on after a close frame so the library completes the closing handshake.
            Ok(Message::Close(f)) => closed = Some(close_info(f)),
            Ok(_) => {}
            Err(_) => break,
        }
    }
    // The connection is over; a writer still waiting on the socket has nothing left to do.
    writer.abort();
    let (code, reason) = closed.unwrap_or((close_code::ABNORMAL, String::new()));
    shared.with(|c| c.on_close(conn_id, code, &reason));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cores_clock_is_monotonic_from_its_start_not_the_wall_clock() {
        let clock = RealClock { start: Instant::now() };
        let first = clock.now_ms();
        // Milliseconds since this clock began, not since 1970.
        assert!(first < 1000, "{first}");
        assert!(clock.unix_ms() > 1_600_000_000_000);
        std::thread::sleep(Duration::from_millis(20));
        let later = clock.now_ms();
        assert!(later >= first + 20 && later < 10_000, "{first} then {later}");
    }
}
