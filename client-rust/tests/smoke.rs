mod support;

use std::time::Duration;

use link_client::*;
use support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pair_and_talk() {
    let net = Net::start(&[], fast()).await;
    let worker = net.add(MemberKind::Worker, &[]).await;
    let surface = net.add(MemberKind::Surface, &[&worker]).await;
    worker.send(surface.id(), &b"hello"[..]).await.unwrap();
    let m = recv_within(&surface, Duration::from_secs(5)).await;
    assert_eq!(m.from, worker.id());
    assert_eq!(&m.bytes[..], b"hello");
    surface.send(worker.id(), &b"back"[..]).await.unwrap();
    assert_eq!(&recv_within(&worker, Duration::from_secs(5)).await.bytes[..], b"back");
    net.primary.send(worker.id(), &b"from the primary"[..]).await.unwrap();
    assert_eq!(&recv_within(&worker, Duration::from_secs(5)).await.bytes[..], b"from the primary");
}
