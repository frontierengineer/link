mod support;

use std::time::Duration;

use support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pair_and_talk() {
    let net = Net::start(&[], fast()).await;
    let alice = net.add(&[]).await;
    let bob = net.add(&[&alice]).await;
    alice.send(bob.id(), &b"hello"[..]).await.unwrap();
    let m = recv_within(&bob, Duration::from_secs(5)).await;
    assert_eq!(m.from, alice.id());
    assert_eq!(&m.bytes[..], b"hello");
    bob.send(alice.id(), &b"back"[..]).await.unwrap();
    assert_eq!(&recv_within(&alice, Duration::from_secs(5)).await.bytes[..], b"back");
    net.primary.send(alice.id(), &b"from the primary"[..]).await.unwrap();
    assert_eq!(&recv_within(&alice, Duration::from_secs(5)).await.bytes[..], b"from the primary");
}
