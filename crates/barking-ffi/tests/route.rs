//! Route of a message (path screen) and its hint (badges), over a local
//! test network.

mod common;

use barking_ffi::begin_link;
use barking_node::testing::{network, stop_all};
use common::{config, device};

#[tokio::test(flavor = "multi_thread")]
async fn message_route_lists_steps() {
    let nodes = network(0..3, |_| u64::MAX).await;
    let (id, addr) = (nodes[0].id.to_string(), nodes[0].addr.to_string());
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    tokio::task::spawn_blocking(move || {
        let alice = device(&da, 1, "Alice");
        let bob = device(&db, 2, "Bob");
        let fb = alice
            .add_contact_bytes(bob.contact_card_bytes().unwrap(), None)
            .unwrap();
        let fa = bob
            .add_contact_bytes(alice.contact_card_bytes().unwrap(), None)
            .unwrap();
        for d in [&alice, &bob] {
            d.add_node(id.clone(), addr.clone()).unwrap();
        }
        bob.sync(30_000).unwrap();
        alice.send_text(fb.clone(), "hello".into()).unwrap();
        let sent = alice.messages_with(fb.clone()).unwrap()[0].id;
        // Before any sync: sealed only, no relay yet.
        let route = alice.message_route(sent).unwrap();
        assert_eq!(route.len(), 1);
        assert_eq!(route[0].step, "sealed");
        assert!(route[0].size.unwrap() > 0);
        assert_eq!(route[0].device_name, None);
        assert!(!route[0].own);
        assert_eq!(alice.messages_with(fb.clone()).unwrap()[0].route, None);

        alice.sync(30_000).unwrap();
        bob.sync(30_000).unwrap();

        // Sender: sealed, then deposited on the node(s) responsible for
        // the mailbox; the hint counts them.
        let route = alice.message_route(sent).unwrap();
        assert_eq!(route[0].step, "sealed");
        assert!(
            route[1..].iter().all(|s| s.step == "deposited"),
            "{route:?}"
        );
        let relays = distinct_nodes(&route);
        assert!(!relays.is_empty());
        assert!(relays.iter().all(|n| n.len() == 8));
        assert_eq!(
            alice.messages_with(fb.clone()).unwrap()[0].route,
            Some(format!("internet:{}", relays.len()))
        );

        // Recipient: fetched from the node, then opened.
        let msg = bob.messages_with(fa.clone()).unwrap();
        let received = msg.iter().find(|m| !m.outgoing).unwrap();
        let route = bob.message_route(received.id).unwrap();
        let steps: Vec<&str> = route.iter().map(|s| s.step.as_str()).collect();
        assert_eq!(steps.last(), Some(&"opened"), "{route:?}");
        assert!(steps[..steps.len() - 1].iter().all(|s| *s == "fetched"));
        let relays = distinct_nodes(&route);
        assert!(!relays.is_empty(), "{route:?}");
        assert!(relays.iter().all(|n| n.len() == 8));
        let hint = Some(format!("internet:{}", relays.len()));
        assert_eq!(received.route, hint);
        let summary = bob.chat_summaries().unwrap();
        assert_eq!(summary[0].route, hint);

        // An unknown message has no route.
        assert!(bob.message_route(i64::MAX).unwrap().is_empty());
    })
    .await
    .unwrap();
    stop_all(nodes).await;
}

/// Alice (admin) with a linked tablet sends to Bob: the copy to the tablet
/// is the "other devices" step, never a relay towards Bob.
#[tokio::test(flavor = "multi_thread")]
async fn own_copies_are_not_relays_to_the_contact() {
    let nodes = network(0..3, |_| u64::MAX).await;
    let (id, addr) = (nodes[0].id.to_string(), nodes[0].addr.to_string());
    let dirs: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
    tokio::task::spawn_blocking(move || {
        let alice = device(&dirs[0], 1, "Alice");
        let bob = device(&dirs[1], 2, "Bob");
        let pending = begin_link(
            config(&dirs[2], 3),
            alice.link_offer().unwrap(),
            "tablet".into(),
        )
        .unwrap();
        let package = alice.link_device(pending.request, false).unwrap();
        pending.device.finish_link(package).unwrap();
        let tablet = pending.device;
        // Bob's card of Alice lists both devices.
        let fb = alice
            .add_contact_bytes(bob.contact_card_bytes().unwrap(), None)
            .unwrap();
        bob.add_contact_bytes(alice.contact_card_bytes().unwrap(), None)
            .unwrap();
        for d in [&alice, &bob, &tablet] {
            d.add_node(id.clone(), addr.clone()).unwrap();
        }
        bob.sync(30_000).unwrap();
        tablet.sync(30_000).unwrap();
        alice.send_text(fb.clone(), "hello".into()).unwrap();
        alice.sync(30_000).unwrap();
        let msg = alice.messages_with(fb).unwrap().pop().unwrap();
        let route = alice.message_route(msg.id).unwrap();
        let copy = route.iter().find(|s| s.step == "own_copy").unwrap();
        assert_eq!(copy.device_name.as_deref(), Some("tablet"));
        assert!(
            route.iter().any(|s| s.step == "deposited" && s.own),
            "{route:?}"
        );
        let mut to_bob: Vec<&str> = route
            .iter()
            .filter(|s| !s.own)
            .filter_map(|s| s.node.as_deref())
            .collect();
        to_bob.sort_unstable();
        to_bob.dedup();
        assert!(!to_bob.is_empty(), "{route:?}");
        assert_eq!(
            msg.route,
            Some(format!("internet:{}", to_bob.len())),
            "{route:?}"
        );
    })
    .await
    .unwrap();
    stop_all(nodes).await;
}

fn distinct_nodes(route: &[barking_ffi::RouteStepInfo]) -> Vec<String> {
    let mut nodes: Vec<String> = route.iter().filter_map(|s| s.node.clone()).collect();
    nodes.sort();
    nodes.dedup();
    nodes
}
