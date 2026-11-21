//! Replies and reactions through the FFI: the quote under a reply, the chips
//! under a message, typed errors, and what a reaction never does (count as
//! unread, become the last message of a chat).

mod common;

use std::sync::Arc;

use barking_core::Core;
use barking_core::store::{Direction, MessageId, MessageInsert, MessageStatus, Queries, Store};
use barking_ffi::{BarkingError, DeliveryState, Device, Quote, ReactionChip, excerpt};
use barking_node::testing::{TestNode, network, stop_all, wait_packets};
use common::device;

/// Alice holds Bob's card and the other way round; no network: nothing here
/// reaches the other device. Returns both devices and each one's view of the
/// other (`alice` knows `fb`, `bob` knows `fa`).
fn paired(
    da: &tempfile::TempDir,
    db: &tempfile::TempDir,
) -> (Arc<Device>, Arc<Device>, String, String) {
    let alice = device(da, 1, "Alice");
    let bob = device(db, 2, "Bob");
    let fb = alice
        .add_contact_bytes(bob.contact_card_bytes().unwrap(), None)
        .unwrap();
    let fa = bob
        .add_contact_bytes(alice.contact_card_bytes().unwrap(), None)
        .unwrap();
    (alice, bob, fb, fa)
}

fn row_of(d: &Device, contact: &str, body: &str) -> i64 {
    d.messages_with(contact.to_owned())
        .unwrap()
        .into_iter()
        .find(|m| m.body == body)
        .unwrap()
        .id
}

/// A blocking device call, off the async test's thread.
async fn step<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.unwrap()
}

/// Waits for the deposits to reach every node (replication), so that the
/// next reader gets everything from the one node it asks.
async fn settle(nodes: &[TestNode]) {
    let most = nodes.iter().map(TestNode::stored_packets).max().unwrap();
    wait_packets(nodes, most).await;
}

struct Pair {
    nodes: Vec<TestNode>,
    alice: Arc<Device>,
    bob: Arc<Device>,
    /// Bob, as Alice knows him.
    fb: String,
    /// Alice, as Bob knows her.
    fa: String,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

/// Alice and Bob over a local test network, both knowing a node.
async fn on_network() -> Pair {
    let nodes = network(0..3, |_| u64::MAX).await;
    let (id, addr) = (nodes[0].id.to_string(), nodes[0].addr.to_string());
    let dirs = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, bob, fb, fa, dirs) = step(move || {
        let (da, db) = &dirs;
        let a = device(da, 1, "Alice");
        let b = device(db, 2, "Bob");
        let fb = a
            .add_contact_bytes(b.contact_card_bytes().unwrap(), None)
            .unwrap();
        let fa = b
            .add_contact_bytes(a.contact_card_bytes().unwrap(), None)
            .unwrap();
        for d in [&a, &b] {
            d.add_node(id.clone(), addr.clone()).unwrap();
        }
        b.sync(30_000).unwrap();
        (a, b, fb, fa, dirs)
    })
    .await;
    Pair {
        nodes,
        alice,
        bob,
        fb,
        fa,
        _dirs: dirs,
    }
}

#[test]
fn excerpt_cuts_by_char() {
    assert_eq!(excerpt("ééé", 2), "éé…");
    assert_eq!(excerpt("ab", 2), "ab");
    assert_eq!(excerpt("", 2), "");
    // A cluster of several scalars is cut by scalar, never inside a byte.
    assert_eq!(excerpt("👨‍👩‍👧x", 1), "👨…");
}

#[test]
fn set_reactions_shows_chips() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, _bob, fb, _fa) = paired(&da, &db);
    alice
        .send_text(fb.clone(), "hello".into(), None, None)
        .unwrap();
    let id = row_of(&alice, &fb, "hello");
    assert!(
        alice.messages_with(fb.clone()).unwrap()[0]
            .reactions
            .is_empty()
    );

    alice.set_reactions(id, vec!["👍".into()]).unwrap();
    let m = &alice.messages_with(fb.clone()).unwrap()[0];
    assert_eq!(
        m.reactions,
        vec![ReactionChip {
            emoji: "👍".into(),
            count: 1,
            mine: true
        }]
    );
    // A reaction is not a message: the thread, the unread counts and the
    // chat's last message are as before.
    assert_eq!(alice.messages_with(fb.clone()).unwrap().len(), 1);
    assert!(alice.unread_counts().unwrap().is_empty());
    let chats = alice.chat_summaries().unwrap();
    assert_eq!(chats[0].last.as_ref().unwrap().id, id);
    assert_eq!(chats[0].last.as_ref().unwrap().body, "hello");
    // The same set again, then none: removes the chip.
    alice.set_reactions(id, vec!["👍".into()]).unwrap();
    alice.set_reactions(id, vec![]).unwrap();
    assert!(
        alice.messages_with(fb.clone()).unwrap()[0]
            .reactions
            .is_empty()
    );
}

#[test]
fn set_reactions_errors_are_typed() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, _bob, fb, _fa) = paired(&da, &db);
    alice
        .send_text(fb.clone(), "hello".into(), None, None)
        .unwrap();
    let id = row_of(&alice, &fb, "hello");

    let too_many: Vec<String> = ["😀", "😃", "😄", "😁", "😆", "😅", "🤣", "😂", "🙂", "🙃"]
        .iter()
        .chain(
            [
                "😉", "😊", "😇", "🥰", "😍", "🤩", "😘", "😗", "😚", "😙", "😋",
            ]
            .iter(),
        )
        .map(|e| (*e).to_owned())
        .collect();
    assert_eq!(too_many.len(), 21);
    assert!(matches!(
        alice.set_reactions(id, too_many),
        Err(BarkingError::TooManyEmoji)
    ));
    assert!(matches!(
        alice.set_reactions(id, vec!["x".into()]),
        Err(BarkingError::InvalidEmoji)
    ));
    assert!(matches!(
        alice.set_reactions(-1, vec!["👍".into()]),
        Err(BarkingError::MessageNotFound)
    ));
    assert!(matches!(
        alice.set_reactions(id + 1000, vec!["👍".into()]),
        Err(BarkingError::MessageNotFound)
    ));
    assert!(matches!(
        alice.send_text(fb.clone(), "re".into(), Some(-1), None),
        Err(BarkingError::MessageNotFound)
    ));
    assert!(matches!(
        alice.send_text(fb.clone(), "re".into(), Some(id + 1000), None),
        Err(BarkingError::MessageNotFound)
    ));
    // Nothing was queued by the refused reply.
    assert_eq!(alice.messages_with(fb.clone()).unwrap().len(), 1);

    // A blocked contact is refused; a contact removed since is not found.
    alice.block_contact(fb.clone()).unwrap();
    assert!(matches!(
        alice.set_reactions(id, vec!["👍".into()]),
        Err(BarkingError::ContactBlocked)
    ));
    alice.unblock_contact(fb.clone()).unwrap();
    alice.remove_contact(fb.clone()).unwrap();
    assert!(matches!(
        alice.set_reactions(id, vec!["👍".into()]),
        Err(BarkingError::NotFound)
    ));
}

/// A reply is a message of its own whose quote is read from the original's
/// row, on both sides, with the original's author known after it is gone.
#[tokio::test(flavor = "multi_thread")]
async fn reply_shows_quote() {
    let p = on_network().await;
    let (alice, bob, fa, fb) = (p.alice.clone(), p.bob.clone(), p.fa.clone(), p.fb.clone());
    let nodes = p.nodes;

    // Alice writes, Bob reads and replies to it.
    let a = alice.clone();
    let fb2 = fb.clone();
    step(move || {
        a.send_text(fb2, "salut".into(), None, None).unwrap();
        a.sync(30_000).unwrap();
    })
    .await;
    settle(&nodes).await;
    let (b, fa2) = (bob.clone(), fa.clone());
    step(move || {
        let s = b.sync(30_000).unwrap();
        assert_eq!(s.new_messages.len(), 1, "{s:?}");
        let original = row_of(&b, &fa2, "salut");
        b.send_text(fa2.clone(), "re: salut".into(), Some(original), None)
            .unwrap();
        // Bob sees his own reply quoting Alice's message.
        let reply = b
            .messages_with(fa2.clone())
            .unwrap()
            .into_iter()
            .find(|m| m.body == "re: salut")
            .unwrap();
        assert_eq!(
            reply.reply_to,
            Some(Quote {
                id: Some(original),
                author_is_me: false,
                excerpt: Some("salut".into())
            })
        );
        b.sync(30_000).unwrap();
    })
    .await;
    settle(&nodes).await;

    let (a, fb2) = (alice.clone(), fb.clone());
    step(move || {
        let s = a.sync(30_000).unwrap();
        assert_eq!(s.new_messages.len(), 1, "{s:?}");
        assert_eq!(s.new_messages[0].text, "re: salut");
        let original = row_of(&a, &fb2, "salut");
        let reply = a
            .messages_with(fb2.clone())
            .unwrap()
            .into_iter()
            .find(|m| m.body == "re: salut")
            .unwrap();
        assert_eq!(
            reply.reply_to,
            Some(Quote {
                id: Some(original),
                author_is_me: true,
                excerpt: Some("salut".into())
            })
        );
        // The chats list's last message carries its quote too.
        let chats = a.chat_summaries().unwrap();
        assert_eq!(chats[0].last.as_ref().unwrap().reply_to, reply.reply_to);

        // The original deleted here: the quote stays, without its text.
        a.delete_message(original).unwrap();
        let reply = a
            .messages_with(fb2.clone())
            .unwrap()
            .into_iter()
            .find(|m| m.body == "re: salut")
            .unwrap();
        assert_eq!(
            reply.reply_to,
            Some(Quote {
                id: None,
                author_is_me: true,
                excerpt: None
            })
        );
    })
    .await;
    stop_all(nodes).await;
}

/// What Bob's reaction does on Alice's phone: the chip, the notification
/// line and the conversation to reload, but no unread message and no new
/// last message; and its removal alone leaves nothing to show.
#[tokio::test(flavor = "multi_thread")]
async fn received_reaction_is_a_chip_not_a_message() {
    let p = on_network().await;
    let (alice, bob, fa, fb) = (p.alice.clone(), p.bob.clone(), p.fa.clone(), p.fb.clone());
    let nodes = p.nodes;

    let (a, fb2) = (alice.clone(), fb.clone());
    step(move || {
        a.send_text(fb2, "salut".into(), None, None).unwrap();
        a.sync(30_000).unwrap();
    })
    .await;
    settle(&nodes).await;
    let (b, fa2) = (bob.clone(), fa.clone());
    step(move || {
        b.sync(30_000).unwrap();
        let original = row_of(&b, &fa2, "salut");
        b.set_reactions(original, vec!["👍".into()]).unwrap();
        b.sync(30_000).unwrap();
    })
    .await;
    settle(&nodes).await;

    let (a, fb2) = (alice.clone(), fb.clone());
    step(move || {
        let s = a.sync(30_000).unwrap();
        assert_eq!(s.error, None);
        assert!(s.new_messages.is_empty(), "{s:?}");
        assert_eq!(s.new_reactions.len(), 1, "{s:?}");
        let r = &s.new_reactions[0];
        assert_eq!(r.contact, fb2);
        assert_eq!(r.emojis, vec!["👍".to_owned()]);
        assert_eq!(r.excerpt.as_deref(), Some("salut"));
        assert_eq!(s.reaction_contacts, vec![fb2.clone()]);
        // Something to show: the notification names the reaction.
        assert!(!s.nothing_to_show);

        let thread = a.messages_with(fb2.clone()).unwrap();
        assert_eq!(thread.len(), 1);
        assert_eq!(
            thread[0].reactions,
            vec![ReactionChip {
                emoji: "👍".into(),
                count: 1,
                mine: false
            }]
        );
        // Spec §3: never unread, never the last message of the list.
        assert!(a.unread_counts().unwrap().is_empty());
        let chats = a.chat_summaries().unwrap();
        assert_eq!(chats[0].unread, 0);
        assert_eq!(chats[0].last.as_ref().unwrap().id, thread[0].id);
    })
    .await;

    // Bob takes it back: Alice's conversation reloads, nothing to notify.
    let (b, fa2) = (bob.clone(), fa.clone());
    step(move || {
        let original = row_of(&b, &fa2, "salut");
        b.set_reactions(original, vec![]).unwrap();
        b.sync(30_000).unwrap();
    })
    .await;
    settle(&nodes).await;
    let (a, fb2) = (alice.clone(), fb.clone());
    step(move || {
        let s = a.sync(30_000).unwrap();
        assert!(
            s.new_messages.is_empty() && s.new_reactions.is_empty(),
            "{s:?}"
        );
        assert_eq!(s.reaction_contacts, vec![fb2.clone()]);
        assert!(s.items_received > 0 && s.nothing_to_show, "{s:?}");
        assert!(
            a.messages_with(fb2.clone()).unwrap()[0]
                .reactions
                .is_empty()
        );
        assert!(a.unread_counts().unwrap().is_empty());
    })
    .await;
    stop_all(nodes).await;
}

/// A placeholder row ("needs a newer version") is a visible message of the
/// conversation, unlike a reaction: it counts as unread and shows as the
/// last message, with no text and `needs_update`.
#[test]
fn placeholder_row_is_unread_and_last() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, _bob, fb, _fa) = paired(&da, &db);
    alice
        .send_text(fb.clone(), "hello".into(), None, None)
        .unwrap();

    let path = da.path().join("barking.db");
    let contact = Core::open(&path, &[1; 32], 1_000)
        .unwrap()
        .contacts()
        .unwrap()
        .remove(0)
        .fingerprint;
    Store::open(&path, &[1; 32])
        .unwrap()
        .insert_message_row(&MessageInsert {
            contact_fp: contact,
            direction: Direction::In,
            body: String::new(),
            status: MessageStatus::Received,
            at: 4_000_000_000, // after the real time of `send_text`
            message_id: MessageId([9; 16]),
            wire_id: None,
            reply_to: None,
            reply_ref: None,
            placeholder: true,
            ttl_secs: None,
            seen_at: None,
            expire_at: None,
        })
        .unwrap();

    let counts = alice.unread_counts().unwrap();
    assert_eq!((counts.len(), counts[0].count), (1, 1));
    let chats = alice.chat_summaries().unwrap();
    let last = chats[0].last.as_ref().unwrap();
    assert!(last.needs_update && last.body.is_empty() && !last.outgoing);
    assert_eq!(chats[0].unread, 1);
    let thread = alice.messages_with(fb).unwrap();
    assert_eq!(
        thread.iter().map(|m| m.needs_update).collect::<Vec<_>>(),
        vec![false, true]
    );
}

#[test]
fn message_carries_my_reaction_state() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, _bob, fb, _fa) = paired(&da, &db);
    alice
        .send_text(fb.clone(), "one".into(), None, None)
        .unwrap();
    alice
        .send_text(fb.clone(), "two".into(), None, None)
        .unwrap();
    let id = row_of(&alice, &fb, "one");
    alice.set_reactions(id, vec!["❤️".into()]).unwrap();
    for m in alice.messages_with(fb.clone()).unwrap() {
        if m.id == id {
            assert_eq!(m.my_reaction_state, Some(DeliveryState::Pending));
        } else {
            assert_eq!(m.my_reaction_state, None);
        }
    }
}

#[test]
fn delivery_update_carries_my_reaction_state() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, _bob, fb, _fa) = paired(&da, &db);
    alice
        .send_text(fb.clone(), "one".into(), None, None)
        .unwrap();
    alice
        .send_text(fb.clone(), "two".into(), None, None)
        .unwrap();
    let id = row_of(&alice, &fb, "one");
    let other = row_of(&alice, &fb, "two");
    alice.set_reactions(id, vec!["❤️".into()]).unwrap();
    let ups = alice.deliveries_of(vec![id, other, id + 1000]).unwrap();
    assert_eq!(ups[0].my_reaction_state, Some(DeliveryState::Pending));
    assert_eq!(ups[1].my_reaction_state, None);
    assert!(ups[2].removed);
    assert_eq!(ups[2].my_reaction_state, None);
}

#[test]
fn reaction_delivery_matches_the_core() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, _bob, fb, _fa) = paired(&da, &db);
    alice
        .send_text(fb.clone(), "one".into(), None, None)
        .unwrap();
    let id = row_of(&alice, &fb, "one");
    assert!(alice.reaction_delivery(id).unwrap().is_none());
    alice.set_reactions(id, vec!["❤️".into()]).unwrap();
    let d = alice.reaction_delivery(id).unwrap().unwrap();
    assert_eq!(d.message_id, id);
    assert_eq!(d.emojis, vec!["❤️".to_owned()]);
    assert_eq!(d.delivery.state, DeliveryState::Pending);
    assert!(!d.devices.is_empty());
}

#[test]
fn retry_reactions_maps_nothing_to_retry() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (alice, _bob, fb, _fa) = paired(&da, &db);
    alice
        .send_text(fb.clone(), "one".into(), None, None)
        .unwrap();
    let id = row_of(&alice, &fb, "one");
    alice.set_reactions(id, vec!["❤️".into()]).unwrap();
    assert!(matches!(
        alice.retry_reactions(id),
        Err(BarkingError::NothingToRetry)
    ));
    assert!(matches!(
        alice.retry_reactions(id + 1000),
        Err(BarkingError::MessageNotFound)
    ));
}
