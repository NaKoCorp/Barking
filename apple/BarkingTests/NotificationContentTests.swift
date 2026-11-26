import UserNotifications
import XCTest
@testable import BarkingKit

final class NotificationContentTests: XCTestCase {
    func msg(_ c: String, _ n: String, _ t: String) -> NewMessage { NewMessage(contact: c, name: n, text: t) }
    func summary(_ m: [NewMessage], reactions: [NewReaction] = [], nothingToShow: Bool = false,
                 networkUp: Bool = true, error: String? = nil) -> SyncSummary {
        SyncSummary(itemsReceived: UInt32(m.count + reactions.count), sent: 0, newMessages: m, networkUp: networkUp,
                    error: error, newReactions: reactions, nothingToShow: nothingToShow)
    }
    func reaction(_ c: String = "FP1", _ n: String = "Alice", _ e: [String] = ["👍"], _ x: String? = "On se voit…") -> NewReaction {
        NewReaction(contact: c, name: n, emojis: e, excerpt: x)
    }
    func original() -> UNMutableNotificationContent {
        let c = UNMutableNotificationContent()
        c.body = "New message"
        return c
    }

    func testOneMessage() {
        let c = original()
        XCTAssertEqual(NotificationContent.apply(summary([msg("FP1", "Alice", "salut")]), to: c, preview: .nameAndText, locked: false), "shown")
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["Alice", "salut", "FP1"])
    }

    func testSameContactSeveral() {
        let c = original()
        XCTAssertEqual(NotificationContent.apply(summary([msg("FP1", "Alice", "a"), msg("FP1", "Alice", "b")]), to: c, preview: .nameAndText, locked: false), "shown")
        XCTAssertEqual([c.title, c.threadIdentifier], ["Alice", "FP1"])
        XCTAssertTrue(c.body.contains("2"), c.body)
    }

    func testSeveralContacts() {
        let c = original()
        _ = NotificationContent.apply(summary([msg("FP1", "Alice", "a"), msg("FP2", "Bob", "b")]), to: c, preview: .nameAndText, locked: false)
        XCTAssertEqual(c.threadIdentifier, "")
        XCTAssertEqual(c.title, "")
        XCTAssertTrue(c.body.contains("2"), c.body)
    }

    func testNothingVisibleDeliversOriginal() {
        let c = original()
        XCTAssertEqual(NotificationContent.apply(summary([]), to: c, preview: .nameAndText, locked: false), "original")
        XCTAssertEqual(c.body, "New message")
    }

    func testNoKeyDeliversOriginal() {
        let c = original()
        XCTAssertEqual(NotificationContent.apply(nil, to: c, preview: .nameAndText, locked: false), "original")
        XCTAssertEqual(c.body, "New message")
    }

    func testLockedShowsOnlyNewMessage() {
        let c = original()
        XCTAssertEqual(NotificationContent.apply(summary([msg("FP1", "Sam", "secret")]), to: c, preview: .nameAndText, locked: true), "shown")
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "New message", ""])
    }

    func testLockedSeveralMessagesShowNoCountEither() {
        let c = original()
        _ = NotificationContent.apply(summary([msg("FP1", "Sam", "a"), msg("FP1", "Sam", "b")]), to: c, preview: .nameAndText, locked: true)
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "New message", ""])
    }

    func testNameOnlyOneMessage() {
        let c = original()
        XCTAssertEqual(NotificationContent.apply(summary([msg("FP1", "Alice", "secret")]), to: c, preview: .nameOnly, locked: false), "shown")
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["Alice", "New message", "FP1"])
    }

    func testNameOnlySeveralOneContact() {
        let c = original()
        _ = NotificationContent.apply(summary([msg("FP1", "Alice", "a"), msg("FP1", "Alice", "b"), msg("FP1", "Alice", "c")]),
                                      to: c, preview: .nameOnly, locked: false)
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["Alice", "3 new messages", "FP1"])
    }

    func testGenericHidesEverything() {
        let c = original()
        c.title = "x"
        c.threadIdentifier = "t"
        XCTAssertEqual(NotificationContent.apply(summary([msg("FP1", "Alice", "secret")]), to: c, preview: .generic, locked: false), "shown")
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "New message", ""])
    }

    func testLockedOverridesNameAndText() {
        let c = original()
        XCTAssertEqual(NotificationContent.apply(summary([msg("FP1", "Alice", "secret")]), to: c, preview: .nameAndText, locked: true), "shown")
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "New message", ""])
    }

    func testNameOnlySeveralContacts() {
        let c = original()
        _ = NotificationContent.apply(summary([msg("FP1", "Alice", "a"), msg("FP2", "Bob", "b")]), to: c, preview: .nameOnly, locked: false)
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "2 new messages", ""])
    }

    func testGenericSeveralMessages() {
        let c = original()
        _ = NotificationContent.apply(summary([msg("FP1", "Alice", "a"), msg("FP2", "Bob", "b")]), to: c, preview: .generic, locked: false)
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "New message", ""])
    }

    func testOneReactionNameAndText() {
        let c = original()
        XCTAssertEqual(NotificationContent.apply(summary([], reactions: [reaction()]), to: c, preview: .nameAndText, locked: false), "shown")
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["Alice", "Reacted 👍 to “On se voit…”", "FP1"])
    }

    func testReactionWithoutExcerpt() {
        let c = original()
        _ = NotificationContent.apply(summary([], reactions: [reaction("FP1", "Alice", ["👍"], nil)]), to: c, preview: .nameAndText, locked: false)
        XCTAssertEqual(c.body, "Reacted 👍")
    }

    func testOneReactionNameOnly() {
        let c = original()
        _ = NotificationContent.apply(summary([], reactions: [reaction()]), to: c, preview: .nameOnly, locked: false)
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["Alice", "Reacted", "FP1"])
    }

    func testReactionLockedAndGeneric() {
        for (preview, locked) in [(PushPreview.nameAndText, true), (.generic, false)] {
            let c = original()
            XCTAssertEqual(NotificationContent.apply(summary([], reactions: [reaction()]), to: c, preview: preview, locked: locked), "shown")
            XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "New message", ""])
        }
    }

    func testMessageAndReactionCount() {
        let c = original()
        _ = NotificationContent.apply(summary([msg("FP1", "Alice", "a")], reactions: [reaction()]), to: c, preview: .nameAndText, locked: false)
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["Alice", "2 new messages", "FP1"])
    }

    func testNothingToShowSuppresses() {
        let c = original()
        c.title = "x"
        c.threadIdentifier = "t"
        XCTAssertEqual(NotificationContent.apply(summary([], nothingToShow: true), to: c, preview: .nameAndText, locked: false), "suppressed")
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "", ""])
    }

    func testFailedOrOfflineSyncNeverSuppresses() {
        for s in [summary([], networkUp: false), summary([], error: "x")] {
            let c = original()
            XCTAssertEqual(NotificationContent.apply(s, to: c, preview: .nameAndText, locked: false), "original")
            XCTAssertEqual(c.body, "New message")
        }
    }

    func testNeedsUpdateMessage() {
        let c = original()
        let m = NewMessage(contact: "FP1", name: "Alice", text: "", needsUpdate: true)
        XCTAssertEqual(NotificationContent.apply(summary([m]), to: c, preview: .nameAndText, locked: false), "shown")
        XCTAssertEqual([c.title, c.body], ["Alice", "This message needs a newer version of Barking."])
        let n = original()
        _ = NotificationContent.apply(summary([m]), to: n, preview: .nameOnly, locked: false)
        XCTAssertEqual(n.body, "New message")
    }

    // MARK: Invitations

    func invitations(_ r: [NewRequest], messages: [NewMessage] = [], nothingToShow: Bool = false,
                     requestContacts: [String]? = nil) -> SyncSummary {
        SyncSummary(itemsReceived: UInt32(r.count + messages.count), sent: 0, newMessages: messages, networkUp: true,
                    error: nil, nothingToShow: nothingToShow, newRequests: r,
                    requestContacts: requestContacts ?? r.map(\.contact))
    }
    let en = Locale(identifier: "en_US")

    func testSingleNewInvitation() throws {
        let c = original()
        c.title = "x"
        c.threadIdentifier = "t"
        let s = invitations([NewRequest(contact: "FPR", name: "Alice", resent: false)])
        XCTAssertEqual(NotificationContent.apply(s, to: c, preview: .nameAndText, locked: false, locale: en), "shown")
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "New invitation from “Alice”", ""])
        let fr = original()
        _ = NotificationContent.apply(s, to: fr, preview: .nameOnly, locked: false, bundle: try french(),
                                      locale: Locale(identifier: "fr_FR"))
        XCTAssertEqual(fr.body, "Nouvelle invitation de «\u{00A0}Alice\u{00A0}»")
    }

    func testResentInvitation() throws {
        let c = original()
        let s = invitations([NewRequest(contact: "FPR", name: "Alice", resent: true)])
        XCTAssertEqual(NotificationContent.apply(s, to: c, preview: .nameAndText, locked: false, locale: en), "shown")
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "“Alice” resent their invitation", ""])
        let fr = original()
        _ = NotificationContent.apply(s, to: fr, preview: .nameAndText, locked: false, bundle: try french(),
                                      locale: Locale(identifier: "fr_FR"))
        XCTAssertEqual(fr.body, "«\u{00A0}Alice\u{00A0}» a renvoyé son invitation")
    }

    func testSeveralInvitationsAreGeneric() {
        let c = original()
        let s = invitations([NewRequest(contact: "FP1", name: "Alice", resent: false),
                             NewRequest(contact: "FP2", name: "Bob", resent: true)])
        XCTAssertEqual(NotificationContent.apply(s, to: c, preview: .nameAndText, locked: false, locale: en), "shown")
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "New invitation", ""])
    }

    func testInvitationGenericWhenLocked() throws {
        let s = invitations([NewRequest(contact: "FPR", name: "Alice", resent: false)])
        for (preview, locked) in [(PushPreview.nameAndText, true), (.generic, false)] {
            let c = original()
            c.title = "x"
            XCTAssertEqual(NotificationContent.apply(s, to: c, preview: preview, locked: locked, locale: en), "shown")
            XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "New invitation", ""])
            XCTAssertFalse(c.body.contains("Alice"))
        }
        let fr = original()
        _ = NotificationContent.apply(s, to: fr, preview: .generic, locked: false, bundle: try french())
        XCTAssertEqual(fr.body, "Nouvelle invitation")
    }

    func testMessageWinsOverInvitation() {
        let c = original()
        let s = invitations([NewRequest(contact: "FPR", name: "Bob", resent: false)],
                            messages: [msg("FP1", "Alice", "salut")])
        XCTAssertEqual(NotificationContent.apply(s, to: c, preview: .nameAndText, locked: false, locale: en), "shown")
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["Alice", "salut", "FP1"])
    }

    /// A wake that only moved a request it must not notify (setting off, or
    /// notified within 24 h): suppressed, never the generic "New message".
    func testRequestNotNotifiedSuppresses() {
        let c = original()
        let s = invitations([], nothingToShow: true, requestContacts: ["FPR"])
        XCTAssertEqual(NotificationContent.apply(s, to: c, preview: .nameAndText, locked: false), "suppressed")
        XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "", ""])
    }

    private func french() throws -> Bundle {
        let kit = Bundle(for: FailureNotifier.Marker.self)
        return try XCTUnwrap(kit.path(forResource: "fr", ofType: "lproj").flatMap(Bundle.init(path:)))
    }

    /// An ephemeral never shows its text (spec §5.4): « Message éphémère »
    /// with the name and with the name only; generic and locked keep "New message".
    func testEphemeralNotificationHidesTextForAllPreviews() throws {
        let fr = try french()
        let m = NewMessage(contact: "FP1", name: "Alice", text: "", ephemeral: true)
        for preview in [PushPreview.nameAndText, .nameOnly] {
            let c = original()
            XCTAssertEqual(NotificationContent.apply(summary([m]), to: c, preview: preview, locked: false, bundle: fr), "shown")
            XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["Alice", "Message éphémère", "FP1"])
            let en = original()
            _ = NotificationContent.apply(summary([m]), to: en, preview: preview, locked: false)
            XCTAssertEqual(en.body, "Disappearing message")
        }
        for (preview, locked) in [(PushPreview.generic, false), (.nameAndText, true)] {
            let c = original()
            _ = NotificationContent.apply(summary([m]), to: c, preview: preview, locked: locked)
            XCTAssertEqual([c.title, c.body, c.threadIdentifier], ["", "New message", ""])
        }
    }

    /// A reaction to an ephemeral says so, without the emoji or any excerpt.
    func testReactionOnEphemeralHidesEmoji() throws {
        let r = NewReaction(contact: "FP1", name: "Alice", emojis: ["👍"], excerpt: nil, onEphemeral: true)
        for preview in [PushPreview.nameAndText, .nameOnly] {
            let c = original()
            _ = NotificationContent.apply(summary([], reactions: [r]), to: c, preview: preview, locked: false)
            XCTAssertEqual([c.title, c.body], ["Alice", "Reacted to a disappearing message"])
            XCTAssertFalse(c.body.contains("👍"))
            let fr = original()
            _ = NotificationContent.apply(summary([], reactions: [r]), to: fr, preview: preview, locked: false,
                                          bundle: try french())
            XCTAssertEqual(fr.body, "A réagi à un message éphémère")
        }
    }
}
