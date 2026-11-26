import XCTest
@testable import Barking
@testable import BarkingKit

/// The history line of a contact request (list row and request page).
final class RequestHistoryTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    private func request(first: TimeInterval, last: TimeInterval, count: UInt32) -> ContactRequestInfo {
        ContactRequestInfo(fingerprint: "a11ce5a1b2c3", displayName: "Léa",
                           firstSeen: UInt64(now.timeIntervalSince1970 - first),
                           lastSeen: UInt64(now.timeIntervalSince1970 - last),
                           inviteCount: count, pendingMessages: 0, hidden: false, unseen: true, nameClash: false)
    }

    private func bundle(_ code: String) throws -> (bundle: Bundle, locale: Locale) {
        let path = try XCTUnwrap(Bundle.main.path(forResource: code, ofType: "lproj"))
        return (try XCTUnwrap(Bundle(path: path)), Locale(identifier: code))
    }

    /// One invitation: "received", dated by its first sight.
    func testHistoryFirst() throws {
        let r = request(first: 3 * 86_400, last: 3 * 86_400, count: 1)
        let en = try bundle("en")
        let ago = RequestHistory.relative(now.addingTimeInterval(-3 * 86_400), now: now, locale: en.locale)
        XCTAssertEqual(RequestHistory.short(r, now: now, bundle: en.bundle, locale: en.locale), "Invitation received \(ago)")
        XCTAssertEqual(RequestHistory.long(r, now: now, bundle: en.bundle, locale: en.locale), ["Invitation received \(ago)"])
        let fr = try bundle("fr")
        let frAgo = RequestHistory.relative(now.addingTimeInterval(-3 * 86_400), now: now, locale: fr.locale)
        XCTAssertEqual(RequestHistory.short(r, now: now, bundle: fr.bundle, locale: fr.locale), "Invitation reçue \(frAgo)")
    }

    /// Resent: "resent", dated by the last one; the long form counts them.
    func testHistoryResent() throws {
        let r = request(first: 5 * 86_400, last: 2 * 3_600, count: 3)
        let en = try bundle("en")
        let ago = RequestHistory.relative(now.addingTimeInterval(-2 * 3_600), now: now, locale: en.locale)
        XCTAssertEqual(RequestHistory.short(r, now: now, bundle: en.bundle, locale: en.locale), "Invitation resent · \(ago)")
        let long = RequestHistory.long(r, now: now, bundle: en.bundle, locale: en.locale)
        XCTAssertEqual(long.first, "Invitation resent · \(ago)")
        XCTAssertTrue(long.contains("3 invitations"), "\(long)")
        let fr = try bundle("fr")
        XCTAssertTrue(RequestHistory.long(r, now: now, bundle: fr.bundle, locale: fr.locale).contains("3 invitations"))
        XCTAssertTrue(RequestHistory.short(r, now: now, bundle: fr.bundle, locale: fr.locale)
            .hasPrefix("Invitation renvoyée · "))
    }

    /// The list row's waiting messages, in a plural.
    func testWaitingMessages() throws {
        let en = try bundle("en")
        XCTAssertEqual(RequestHistory.waiting(2, bundle: en.bundle, locale: en.locale), "2 messages waiting")
        XCTAssertEqual(RequestHistory.waiting(1, bundle: en.bundle, locale: en.locale), "1 message waiting")
        let fr = try bundle("fr")
        XCTAssertEqual(RequestHistory.waiting(2, bundle: fr.bundle, locale: fr.locale), "2 messages en attente")
    }
}
