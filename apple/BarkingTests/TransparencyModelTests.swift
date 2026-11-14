import UserNotifications
import XCTest
@testable import Barking
@testable import BarkingKit

/// Transparency view (spec block 2b §5): the journal by day, its filter and
/// pages, and where the data is.
@MainActor
final class TransparencyModelTests: XCTestCase {
    private var utc: Calendar {
        var c = Calendar(identifier: .gregorian)
        c.timeZone = TimeZone(identifier: "UTC")!
        return c
    }

    /// 2027-01-15 12:00 UTC.
    private let noon: UInt64 = 1_800_000_000 - 1_800_000_000 % 86_400 + 12 * 3_600

    /// The id grows with the time, as the core's does.
    private func entry(_ at: UInt64, security: Bool = false, key: String = "log.node_fetch",
                       args: [String] = ["K7QX2M4A", "3", "1"], id: Int64? = nil) -> LogEntry {
        LogEntry(id: id ?? Int64(at) - Int64(noon) + 1_000_000, at: at, family: security ? "security" : "node", key: key,
                 args: args, security: security)
    }

    private func model(_ d: FakeDevice, protection: String = "secure-enclave", push: PushToken? = nil) -> TransparencyModel {
        let token = push ?? Self.push(.authorized)
        return TransparencyModel(core: CoreService(device: d, runner: DirectRunner()), push: token,
                                 protection: { protection }, calendar: utc,
                                 locale: Locale(identifier: "en_US_POSIX"))
    }

    private static func push(_ status: UNAuthorizationStatus, relay: Bool = true) -> PushToken {
        let push = PushToken()
        push.info = ["BarkingRelayHost": relay ? "relay.local" : ""]
        push.authorization = { status }
        return push
    }

    /// 20_405 days after the epoch: 2025-11-13.
    func testWakeRowsFromStatus() async {
        let d = FakeDevice()
        d.wakeStatusValue = WakeStatus(configSet: true, nodes: [
            WakeNode(node: "K7QX2M4A", mailboxes: 3, messages: true, acks: true, expiresDay: 20_405),
            WakeNode(node: "B2C3D4E5", mailboxes: 1, messages: false, acks: true, expiresDay: 20_405),
        ])
        let m = model(d)
        await m.load()
        XCTAssertEqual(m.wakeRows.map(\.id), ["K7QX2M4A", "B2C3D4E5"])
        XCTAssertEqual(m.wakeRows.map(\.title), ["K7QX2M4A", "B2C3D4E5"])
        XCTAssertEqual(m.wakeRows[0].detail, "3 mailboxes · messages, receipts · until Nov 13, 2025")
        XCTAssertEqual(m.wakeRows[1].detail, "1 mailbox · receipts · until Nov 13, 2025")
    }

    func testWakeRowsEmpty() async {
        let m = model(FakeDevice())
        await m.load()
        XCTAssertTrue(m.wakeRows.isEmpty)
    }

    func testLastWakeNilIsNever() async {
        let m = model(FakeDevice())
        await m.load()
        XCTAssertNil(m.lastWake)
    }

    func testLastWakeFromPrefs() async {
        let d = FakeDevice()
        d.prefs.lastWake = noon
        let m = model(d)
        await m.load()
        XCTAssertEqual(m.lastWake, Date(timeIntervalSince1970: TimeInterval(noon)))
    }

    func testWakeStateReusesTheNotificationsPriority() async {
        let off = FakeDevice()
        off.prefs.instant = false
        let a = model(off)
        await a.load()
        XCTAssertEqual(a.wakeState, .off)
        let b = model(FakeDevice(), push: Self.push(.denied))
        await b.load()
        XCTAssertEqual(b.wakeState, .denied)
        let c = model(FakeDevice(), push: Self.push(.authorized, relay: false))
        await c.load()
        XCTAssertEqual(c.wakeState, .noRelay)
    }

    func testWaitingForTokenWhenOnWithoutToken() async {
        let push = Self.push(.authorized)
        let m = model(FakeDevice(), push: push)
        await m.load()
        XCTAssertEqual(m.wakeState, .on)
        XCTAssertTrue(m.waitingForToken)
        push.token = Data([1, 2, 3])
        await m.load()
        XCTAssertFalse(m.waitingForToken)
    }

    func testNotWaitingForTokenWhenOff() async {
        let d = FakeDevice()
        d.prefs.instant = false
        let m = model(d)
        await m.load()
        XCTAssertFalse(m.waitingForToken)
    }

    func testGroupsByDayNewestFirst() async {
        let d = FakeDevice()
        // Newest first, as the core gives them: two today, one yesterday, one three days ago.
        d.logEntries = [entry(noon + 600), entry(noon), entry(noon - 86_400), entry(noon - 3 * 86_400)]
        let m = model(d)
        await m.load()
        XCTAssertEqual(m.days.count, 3)
        XCTAssertEqual(m.days.map { $0.rows.count }, [2, 1, 1])
        let dates = m.days.map(\.date)
        XCTAssertEqual(dates, dates.sorted(by: >))
        XCTAssertEqual(m.days[0].rows.map(\.at), [noon + 600, noon].map { Date(timeIntervalSince1970: TimeInterval($0)) })
        XCTAssertEqual(utc.startOfDay(for: m.days[0].rows[0].at), m.days[0].date)
    }

    func testTheJournalShowsEverythingByDefault() {
        XCTAssertEqual(model(FakeDevice()).filter, .everything)
    }

    func testSecurityFilter() async {
        let d = FakeDevice()
        d.logEntries = [entry(noon + 3), entry(noon + 2, security: true, key: "log.contact_key_changed",
                                                args: ["Bob", "a", "b"]),
                        entry(noon + 1), entry(noon, security: true, key: "log.session_established",
                                               args: ["Bob", "02020202", "@initiator", "@post_quantum"])]
        let m = model(d)
        await m.load()
        XCTAssertEqual(m.days.flatMap(\.rows).count, 4)
        await m.setFilter(.keysAndDevices)
        let rows = m.days.flatMap(\.rows)
        XCTAssertEqual(rows.count, 2)
        XCTAssertTrue(rows.allSatisfy(\.security))
        await m.setFilter(.everything)
        XCTAssertEqual(m.days.flatMap(\.rows).count, 4)
    }

    func testPagesOfOneHundred() async {
        let d = FakeDevice()
        d.logEntries = (0..<250).map { entry(noon + UInt64(250 - $0)) }
        let m = model(d)
        await m.load()
        XCTAssertEqual(m.days.flatMap(\.rows).count, 100)
        XCTAssertTrue(m.canLoadMore)
        await m.loadMore()
        XCTAssertEqual(m.days.flatMap(\.rows).count, 200)
        await m.loadMore()
        XCTAssertEqual(m.days.flatMap(\.rows).count, 250)
        XCTAssertFalse(m.canLoadMore)
        // No row twice.
        let ids = m.days.flatMap(\.rows).map(\.id)
        XCTAssertEqual(Set(ids).count, 250)
    }

    /// Events logged while the user scrolls do not shift the next page.
    func testNextPageFollowsTheEventIdNotThePosition() async {
        let d = FakeDevice()
        d.logEntries = (0..<150).map { entry(noon + UInt64(150 - $0)) }
        let m = model(d)
        await m.load()
        XCTAssertEqual(m.days.flatMap(\.rows).count, 100)
        // Five events arrive at the top, then the user scrolls.
        d.logEntries.insert(contentsOf: (0..<5).map { entry(noon + 200 + UInt64($0)) }.reversed(), at: 0)
        await m.loadMore()
        let ids = m.days.flatMap(\.rows).map(\.id)
        XCTAssertEqual(ids.count, 150)
        XCTAssertEqual(Set(ids).count, 150, "a row twice")
        XCTAssertEqual(ids, ids.sorted(by: >), "a gap or a reordering")
    }

    /// A clock that went back and forth must not make two groups of one day.
    func testSameDayIsOneGroupWhateverTheOrder() async {
        let d = FakeDevice()
        d.logEntries = [entry(noon, id: 9), entry(noon - 86_400, id: 8), entry(noon + 60, id: 7)]
        let m = model(d)
        await m.load()
        XCTAssertEqual(m.days.count, 2)
        XCTAssertEqual(Set(m.days.map(\.id)).count, 2)
        XCTAssertEqual(m.days[0].rows.map(\.id), [9, 7])
    }

    func testKeyProtectionCopyDoesNotOverclaim() {
        let enclave = TransparencyModel.dataRows(protection: "secure-enclave").first { $0.id == "key" }
        XCTAssertEqual(enclave?.detail, "Wrapped by a key that never leaves this iPhone's chip.")
        let keychain = TransparencyModel.dataRows(protection: "keychain").first { $0.id == "key" }
        XCTAssertEqual(keychain?.detail, "Kept in the keychain, without the Secure Enclave.")
        XCTAssertTrue(TransparencyModel.dataRows(protection: "keychain")[0].detail.contains("SQLCipher"))
    }

    func testCountsArePlural() {
        let one = LogText.render(LogEntry(id: 1, at: 0, family: "device", key: "log.history_imported",
                                          args: ["1"], security: false), locale: Locale(identifier: "en"))
        let many = LogText.render(LogEntry(id: 1, at: 0, family: "device", key: "log.history_imported",
                                           args: ["7"], security: false), locale: Locale(identifier: "en"))
        XCTAssertTrue(one.hasPrefix("1 history message copied"), one)
        XCTAssertTrue(many.hasPrefix("7 history messages copied"), many)
    }

    func testReasonsAndTransportAreTranslated() {
        let text = LogText.render(LogEntry(id: 1, at: 0, family: "packet", key: "log.packet_opened",
                                           args: ["Sam", "@transport_node", ""], security: false))
        XCTAssertFalse(text.contains("@"), text)
        XCTAssertTrue(text.contains("via a node") || text.contains("a node"), text)
    }

    func testDataLocationReflectsProtection() async {
        let enclave = model(FakeDevice(), protection: "secure-enclave")
        await enclave.load()
        XCTAssertTrue(enclave.dataRows.contains { $0.title == "Database key protected by the Secure Enclave" })
        let keychain = model(FakeDevice(), protection: "keychain")
        await keychain.load()
        XCTAssertTrue(keychain.dataRows.contains { $0.title == "Database key protected by the keychain only" })
        XCTAssertEqual(keychain.dataRows.count, 4)
    }

    func testRowTextComesFromKeyAndArgs() async {
        let d = FakeDevice()
        d.logEntries = [entry(noon, key: "log.node_fetch", args: ["K7QX2M4A", "3", "1"])]
        let m = model(d)
        await m.load()
        let text = m.days[0].rows[0].text
        XCTAssertTrue(text.contains("K7QX2M4A"), text)
        XCTAssertFalse(text.hasPrefix("log."), text)
    }

    func testEveryCoreKeyRenders() {
        for key in logKeys() {
            let text = LogText.render(LogEntry(id: 1, at: 0, family: "node", key: key, args: ["a", "b", "c", "d"],
                                               security: false))
            XCTAssertFalse(text.isEmpty, key)
            XCTAssertNotEqual(text, key)
            XCTAssertFalse(text.contains("%"), "\(key): \(text)")
        }
    }

    func testContactDevicesLoad() async {
        let d = FakeDevice()
        d.contactList = [Contact(fingerprint: "zab2", alias: nil, displayName: "Maya", verified: false)]
        d.contactDeviceList = ["zab2": [MyDeviceInfo(id: "aa", name: "Maya's iPhone", issuedAt: noon,
                                                     thisDevice: false, admin: false)]]
        let m = ContactModel(contact: "zab2", core: CoreService(device: d, runner: DirectRunner()))
        await m.load()
        XCTAssertEqual(m.devices.map(\.name), ["Maya's iPhone"])
    }

    /// UI review U-30: a short title, a meta line with the size in KB (no
    /// decimals, no raw bytes), and the explanation without the numbers.
    func testPacketRowIsStructured() async {
        let d = FakeDevice()
        d.logEntries = [entry(noon, key: "log.packet_sealed",
                              args: ["16384", "@tier_large", "\(noon + 7 * 86_400)", "@intro_mailbox"])]
        let m = model(d)
        await m.load()
        let row = try? XCTUnwrap(m.days.first?.rows.first)
        XCTAssertEqual(row?.title, "Sent: first message of a session")
        XCTAssertEqual(row?.glyph, .sent)
        let meta = row?.meta ?? ""
        XCTAssertTrue(meta.contains("16 KB"), meta)
        XCTAssertTrue(meta.contains("large"), meta)
        XCTAssertTrue(meta.contains("expires"), meta)
        XCTAssertFalse(meta.contains("16384"), meta)
        let text = row?.text ?? ""
        XCTAssertFalse(text.contains("16384"), text)
        XCTAssertTrue(text.hasPrefix("First message of a session"), text)
        XCTAssertTrue(text.contains("Relays see the size"), text)
    }

    func testDailyPacketTitle() {
        let e = LogEntry(id: 1, at: 0, family: "packet", key: "log.packet_sealed",
                         args: ["2048", "@tier_small", "0", "@daily_mailbox"], security: false)
        XCTAssertEqual(LogText.title(e), "Sent: encrypted packet")
    }

    func testKilobytesHaveNoDecimals() {
        XCTAssertEqual(ByteSize.kilobytes(16_384), "16 KB")
        XCTAssertEqual(ByteSize.kilobytes(2_048), "2 KB")
        XCTAssertEqual(ByteSize.kilobytes(1_536), "2 KB")
        XCTAssertEqual(ByteSize.kilobytes(100), "1 KB")
    }

    /// Every key the core can log has a short title, in both languages.
    func testEveryCoreKeyHasATitle() {
        for key in logKeys() {
            let e = LogEntry(id: 1, at: 0, family: "node", key: key, args: ["a", "b", "c", "d"], security: false)
            let title = LogText.title(e)
            XCTAssertFalse(title.isEmpty, key)
            XCTAssertFalse(title.hasPrefix("log."), "\(key): \(title)")
            XCTAssertFalse(title.contains("%"), "\(key): \(title)")
            XCTAssertLessThan(title.count, 48, "\(key): \(title)")
        }
    }

    func testDirectionGlyphs() {
        XCTAssertEqual(LogGlyph.of(key: "log.packet_opened"), .received)
        XCTAssertEqual(LogGlyph.of(key: "log.ack_verified"), .verified)
        XCTAssertEqual(LogGlyph.of(key: "log.contact_key_changed"), .warning)
        XCTAssertEqual(LogGlyph.of(key: "log.device_linked"), .devices)
        XCTAssertEqual(LogGlyph.sent.symbol, "↑")
        XCTAssertEqual(LogGlyph.received.symbol, "↓")
        XCTAssertEqual(LogGlyph.warning.token, "danger")
        // Review B4 #5: a key this app does not know claims nothing.
        XCTAssertEqual(LogGlyph.of(key: "log.something_new"), .other)
        for key in ["log.link_finished", "log.sync_applied", "log.sync_skipped", "log.contact_card_updated",
                    "log.history_imported", "log.own_devices_updated", "log.seal_skipped", "log.admin_transfer_started",
                    "log.admin_transferred", "log.admin_received", "log.this_device_removed", "log.device_removed",
                    "log.remove_requested"] {
            XCTAssertEqual(LogGlyph.of(key: key), .devices, key)
        }
    }

    /// Review B4 #6: the disclosure shows only when two lines cut the text.
    func testDisclosureFollowsTheCut() {
        XCTAssertTrue(JournalText.isCut(full: 60, clamped: 40))
        XCTAssertFalse(JournalText.isCut(full: 40, clamped: 40))
        XCTAssertFalse(JournalText.isCut(full: 40.4, clamped: 40), "rounding is not a cut")
    }
}
