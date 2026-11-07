import BarkingKit
import Foundation
import Observation
import SwiftUI

/// The message sheet (spec Lot M §6.4): a sent message's delivery timeline,
/// the contact's devices, my copies, Retry and Delete; a received message's
/// path; a message sent from another of my devices says it is tracked there.
/// It follows its message while open and closes when it is deleted elsewhere.
@MainActor @Observable
final class MessageSheetModel {
    /// One step of the timeline, in words (tests read them in both languages).
    struct Line: Equatable {
        let id: String
        /// nil: a neutral dot (sealed).
        let glyph: DeliveryState?
        let title: String
        /// nil: "not recorded" on a done step, "not yet" ahead.
        let at: Date?
        let detail: String?
        let phase: DeliveryTimeline.Phase
        /// The detail says what a relay could see (the purple rule).
        var privacy = false
        /// Part of the title VoiceOver spells out (a relay id).
        var spelled: String?
    }

    /// One of the contact's devices.
    struct DeviceRow: Equatable, Identifiable {
        let id: String
        let name: String
        /// "received 14:05", "on the network 14:03", "pending", "not delivered".
        let status: String
        let state: DeliveryState
    }

    enum Content: Equatable {
        case loading
        /// Sent from this iPhone: the delivery is known.
        case sent
        /// Sent from another of my devices: its delivery is tracked there.
        case sentElsewhere
        case received
        /// The read failed (§6.4 "Erreur de lecture").
        case unavailable
    }

    /// Why the sheet closes on its own.
    enum Exit: Equatable {
        /// Deleted from here; the banner the conversation shows, if any (§6.7).
        case deleted(DeleteBanner.Message?)
        /// Deleted elsewhere in the app (§9).
        case removedElsewhere
    }

    typealias Notice = ConversationModel.Notice

    /// Messages expire 24 h after sealing (`DEFAULT_TTL_SECS`, Lot N).
    static let lifetime: TimeInterval = 86_400

    private let core: CoreService
    let messageId: Int64
    let contact: String
    let contactName: String
    private(set) var content: Content = .loading
    private(set) var exit: Exit?
    /// A warning in the sheet (deletion or retry failed).
    private(set) var notice: Notice?
    private(set) var quote = ""
    private(set) var outgoing = true
    private(set) var sheet: MessageDelivery?
    private(set) var lines: [Line] = []
    /// "Expired at 11:50. Checking with the relays at the next sync." (§6.4).
    private(set) var verdict: String?
    private(set) var devices: [DeviceRow] = []
    /// "Received on 1 of 2 devices." above the device rows.
    private(set) var devicesSentence: String?
    /// "Copy for your other devices: left at 14:02." or "…: pending.", nil
    /// without a linked device.
    private(set) var ownCopies: String?
    /// The confirmation adds "Your other devices keep their copy." (§5.1, §7.4).
    private(set) var keepsOwnCopies = false
    /// The received message's path (`PathView` rows).
    private(set) var path: PathModel?
    private var retrying = false
    private var deleting = false
    var now: () -> Date = Date.init

    init(core: CoreService, messageId: Int64, contact: String, contactName: String) {
        self.core = core
        self.messageId = messageId
        self.contact = contact
        self.contactName = contactName
    }

    var delivery: Delivery? { sheet?.delivery }

    /// The timeline, for `DeliveryTimeline`.
    var steps: [DeliveryTimeline.Step] { lines.map(Self.step) }

    /// The contact has more than one device: the sheet lists them.
    var showsDevices: Bool { devices.count > 1 }

    /// The §7.4 case, from the delivery shown.
    var confirmation: DeleteConfirmation {
        DeleteConfirmation(outgoing: outgoing, delivery: content == .sentElsewhere ? nil : delivery)
    }

    func confirmationMessage(bundle: Bundle = .main, locale: Locale = .current) -> String {
        confirmation.message(name: contactName, keepsOwnCopies: keepsOwnCopies, bundle: bundle, locale: locale)
    }

    var canRetry: Bool { content == .sent && delivery?.state == .notDelivered }

    // MARK: Loading

    func load() async {
        do {
            guard let message = try await core.messages(with: contact).first(where: { $0.id == messageId }) else {
                close(.removedElsewhere)
                return
            }
            quote = message.body
            outgoing = message.outgoing
            if !message.outgoing {
                let mine = (try? await core.myDevices()) ?? []
                keepsOwnCopies = mine.contains { !$0.thisDevice }
                let path = self.path ?? PathModel(core: core, messageId: messageId, contact: contact,
                                                  contactName: contactName)
                await path.load()
                self.path = path
                content = .received
                return
            }
            guard let sheet = try await core.messageDelivery(messageId) else {
                show(nil, route: [])
                content = .sentElsewhere
                return
            }
            let route = (try? await core.messageRoute(messageId)) ?? []
            show(sheet, route: route)
            content = .sent
        } catch {
            content = .unavailable
        }
    }

    /// `.messages` of this contact reloads (it may have absorbed a state
    /// change); a `.delivery` naming this message refreshes it.
    func handle(_ change: CoreChange) async {
        guard exit == nil else { return }
        switch change {
        case .messages(let c) where c == contact: await load()
        case .delivery(let c, let ids) where c == contact && ids.contains(messageId): await refresh()
        default: break
        }
    }

    /// Fresh delivery of this message; gone means deleted elsewhere.
    func refresh() async {
        guard let update = try? await core.deliveriesOf([messageId]).first else { return }
        if update.removed {
            close(.removedElsewhere)
            return
        }
        guard outgoing, let sheet = try? await core.messageDelivery(messageId) else { return }
        let route = (try? await core.messageRoute(messageId)) ?? []
        show(sheet, route: route)
        content = .sent
    }

    private func show(_ sheet: MessageDelivery?, route: [RouteStepInfo]) {
        self.sheet = sheet
        guard let sheet else {
            lines = []
            verdict = nil
            devices = []
            devicesSentence = nil
            ownCopies = nil
            keepsOwnCopies = false
            return
        }
        let size = route.filter { $0.step == "sealed" && !$0.own }.compactMap(\.size).max()
            ?? sheet.relays.map(\.size).filter { $0 > 0 }.max()
        lines = Self.lines(for: sheet, sealedSize: size, contactName: contactName)
        verdict = Self.verdictPending(sheet.delivery, now: now())
        devices = Self.deviceRows(sheet.devices)
        devicesSentence = Self.devicesSentence(sheet.delivery)
        let copyLeft = route.first { $0.own && $0.step == "deposited" }.map { Date(timeIntervalSince1970: TimeInterval($0.at)) }
        ownCopies = Self.ownCopiesLine(sheet.ownCopies, leftAt: copyLeft)
        keepsOwnCopies = DeleteConfirmation.keepsOwnCopies(delivery: sheet.delivery, ownCopies: sheet.ownCopies)
    }

    #if DEBUG
    /// Previews and renders: a sent message shown as if loaded.
    func preload(quote: String, sheet: MessageDelivery?, route: [RouteStepInfo] = [], now: Date) {
        self.quote = quote
        outgoing = true
        self.now = { now }
        show(sheet, route: route)
        content = sheet == nil ? .sentElsewhere : .sent
    }
    #endif

    private func close(_ why: Exit) {
        if exit == nil { exit = why }
    }

    // MARK: Actions

    /// Sends the not delivered message again; the sheet follows at once.
    func retry() async {
        guard canRetry, !retrying else { return }
        retrying = true
        defer { retrying = false }
        notice = nil
        do {
            try await core.retryMessage(messageId, contact: contact)
        } catch BarkingError.NoSession {
            notice = .noReachableDevice(name: contactName)
        } catch {
            // NothingToRetry: it moved meanwhile; the refresh shows where.
        }
        await refresh()
    }

    /// Deletes the message; `shown` is the delivery the confirmation showed
    /// (its text wins over a change meanwhile, §9). The sheet then closes,
    /// and the conversation says what really happened (§6.7).
    func delete(shown: Delivery?) async {
        guard !deleting, exit == nil else { return }
        deleting = true
        defer { deleting = false }
        notice = nil
        // How many devices it left for, read just before: a delivery shown
        // as Pending has none, and the outcome carries no count (§6.7).
        let fresh = outgoing ? (try? await core.deliveriesOf([messageId]).first)?.delivery : nil
        do {
            let outcome = try await core.deleteMessage(messageId)
            var banner: DeleteBanner.Message?
            if outgoing, content == .sent, let shown {
                let counted = fresh ?? shown
                banner = DeleteBanner.message(shown: shown.state, outcome: outcome, contactName: contactName,
                                              devices: (left: Int(counted.devicesLeft), total: Int(counted.devices)))
            }
            close(.deleted(banner))
        } catch {
            notice = .deleteFailed
        }
    }

    // MARK: Texts (§7.2)

    /// The timeline of a sent message, top to bottom (§6.4 point 3).
    static func lines(for md: MessageDelivery, sealedSize: UInt32?, contactName: String,
                      bundle: Bundle = .main, locale: Locale = .current, timeZone: TimeZone = .current) -> [Line] {
        let d = md.delivery
        let date = { (s: UInt64) in Date(timeIntervalSince1970: TimeInterval(s)) }
        var out: [Line] = []

        let devices = Int(d.devices)
        let sealedDetail: String = if let sealedSize, sealedSize > 0 {
            String(localized: "\(devices) devices · \(ByteSize.kilobytes(UInt64(sealedSize), bundle: bundle, locale: locale))",
                   bundle: bundle, locale: locale)
        } else {
            String(localized: "\(devices) devices", bundle: bundle, locale: locale)
        }
        out.append(Line(id: "sealed", glyph: nil,
                        title: String(localized: "Sealed and saved on this iPhone", bundle: bundle, locale: locale),
                        at: date(d.sealedAt), detail: sealedDetail, phase: .done))

        // One line per distinct relay, in the order of the first deposit.
        var seen: Set<String> = []
        for relay in md.relays where seen.insert(relay.node).inserted {
            let saw: String = if relay.size > 0 {
                String(localized: "Could see: a sealed packet of \(ByteSize.kilobytes(UInt64(relay.size), bundle: bundle, locale: locale)) for a mailbox that changes every day. Not the sender, not the text. The IP address of whoever deposited it.",
                       bundle: bundle, locale: locale)
            } else {
                String(localized: "Could see: a sealed packet for a mailbox that changes every day. Not the sender, not the text. The IP address of whoever deposited it.",
                       bundle: bundle, locale: locale)
            }
            out.append(Line(id: "relay-\(relay.node)", glyph: .onNetwork,
                            title: String(localized: "Deposited on relay \(relay.node)", bundle: bundle, locale: locale),
                            at: date(relay.at), detail: saw, phase: .done, privacy: true, spelled: relay.node))
        }
        let deposited = d.depositedAt != nil || d.devicesLeft > 0
        let anyRelay = seen.isEmpty == false
        let deposit = String(localized: "Deposited on a relay", bundle: bundle, locale: locale)
        if !anyRelay && deposited {
            // A receipt came before the deposit was traced, or a migrated
            // message: the deposit happened, its time is unknown.
            out.append(Line(id: "deposit", glyph: .onNetwork, title: deposit, at: nil, detail: nil, phase: .done))
        }

        if d.state == .notDelivered {
            let expiry = d.expiredAt.map(date)
            let on = expiry.map { dayAndTime($0, bundle: bundle, locale: locale, timeZone: timeZone) }
            let reason: String? = if d.depositedAt == nil && !anyRelay {
                on.map { String(localized: "Expired on \($0) before a relay accepted it. It never left this iPhone.",
                                bundle: bundle, locale: locale) }
            } else {
                on.map { String(localized: "None of \(contactName)’s devices picked it up within 24 hours. The relay erased it on \($0).",
                                bundle: bundle, locale: locale) }
            }
            out.append(Line(id: "stop", glyph: .notDelivered, title: d.state.wordString(bundle: bundle, locale: locale),
                            at: nil, detail: reason, phase: .stopped))
            return out
        }

        if !deposited {
            out.append(Line(id: "deposit", glyph: .onNetwork, title: deposit, at: nil, detail: nil, phase: .ahead))
        }
        let all = String(localized: "Received on all their devices", bundle: bundle, locale: locale)
        let received = Int(d.devicesReceived)
        // Devices that may still receive it: the receipt can still come.
        let open = md.devices.isEmpty
            ? devices - received
            : md.devices.filter { $0.state == .pending || $0.state == .onNetwork }.count
        if devices <= 1 {
            let title = d.state.wordString(bundle: bundle, locale: locale)
            if received > 0 {
                out.append(Line(id: "received", glyph: .received, title: title,
                                at: d.receivedAt.map(date), detail: nil, phase: .done))
            } else {
                out.append(Line(id: "received", glyph: .received,
                                title: String(localized: "Received", bundle: bundle, locale: locale),
                                at: nil, detail: nil, phase: .ahead))
            }
        } else if received >= devices {
            let last = md.devices.compactMap(\.receivedAt).max() ?? d.receivedAt
            out.append(Line(id: "all", glyph: .received, title: all, at: last.map(date), detail: nil, phase: .done))
        } else {
            if received > 0 {
                out.append(Line(id: "received", glyph: .received,
                                title: String(localized: "Received on \(received) of \(devices) devices",
                                              bundle: bundle, locale: locale),
                                at: d.receivedAt.map(date), detail: nil, phase: .done))
            }
            if open > 0 {
                out.append(Line(id: "all", glyph: .received, title: all, at: nil, detail: nil, phase: .ahead))
            }
        }
        return out
    }

    /// Past its expiry, still on the network: the verdict waits for the
    /// next sync (§6.4, §15.5). The state stays "On the network".
    static func verdictPending(_ d: Delivery, now: Date, bundle: Bundle = .main, locale: Locale = .current,
                               timeZone: TimeZone = .current) -> String? {
        guard d.state == .onNetwork else { return nil }
        let expiry = Date(timeIntervalSince1970: TimeInterval(d.sealedAt) + lifetime)
        guard now >= expiry else { return nil }
        return String(localized: "Expired at \(clock(expiry, locale: locale, timeZone: timeZone)). Checking with the relays at the next sync.",
                      bundle: bundle, locale: locale)
    }

    /// "Nov 13 at 11:50", "13 nov. à 11:50".
    static func dayAndTime(_ at: Date, bundle: Bundle = .main, locale: Locale = .current,
                           timeZone: TimeZone = .current) -> String {
        var style = Date.FormatStyle(locale: locale, timeZone: timeZone).day().month(.abbreviated)
        style.timeZone = timeZone
        let day = at.formatted(style)
        let time = clock(at, locale: locale, timeZone: timeZone)
        return String(localized: "\(day) at \(time)", bundle: bundle, locale: locale)
    }

    private static func clock(_ at: Date, locale: Locale, timeZone: TimeZone) -> String {
        // The app's clock (path, bubbles): "14:02", or "2:02 PM" where the
        // region says so.
        var style = Date.FormatStyle(locale: locale, timeZone: timeZone).hour().minute()
        style.timeZone = timeZone
        return at.formatted(style)
    }

    /// One row per device of the contact (§6.4 point 4). Names come from
    /// the card, shown as typed; two alike get the first 4 characters of
    /// their id; a device off the card is "Removed device".
    static func deviceRows(_ devices: [DeviceDelivery], bundle: Bundle = .main, locale: Locale = .current,
                           timeZone: TimeZone = .current) -> [DeviceRow] {
        let removed = String(localized: "Removed device", bundle: bundle, locale: locale)
        let names = devices.map { $0.name.isEmpty ? removed : $0.name }
        let date = { (s: UInt64) in Date(timeIntervalSince1970: TimeInterval(s)) }
        return zip(devices, names).map { d, name in
            let twin = names.filter { $0 == name }.count > 1
            let shown = twin ? "\(name) · \(d.device.prefix(4))" : name
            let status: String = switch d.state {
            case .received:
                d.receivedAt.map { String(localized: "received \(clock(date($0), locale: locale, timeZone: timeZone))",
                                          bundle: bundle, locale: locale) }
                    ?? String(localized: "received", bundle: bundle, locale: locale)
            case .onNetwork:
                d.depositedAt.map { String(localized: "on the network \(clock(date($0), locale: locale, timeZone: timeZone))",
                                           bundle: bundle, locale: locale) }
                    ?? String(localized: "on the network", bundle: bundle, locale: locale)
            case .pending: String(localized: "pending", bundle: bundle, locale: locale)
            case .notDelivered: String(localized: "not delivered", bundle: bundle, locale: locale)
            }
            return DeviceRow(id: d.device, name: shown, status: status, state: d.state)
        }
    }

    /// "Received on 1 of 2 devices." once at least one has it.
    static func devicesSentence(_ d: Delivery, bundle: Bundle = .main, locale: Locale = .current) -> String? {
        guard d.devices > 1, d.devicesReceived > 0 else { return nil }
        return String(localized: "Received on \(Int(d.devicesReceived)) of \(Int(d.devices)) devices.",
                      bundle: bundle, locale: locale)
    }

    /// My copies for my other devices; nil without a linked device. Copies
    /// that expired here are not mentioned: nothing true to add.
    static func ownCopiesLine(_ c: OwnCopies, leftAt: Date?, bundle: Bundle = .main, locale: Locale = .current,
                              timeZone: TimeZone = .current) -> String? {
        guard c.total > 0 else { return nil }
        if c.left > 0 {
            guard let leftAt else {
                return String(localized: "Copy for your other devices: left.", bundle: bundle, locale: locale)
            }
            return String(localized: "Copy for your other devices: left at \(clock(leftAt, locale: locale, timeZone: timeZone)).",
                          bundle: bundle, locale: locale)
        }
        if c.waiting > 0 {
            return String(localized: "Copy for your other devices: pending.", bundle: bundle, locale: locale)
        }
        return nil
    }

    /// A line as a `DeliveryTimeline` step; a relay id is spelled out.
    private static func step(_ line: Line) -> DeliveryTimeline.Step {
        var title = AttributedString(line.title)
        if let spelled = line.spelled, let range = title.range(of: spelled) {
            title[range].accessibilitySpeechSpellsOutCharacters = true
        }
        return DeliveryTimeline.Step(id: line.id, glyph: line.glyph, title: Text(title), at: line.at,
                                     detail: line.detail.map { Text(verbatim: $0) }, phase: line.phase,
                                     privacy: line.privacy)
    }
}
