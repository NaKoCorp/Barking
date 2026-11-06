import BarkingKit
import Foundation
import Observation

/// Route badge (bubbles, chats list): "Internet · 2 relays" from the core's
/// hint `internet:N`.
enum RouteBadge {
    static func text(for hint: String?) -> String? {
        guard let hint, hint.hasPrefix("internet:"), let n = Int(hint.dropFirst("internet:".count)), n > 0 else {
            return nil
        }
        return String(localized: "Internet · \(n) relays")
    }
}

/// Sizes in the UI (UI review §6 units): whole kilobytes of 1024 bytes, no
/// decimals, at least 1 KB. Raw bytes belong to exports only.
enum ByteSize {
    static func kilobytes(_ bytes: UInt64) -> String {
        let kb = max(1, Int((Double(bytes) / 1024).rounded()))
        return String(localized: "\(kb) KB")
    }
}

/// One stop of a message's way on the path screen.
struct PathRow: Identifiable, Equatable {
    enum Glyph: Equatable { case sender, relay, recipient, ownDevices }

    var id: String { "\(glyph)-\(title)" }
    let title: String
    let subtitle: String
    /// What this stop could see, after "Could see:".
    let saw: String
    let glyph: Glyph

    /// One sentence for VoiceOver (U-36): "iPhone, wrote and encrypted,
    /// 11:58. Could see: everything…", without the "·" separators.
    var spoken: String {
        let plain = { (s: String) in s.replacingOccurrences(of: " · ", with: ", ") }
        return "\(plain(title)), \(plain(subtitle)). \(String(localized: "Could see:")) \(saw)"
    }
}

/// Message path screen (spec block 2b §4.2): only the recorded steps show.
@MainActor @Observable
final class PathModel {
    private let core: CoreService
    let messageId: Int64
    let contact: String
    let contactName: String
    private(set) var rows: [PathRow] = []
    private(set) var notRecorded = false
    private(set) var quote = ""
    private(set) var routeBadge: String?
    /// "sent 18:01", "receipt 18:02": one tag each (U-18), so a tag never
    /// wraps inside itself in French.
    private(set) var times: [String] = []

    init(core: CoreService, messageId: Int64, contact: String, contactName: String) {
        self.core = core
        self.messageId = messageId
        self.contact = contact
        self.contactName = contactName
    }

    func load() async {
        let message = try? await core.messages(with: contact).first { $0.id == messageId }
        var steps = (try? await core.messageRoute(messageId)) ?? []
        var hint = message?.route
        #if BARKING_DEV
        if ProcessInfo.processInfo.arguments.contains("-BarkingUITestFakeRoute"), let message, steps.count < 2 {
            steps = Self.uiTestRoute(for: message)
            hint = "internet:1"
        }
        #endif
        let outgoing = message?.outgoing ?? false
        // This device by its name (an iPad is not "your iPhone").
        let me = (try? await core.myDevices())?.first { $0.thisDevice }?.name
        quote = message?.body ?? ""
        routeBadge = RouteBadge.text(for: hint)
        rows = Self.rows(for: steps, outgoing: outgoing, contactName: contactName,
                         thisDevice: me ?? String(localized: "This device"))
        notRecorded = rows.isEmpty
        times = Self.times(for: steps, outgoing: outgoing)
    }

    // MARK: Rows

    static func rows(for steps: [RouteStepInfo], outgoing: Bool, contactName: String,
                     thisDevice: String) -> [PathRow] {
        guard !steps.isEmpty else { return [] }
        let first = { (name: String) in steps.first { $0.step == name } }
        var out: [PathRow] = []
        let syncCopy = outgoing && first("sealed") == nil && first("opened") != nil
        if syncCopy {
            // A message I sent from another of my devices, received here as
            // its copy: that device wrote it, this one fetched and opened it.
            out.append(PathRow(
                title: String(localized: "Your other device"),
                subtitle: String(localized: "wrote and encrypted"),
                saw: String(localized: "everything — it is the sender."),
                glyph: .sender))
            out += relays(steps, step: "fetched", size: nil)
            if let opened = first("opened") {
                out.append(PathRow(
                    title: thisDevice,
                    subtitle: String(localized: "synced copy · \(clock(opened.at))"),
                    saw: String(localized: "the message, encrypted between your own devices."),
                    glyph: .ownDevices))
            }
        } else if outgoing {
            let sealed = first("sealed")
            out.append(PathRow(
                title: thisDevice,
                subtitle: sealed.map { String(localized: "wrote and encrypted · \(clock($0.at))") }
                    ?? String(localized: "wrote and encrypted"),
                saw: String(localized: "everything — it is the sender."),
                glyph: .sender))
            // The packet's size: the one sealed for the contact.
            let size = steps.filter { $0.step == "sealed" && !$0.own }.compactMap(\.size).max()
            // Deposits of the copies to my devices belong to their row.
            out += relays(steps.filter { !$0.own }, step: "deposited", size: size)
            // Only the contact's receipt: one of my devices acknowledges
            // its copy too, and that is not the contact getting it.
            if let ack = steps.first(where: { $0.step == "ack_verified" && !$0.own }) {
                out.append(PathRow(
                    title: String(localized: "\(contactName)'s phone"),
                    subtitle: String(localized: "receipt received · \(clock(ack.at))"),
                    saw: String(localized: "everything — it is the recipient."),
                    glyph: .recipient))
            }
            let copies = steps.filter { $0.step == "own_copy" }
            if let copy = copies.first {
                var names: [String] = []
                for n in copies.compactMap(\.deviceName) where !names.contains(n) { names.append(n) }
                let title = names.isEmpty
                    ? String(localized: "Your other devices")
                    : String(localized: "Your other devices · \(names.joined(separator: ", "))")
                out.append(PathRow(
                    title: title,
                    subtitle: String(localized: "copy encrypted · \(clock(copy.at))"),
                    saw: String(localized: "the message, encrypted between your own devices."),
                    glyph: .ownDevices))
            }
        } else {
            out.append(PathRow(
                title: String(localized: "\(contactName)'s phone"),
                subtitle: String(localized: "wrote and encrypted"),
                saw: String(localized: "everything — it is the sender."),
                glyph: .sender))
            out += relays(steps, step: "fetched", size: nil)
            if let opened = first("opened") {
                // The receipt leaves with the next sync: the app cannot
                // tell when.
                out.append(PathRow(
                    title: thisDevice,
                    subtitle: String(localized: "decrypted · \(clock(opened.at)) · receipt queued"),
                    saw: String(localized: "everything — it is the recipient."),
                    glyph: .recipient))
            }
        }
        return out
    }

    /// One row per relay node, in the order the packet reached them
    /// (`deposited` on a sent message, `fetched` on a received one).
    private static func relays(_ steps: [RouteStepInfo], step: String, size: UInt32?) -> [PathRow] {
        var seen: Set<String> = []
        return steps.filter { $0.step == step }.compactMap { s -> PathRow? in
            guard let node = s.node, seen.insert(node).inserted else { return nil }
            let deposited = step == "deposited"
            // A received packet's size is not recorded (only `sealed` has one).
            let saw: String
            if !deposited {
                saw = String(localized: "a sealed packet for a mailbox that changes every day. Not the sender, not the text. The IP address of whoever fetched it.")
            } else if let size {
                let bytes = ByteSize.kilobytes(UInt64(size))
                saw = String(localized: "a sealed packet of \(bytes) for a mailbox that changes every day. Not the sender, not the text. The IP address of whoever deposited it.")
            } else {
                saw = String(localized: "a sealed packet for a mailbox that changes every day. Not the sender, not the text. The IP address of whoever deposited it.")
            }
            return PathRow(
                title: String(localized: "Internet relay · \(node)"),
                subtitle: deposited
                    ? String(localized: "deposited · \(clock(s.at))")
                    : String(localized: "fetched · \(clock(s.at))"),
                saw: saw,
                glyph: .relay)
        }
    }

    /// ["sent 18:01", "receipt 18:02"], from the recorded steps: the
    /// receipt time is when my device verified it.
    static func times(for steps: [RouteStepInfo], outgoing: Bool) -> [String] {
        var parts: [String] = []
        let sealed = steps.first(where: { $0.step == "sealed" })
        let opened = steps.first(where: { $0.step == "opened" })
        if outgoing, sealed == nil, let o = opened {
            parts.append(String(localized: "synced \(clock(o.at))"))
        } else if outgoing {
            if let s = sealed { parts.append(String(localized: "sent \(clock(s.at))")) }
            if let a = steps.first(where: { $0.step == "ack_verified" && !$0.own }) {
                parts.append(String(localized: "receipt \(clock(a.at))"))
            }
        } else if let o = opened {
            parts.append(String(localized: "received \(clock(o.at))"))
        }
        return parts
    }

    private static func clock(_ at: UInt64) -> String {
        Date(timeIntervalSince1970: TimeInterval(at)).formatted(.dateTime.hour().minute())
    }

    #if BARKING_DEV
    /// UI tests (screenshot of the path screen): a real message on a fake
    /// route, as a sync over the internet would record it.
    private static func uiTestRoute(for m: Message) -> [RouteStepInfo] {
        if m.outgoing {
            return [
                RouteStepInfo(at: m.at, step: "sealed", node: nil, size: 2048, deviceName: nil, own: false),
                RouteStepInfo(at: m.at + 1, step: "deposited", node: "K7QX2M4A", size: nil, deviceName: nil, own: false),
                RouteStepInfo(at: m.at + 60, step: "ack_verified", node: nil, size: nil, deviceName: nil, own: false),
            ]
        }
        return [
            RouteStepInfo(at: m.at, step: "fetched", node: "K7QX2M4A", size: nil, deviceName: nil, own: false),
            RouteStepInfo(at: m.at, step: "opened", node: nil, size: nil, deviceName: nil, own: false),
        ]
    }
    #endif
}
