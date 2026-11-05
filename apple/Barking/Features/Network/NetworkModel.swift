import BarkingKit
import Foundation
import Observation

/// Network tab (screen 7, spec §5.7): Internet only in this block.
@MainActor @Observable
final class NetworkModel {
    private let core: CoreService
    private(set) var internetReachable: Bool?
    private(set) var lastSync: Date?
    private(set) var pending = 0
    private(set) var relays: [NodeInfo] = []
    private(set) var terminal: [String] = []
    private(set) var syncing = false
    var addError: String?

    init(core: CoreService) { self.core = core }

    func load() async {
        internetReachable = await core.lastSync?.networkUp
        lastSync = await core.lastSyncAt
        pending = (try? await core.outboxCount()) ?? 0
        relays = (try? await core.nodes()) ?? []
    }

    func syncNow() async {
        syncing = true
        defer { syncing = false }
        let outcome = await core.sync(reason: .pull)
        terminal = outcome.lines
        await load()
    }

    /// `barking://node#<52-char id>@<ip:port>`.
    static func parseRelay(link: String) -> (id: String, addr: String)? {
        guard let url = URL(string: link), url.scheme == "barking", url.host() == "node",
              let frag = url.fragment(percentEncoded: false),
              let at = frag.lastIndex(of: "@") else { return nil }
        return validRelay(id: String(frag[..<at]), addr: String(frag[frag.index(after: at)...]))
    }

    static func validRelay(id: String, addr: String) -> (id: String, addr: String)? {
        let id = id.trimmingCharacters(in: .whitespaces).uppercased()
        let addr = addr.trimmingCharacters(in: .whitespaces)
        let base32 = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        guard id.count == 52, id.unicodeScalars.allSatisfy(base32.contains),
              let colon = addr.lastIndex(of: ":"), Int(addr[addr.index(after: colon)...]) != nil
        else { return nil }
        return (id, addr)
    }

    func addRelay(id: String, addr: String) async -> Bool {
        guard let r = Self.validRelay(id: id, addr: addr) else {
            addError = "Check the identifier (52 characters) and the address (ip:port)."
            return false
        }
        do {
            try await core.addNode(id: r.id, addr: r.addr)
            addError = nil
            await load()
            return true
        } catch {
            addError = "This relay could not be added."
            return false
        }
    }
}

/// Settings tab (screen 8): language, appearance, display name.
@MainActor @Observable
final class SettingsModel {
    private let core: CoreService
    private(set) var displayName = ""
    private(set) var fingerprint = ""

    init(core: CoreService) { self.core = core }

    /// 1 to 64 characters, edges trimmed (the core's limit is 64 bytes).
    static func validName(_ s: String) -> String? {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        return (1...64).contains(t.utf8.count) ? t : nil
    }

    func load() async {
        displayName = (try? await core.displayName()) ?? ""
        fingerprint = (try? await core.fingerprint()) ?? ""
    }

    func rename(_ s: String) async {
        guard let n = Self.validName(s) else { return }
        try? await core.setDisplayName(n)
        await load()
    }

    var fingerprintShort: String {
        let g = fingerprint.split(separator: "-").prefix(4).map(String.init)
        return g.count == 4 ? "\(g[0]) \(g[1]) · \(g[2]) \(g[3])" : fingerprint
    }
}

/// Linked devices (screen 9).
@MainActor @Observable
final class DevicesModel {
    private let core: CoreService
    private(set) var devices: [MyDeviceInfo] = []
    /// The device a root key transfer awaits the ack of.
    private(set) var pendingTarget: String?
    /// Removed from the account by a newer device list.
    private(set) var removed = false
    private(set) var transferFailed = false

    init(core: CoreService) { self.core = core }

    private var isAdmin: Bool { devices.contains { $0.thisDevice && $0.admin } }
    var canLink: Bool { isAdmin && pendingTarget == nil && !removed }
    var count: Int { devices.count }

    /// Only the administrator, to another device, one transfer at a time.
    func canTransfer(to device: MyDeviceInfo) -> Bool { canLink && !device.thisDevice }

    func load() async {
        devices = (try? await core.myDevices()) ?? []
        pendingTarget = try? await core.adminTransferPending()
        removed = ((try? await core.removed()) ?? nil) != nil
    }

    func transfer(to device: MyDeviceInfo) async {
        transferFailed = false
        do {
            try await core.transferAdmin(to: device.id)
        } catch {
            transferFailed = true
        }
        await load()
    }
}
