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

/// Linked devices (screen 9): linking, the admin transfer, removing a
/// device, and leaving the account (spec §8.2).
@MainActor @Observable
final class DevicesModel {
    /// What "Disconnect this device" does here.
    enum DisconnectPlan: Equatable {
        /// A linked device: my other devices remove it, then the wipe.
        case leave
        /// The administrator with other devices: one of them takes the root
        /// key, removes this one at its ack, then the wipe.
        case handOver(candidates: [MyDeviceInfo])
        /// The administrator alone: the wipe, nobody is told.
        case erase
    }

    /// Where a departure stands.
    enum Departure: Equatable {
        case idle
        /// The root key is on its way to `name`; the wipe follows its ack.
        case handingOver(name: String)
        /// The transfer expired: nothing erased, this device keeps the root.
        case handoverFailed(name: String)
        /// The request to be removed is queued; a sync sends it.
        case sending
        /// The sync could not reach the network: nothing erased yet.
        case offline
        case failed
        /// Erased: back to the welcome screen.
        case wiped
    }

    private let core: CoreService
    private let owner: () async -> Bool
    private let wipe: (CoreService) async -> Void
    private(set) var devices: [MyDeviceInfo] = []
    /// The device a root key transfer awaits the ack of.
    private(set) var pendingTarget: String?
    /// Removed from the account by a newer device list.
    private(set) var removed = false
    private(set) var transferFailed = false
    private(set) var removeFailed = false
    private(set) var departure: Departure = .idle

    init(core: CoreService,
         owner: @escaping () async -> Bool = { await Owner.check() },
         wipe: @escaping (CoreService) async -> Void = { try? await Wipe.run(closing: $0) }) {
        self.core = core
        self.owner = owner
        self.wipe = wipe
    }

    private var isAdmin: Bool { devices.contains { $0.thisDevice && $0.admin } }
    var canLink: Bool { isAdmin && pendingTarget == nil && !removed && departure == .idle }
    var count: Int { devices.count }

    /// Only the administrator, to another device, one transfer at a time.
    func canTransfer(to device: MyDeviceInfo) -> Bool { canLink && !device.thisDevice }
    /// Only the administrator removes, and never itself (it disconnects).
    func canRemove(_ device: MyDeviceInfo) -> Bool { canLink && !device.thisDevice }
    /// This device, while it still belongs to the account (a removed device
    /// resets from its banner) and no transfer is under way.
    func canDisconnect(_ device: MyDeviceInfo) -> Bool {
        device.thisDevice && !removed && pendingTarget == nil && departure == .idle
    }

    var disconnectPlan: DisconnectPlan {
        guard isAdmin else { return .leave }
        let others = devices.filter { !$0.thisDevice }
        return others.isEmpty ? .erase : .handOver(candidates: others)
    }

    func load() async {
        devices = (try? await core.myDevices()) ?? []
        pendingTarget = try? await core.adminTransferPending()
        removed = ((try? await core.removed()) ?? nil) != nil
        // Killed after `leave` or after the handover's ack: the request is
        // queued, the departure finishes here.
        if departure == .idle, (try? await core.leaveReady()) == true {
            departure = .sending
            await finishLeaving()
        }
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

    func remove(_ device: MyDeviceInfo) async {
        guard await owner() else { return }
        removeFailed = false
        do {
            try await core.removeDevice(device.id)
        } catch {
            removeFailed = true
        }
        await load()
    }

    /// "Disconnect this device", once confirmed, for `.leave` and `.erase`
    /// (`.handOver` goes through `handOver(to:)`).
    func disconnect() async {
        guard departure == .idle, await owner() else { return }
        switch disconnectPlan {
        case .erase:
            await finish()
        case .leave:
            do {
                try await core.leave()
                departure = .sending
                await finishLeaving()
            } catch {
                departure = .failed
            }
        case .handOver:
            break
        }
    }

    /// The administrator leaves through `device`.
    func handOver(to device: MyDeviceInfo) async {
        guard departure == .idle, await owner() else { return }
        transferFailed = false
        do {
            try await core.transferAndLeave(to: device.id)
            departure = .handingOver(name: device.name)
        } catch {
            transferFailed = true
        }
        await load()
    }

    /// One step of the handover: a sync, then the wipe once the request to
    /// be removed is queued. A transfer that expired leaves `leave_ready`
    /// false forever (known core limit): the handover failed, nothing erased.
    func pollHandover() async {
        guard case .handingOver(let name) = departure else { return }
        _ = await core.sync(reason: .timer)
        if (try? await core.leaveReady()) == true {
            departure = .sending
            await finishLeaving()
        } else if (try? await core.adminTransferPending()) == nil {
            departure = .handoverFailed(name: name)
            await load()
        }
    }

    /// Sends the queued request to be removed, then wipes. Offline: nothing
    /// is erased, the user tries again.
    func finishLeaving() async {
        guard departure == .sending || departure == .offline else { return }
        let outcome = await core.sync(reason: .afterSend)
        guard outcome.networkUp, (try? await core.leaveReady()) == true else {
            departure = .offline
            return
        }
        await finish()
    }

    func dismissDeparture() {
        if case .handoverFailed = departure { departure = .idle }
        if departure == .failed { departure = .idle }
    }

    private func finish() async {
        await wipe(core)
        departure = .wiped
    }
}
