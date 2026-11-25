import Darwin
import XCTest
@testable import Barking
@testable import BarkingKit

/// A conversation opens at once while a long sync is in flight: the sync
/// holds the database lock for its whole run, but the reads of the app
/// join it instead of waiting for it (barking-ffi `DbLock::acquire_read`).
@MainActor
final class SyncReadsTests: XCTestCase {
    /// A node identifier that solves the identity puzzle (barking-node
    /// `testing::id_of(&key(0))`).
    private static let nodeId = "RU5BSFBEW6TLG4MHDVARRZNWHZHA23JZR2IJCDTAVMNF7V6CA2IQ"
    /// Any identifier: a block does not check the puzzle.
    private static let blockedId = String(repeating: "A", count: 50) + "XQ"

    func testConversationShowsWhileASyncIsInFlight() async throws {
        var cfg = try TestDevice.config(lockTimeoutMs: Budget.appLockMs)
        cfg.allowPrivate = true
        let alice = try createDevice(config: cfg, deviceName: "alice").device
        let bob = try createDevice(config: try TestDevice.config(), deviceName: "bob").device
        let fp = try alice.addContact(card: try bob.contactCard(displayName: "Bob"), alias: "bob")
        try alice.sendText(contact: fp, text: "hello", replyTo: nil)
        // A node that never answers: the sync runs for its whole deadline,
        // as against a reachable but slow node.
        let hole = try SilentPort()
        defer { hole.close() }
        try alice.addNode(id: Self.nodeId, addr: "127.0.0.1:\(hole.port)")

        let runner = AppCallRunner()
        let sync = Task.detached { () -> TimeInterval in
            let start = Date()
            _ = try? await runner.run("sync") { try alice.sync(deadlineMs: 3_000) }
            return Date().timeIntervalSince(start)
        }
        try await waitForSyncLock(cfg)

        let model = ConversationModel(contact: fp, core: CoreService(device: alice, runner: runner))
        let start = Date()
        await model.onAppear()
        let opened = Date().timeIntervalSince(start)
        XCTAssertLessThan(opened, 1, "the conversation waited for the sync")
        XCTAssertEqual(model.items.map(\.text), ["hello"])
        XCTAssertEqual(model.name, "bob")
        XCTAssertFalse(model.removed)

        // The sync was still running: the reads did not come after it.
        let took = await sync.value
        XCTAssertGreaterThan(took, opened + 1)
    }

    /// The Network tab opens on the relays it knows while the launch sync
    /// is still running, and so do the blocked nodes: neither list waits
    /// for the sync.
    func testNetworkShowsKnownRelaysWhileASyncIsInFlight() async throws {
        var cfg = try TestDevice.config(lockTimeoutMs: Budget.appLockMs)
        cfg.allowPrivate = true
        let alice = try createDevice(config: cfg, deviceName: "alice").device
        let hole = try SilentPort()
        defer { hole.close() }
        try alice.addNode(id: Self.nodeId, addr: "127.0.0.1:\(hole.port)")
        try alice.blockNode(id: Self.blockedId)

        let core = CoreService(device: alice, runner: AppCallRunner())
        let sync = Task.detached { () -> TimeInterval in
            let start = Date()
            _ = await core.sync(reason: .launch)
            return Date().timeIntervalSince(start)
        }
        try await waitForSyncLock(cfg)

        let model = NetworkModel(core: core)
        let start = Date()
        await model.load()
        let opened = Date().timeIntervalSince(start)
        XCTAssertLessThan(opened, 1, "the relays waited for the sync")
        XCTAssertEqual((model.inUse + model.others).map(\.id), [Self.nodeId])
        XCTAssertEqual(model.blockedCount, 1)
        XCTAssertTrue(model.loaded)
        XCTAssertFalse(model.loadFailed)
        XCTAssertEqual(model.status, .checking, "the launch sync shows as running")

        let blocked = BlockedNodesModel(core: core)
        let listed = Date()
        await blocked.load()
        XCTAssertLessThan(Date().timeIntervalSince(listed), 1, "the blocked nodes waited for the sync")
        XCTAssertEqual(blocked.nodes.map(\.id), [Self.blockedId])

        let took = await sync.value
        XCTAssertGreaterThan(took, opened + 1)
    }

    /// Waits until the sync holds the lock: an opening then gives up.
    private func waitForSyncLock(_ cfg: DeviceConfig) async throws {
        for _ in 0..<500 {
            do {
                _ = try Device.open(config: TestDevice.with(cfg, lockTimeoutMs: 1))
            } catch BarkingError.Locked {
                return
            }
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTFail("the sync never took the lock")
    }
}

/// A local UDP port that receives and never answers.
private struct SilentPort {
    let fd: Int32
    let port: UInt16

    init() throws {
        fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { throw POSIXError(.EBADF) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = 0
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let fd = self.fd
        let bound = withUnsafeMutablePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { s in
                bind(fd, s, len) == 0 && getsockname(fd, s, &len) == 0
            }
        }
        guard bound else {
            Darwin.close(fd)
            throw POSIXError(.EADDRNOTAVAIL)
        }
        port = UInt16(bigEndian: addr.sin_port)
    }

    func close() { Darwin.close(fd) }
}
