import XCTest
@testable import BarkingKit

/// Records the key deletion; can fail it.
final class FakeKeys: KeyWiping, @unchecked Sendable {
    private let lock = NSLock()
    private var _deleted = false
    var fails = false
    /// Calls that fail before the others succeed.
    var failuresLeft = 0
    var deleted: Bool { lock.withLock { _deleted } }

    struct Failure: Error {}

    func deleteAll() throws {
        if fails { throw Failure() }
        let failNow = lock.withLock { () -> Bool in
            guard failuresLeft > 0 else { return false }
            failuresLeft -= 1
            return true
        }
        if failNow { throw Failure() }
        lock.withLock { _deleted = true }
    }
}

final class WipeTests: XCTestCase {
    private var container: URL!
    private var temporary: URL!
    private var suite: String!
    private var defaults: UserDefaults!

    override func setUpWithError() throws {
        let base = FileManager.default.temporaryDirectory.appending(path: "wipe-\(UUID())")
        container = base.appending(path: "container")
        temporary = base.appending(path: "tmp")
        for dir in [container!, temporary!] {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        }
        suite = "wipe.tests.\(UUID())"
        defaults = UserDefaults(suiteName: suite)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: container.deletingLastPathComponent())
        defaults.removePersistentDomain(forName: suite)
    }

    private var paths: WipePaths {
        WipePaths(container: container, temporary: temporary, defaults: [defaults], lockTimeoutMs: 200)
    }

    private func touch(_ dir: URL, _ names: [String]) throws {
        for name in names {
            let url = dir.appending(path: name)
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                    withIntermediateDirectories: true)
            try Data([1, 2, 3]).write(to: url)
        }
    }

    private func exists(_ dir: URL, _ name: String) -> Bool {
        FileManager.default.fileExists(atPath: dir.appending(path: name).path)
    }

    private let databaseFiles = ["barking.db", "barking.db-wal", "barking.db-shm", "barking.db-journal",
                                 "barking.lock", "outbox.export", "tablet.barkinglink", "bench/run.json",
                                 "dev-card.txt"]

    func testRemovesEveryFile() throws {
        try touch(container, databaseFiles)
        try touch(container, [".com.apple.mobile_container_manager.metadata.plist", "Library/Preferences/x.plist"])
        try touch(temporary, ["tablet.barkinglink", "Alice.barkingcard", "unrelated.txt"])
        defaults.set(true, forKey: "barking.phraseConfirmed")
        defaults.set("dark", forKey: "barking.appearance")
        defaults.set(1, forKey: "unrelated")
        let keys = FakeKeys()

        try Wipe.run(paths: paths, keys: keys)

        for name in databaseFiles + ["bench", Wipe.markerName] {
            XCTAssertFalse(exists(container, name), name)
        }
        // The system's own files keep the container alive.
        XCTAssertTrue(exists(container, ".com.apple.mobile_container_manager.metadata.plist"))
        XCTAssertTrue(exists(container, "Library/Preferences/x.plist"))
        XCTAssertFalse(exists(temporary, "tablet.barkinglink"))
        XCTAssertFalse(exists(temporary, "Alice.barkingcard"))
        XCTAssertTrue(exists(temporary, "unrelated.txt"))
        XCTAssertNil(defaults.object(forKey: "barking.phraseConfirmed"))
        XCTAssertNil(defaults.object(forKey: "barking.appearance"))
        XCTAssertEqual(defaults.integer(forKey: "unrelated"), 1)
        XCTAssertTrue(keys.deleted)
    }

    func testResumesAfterInterruption() throws {
        // No marker: nothing to resume, nothing touched.
        try touch(container, ["barking.db"])
        let untouched = FakeKeys()
        XCTAssertFalse(try Wipe.resumeIfNeeded(paths: paths, keys: untouched))
        XCTAssertTrue(exists(container, "barking.db"))
        XCTAssertFalse(untouched.deleted)

        // Killed after the marker: the next launch finishes the wipe.
        try touch(container, [Wipe.markerName, "barking.db-wal"])
        let keys = FakeKeys()
        XCTAssertTrue(try Wipe.resumeIfNeeded(paths: paths, keys: keys))
        for name in ["barking.db", "barking.db-wal", Wipe.markerName] {
            XCTAssertFalse(exists(container, name), name)
        }
        XCTAssertTrue(keys.deleted)
    }

    /// A step that fails leaves the marker: the next launch tries again.
    func testFailureKeepsTheMarker() throws {
        try touch(container, ["barking.db"])
        let keys = FakeKeys()
        keys.fails = true
        XCTAssertThrowsError(try Wipe.run(paths: paths, keys: keys))
        XCTAssertFalse(exists(container, "barking.db"))
        XCTAssertTrue(exists(container, Wipe.markerName))

        // Still failing at launch: the launch is told, the marker stays.
        XCTAssertThrowsError(try Wipe.resumeIfNeeded(paths: paths, keys: keys))
        XCTAssertTrue(Wipe.isPending(paths: paths))

        keys.fails = false
        XCTAssertTrue(try Wipe.resumeIfNeeded(paths: paths, keys: keys))
        XCTAssertFalse(exists(container, Wipe.markerName))
        XCTAssertTrue(keys.deleted)
    }

    /// The extension holding the lock delays the wipe, never prevents it.
    func testLockHeldElsewhereStillWipes() throws {
        try touch(container, ["barking.db", "barking.lock"])
        let fd = open(container.appending(path: "barking.lock").path, O_RDWR)
        XCTAssertGreaterThanOrEqual(fd, 0)
        XCTAssertEqual(flock(fd, LOCK_EX | LOCK_NB), 0)
        defer { close(fd) }

        try Wipe.run(paths: paths, keys: FakeKeys())
        XCTAssertFalse(exists(container, "barking.db"))
    }

    func testWithoutContainerStillDeletesTheKey() throws {
        let keys = FakeKeys()
        let noContainer = WipePaths(container: nil, temporary: temporary, defaults: [defaults], lockTimeoutMs: 200)
        try Wipe.run(paths: noContainer, keys: keys)
        XCTAssertTrue(keys.deleted)
    }

    /// The wipe waits for the calls in flight, then the service refuses new ones.
    func testRunClosingTheServiceStopsIt() async throws {
        try touch(container, ["barking.db"])
        let core = CoreService(device: FakeDevice(), runner: DirectRunner())
        try await Wipe.run(closing: core, paths: paths, keys: FakeKeys())
        XCTAssertFalse(exists(container, "barking.db"))
        do {
            _ = try await core.fingerprint()
            XCTFail("the service still answers")
        } catch {}
    }

    /// One failure is retried at once; two are reported, marker kept.
    func testRunClosingRetriesOnceThenThrows() async throws {
        try touch(container, ["barking.db"])
        let once = FakeKeys()
        once.failuresLeft = 1
        try await Wipe.run(closing: nil, paths: paths, keys: once)
        XCTAssertFalse(Wipe.isPending(paths: paths))
        XCTAssertTrue(once.deleted)

        let twice = FakeKeys()
        twice.failuresLeft = 2
        do {
            try await Wipe.run(closing: nil, paths: paths, keys: twice)
            XCTFail("a wipe that failed twice must throw")
        } catch {}
        XCTAssertTrue(Wipe.isPending(paths: paths))
    }

    /// A new identity first finishes the pending wipe (or is refused), so the
    /// marker can never erase an identity created after it.
    func testPendingWipeFinishesBeforeANewIdentity() throws {
        try touch(container, [Wipe.markerName, "barking.db"])
        let failing = FakeKeys()
        failing.fails = true
        XCTAssertThrowsError(try Wipe.finishPending(paths: paths, keys: failing))
        XCTAssertTrue(Wipe.isPending(paths: paths))

        try Wipe.finishPending(paths: paths, keys: FakeKeys())
        XCTAssertFalse(Wipe.isPending(paths: paths))
        // The new identity's database: the next launch leaves it alone.
        try touch(container, ["barking.db"])
        XCTAssertFalse(try Wipe.resumeIfNeeded(paths: paths, keys: FakeKeys()))
        XCTAssertTrue(exists(container, "barking.db"))
        // Nothing pending: nothing to do.
        try Wipe.finishPending(paths: paths, keys: failing)
    }

    /// The extension's work never opens the database while a wipe is under
    /// way: the push goes out as it came, nothing is recorded.
    func testExtensionSkipsTheDatabaseWhileAWipeIsPending() throws {
        try touch(container, [Wipe.markerName, "barking.db"])
        XCTAssertNil(try DeviceFactory.existing(lockTimeoutMs: 100, paths: paths))
        let (record, summary) = BenchRun.run(source: "test", paths: paths)
        XCTAssertEqual(record.outcome, BenchRun.wipePending)
        XCTAssertNil(summary)
        XCTAssertFalse(record.steps.contains { $0.name == "opened" })
    }
}
