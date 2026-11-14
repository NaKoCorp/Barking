import XCTest
@testable import BarkingKit

/// The extension's run reads the preview and notes the wake with the
/// database open (spec §5.5).
final class BenchRunWakeTests: XCTestCase {
    private func run(_ device: FakeDevice?, sync: Bool = true, paths: WipePaths? = nil) -> (BenchRecord, PushPreview) {
        let dir = FileManager.default.temporaryDirectory.appending(path: "bench-wake-\(UUID())")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        let paths = paths ?? WipePaths(container: dir, temporary: dir, defaults: [], lockTimeoutMs: 100)
        let (record, _, preview) = BenchRun.run(source: "test", paths: paths, sync: sync) { _ in device }
        return (record, preview)
    }

    func testReadsThePreviewAndNotesTheWake() {
        let d = FakeDevice()
        d.prefs.preview = .nameOnly
        let (_, preview) = run(d)
        XCTAssertEqual(preview, .nameOnly)
        XCTAssertEqual(d.wakeNotes.count, 1)
    }

    func testUnreadablePrefsGiveGenericButTheWakeIsNoted() {
        let d = FakeDevice()
        d.prefsError = BarkingError.Locked
        let (_, preview) = run(d)
        XCTAssertEqual(preview, .generic)
        XCTAssertEqual(d.wakeNotes.count, 1)
    }

    func testTheWakeIsNotedEvenWhenTheQuickSyncThrows() {
        let d = FakeDevice()
        d.prefs.preview = .nameAndText
        d.quickSyncError = BarkingError.Locked
        let (record, preview) = run(d)
        XCTAssertEqual(record.outcome, "locked")
        XCTAssertEqual(preview, .nameAndText)
        XCTAssertEqual(d.wakeNotes.count, 1)
    }

    func testNoSyncReadsAndNotesNothing() {
        let d = FakeDevice()
        d.prefs.preview = .nameOnly
        let (record, preview) = run(d, sync: false)
        XCTAssertEqual(record.outcome, "opened")
        XCTAssertEqual(preview, .generic)
        XCTAssertTrue(d.wakeNotes.isEmpty)
    }

    func testNoDeviceIsGeneric() {
        let (record, preview) = run(nil)
        XCTAssertEqual(record.outcome, "no-key")
        XCTAssertEqual(preview, .generic)
    }

    func testWipePendingOpensNothing() throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "bench-wake-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        FileManager.default.createFile(atPath: dir.appending(path: Wipe.markerName).path, contents: Data())
        let d = FakeDevice()
        let (record, preview) = run(d, paths: WipePaths(container: dir, temporary: dir, defaults: [], lockTimeoutMs: 100))
        XCTAssertEqual(record.outcome, BenchRun.wipePending)
        XCTAssertEqual(preview, .generic)
        XCTAssertTrue(d.wakeNotes.isEmpty)
    }
}
