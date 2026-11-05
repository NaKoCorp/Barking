import XCTest
@testable import BarkingKit

extension BenchRecord {
    static func fixture(totalMs: UInt64) -> BenchRecord {
        BenchRecord(source: "extension", device: "iPhone14,5", startedAt: Date(timeIntervalSince1970: Double(totalMs)),
                    steps: [.init(name: "start", atMs: 0, footprintBytes: 1)], peakBytes: 2, totalMs: totalMs, outcome: "shown")
    }
}

final class BenchStoreTests: XCTestCase {
    func testKeepsFiftyAndHoldsNoContent() throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let store = BenchStore(directory: dir, keep: 50)
        for i in 0..<55 { try store.append(.fixture(totalMs: UInt64(i))) }
        let all = try store.all()
        XCTAssertEqual(all.count, 50)
        XCTAssertEqual(all.map(\.totalMs).min(), 5)
        let raw = try FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)
            .map { try String(contentsOf: $0, encoding: .utf8) }.joined()
        XCTAssertFalse(raw.contains("salut"))
    }

    func testFootprintIsPositiveAndSamplerSeesPeak() throws {
        XCTAssertGreaterThan(Footprint.current(), 0)
        let sampler = FootprintSampler(interval: .milliseconds(5))
        sampler.start()
        let blob = [UInt8](repeating: 1, count: 8 << 20)
        Thread.sleep(forTimeInterval: 0.05)
        let peak = sampler.stop()
        XCTAssertGreaterThanOrEqual(peak, Footprint.current() - UInt64(blob.count))
        XCTAssertEqual(blob.count, 8 << 20)
    }
}
