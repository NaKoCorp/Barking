import XCTest
@testable import BarkingKit

/// The nodes the app was built with (Info.plist, from the build settings)
/// reach the core as hand-added nodes.
final class BootstrapNodesTests: XCTestCase {
    private static let id = "IMY7C3XROVDOQ5ENPIVA7KJYUKZZDTQPBHBD72W5PMVK6RJ5QRQA"

    func testEntriesAreSplitOnSpacesAndCommas() {
        let info: [String: Any] = ["BarkingBootstrapNodes":
            " \(Self.id)@203.0.113.7:4433,\(Self.id)@[2001:db8::7]:4433  A@1.2.3.4:1 "]
        XCTAssertEqual(BootstrapNodes.entries(info: info).map { "\($0.id)@\($0.addr)" }, [
            "\(Self.id)@203.0.113.7:4433", "\(Self.id)@[2001:db8::7]:4433", "A@1.2.3.4:1",
        ])
    }

    func testNothingBuiltInOrMalformedEntriesGiveNoNode() {
        XCTAssertTrue(BootstrapNodes.entries(info: [:]).isEmpty)
        // An unset build setting leaves the key empty.
        XCTAssertTrue(BootstrapNodes.entries(info: ["BarkingBootstrapNodes": ""]).isEmpty)
        let bad: [String: Any] = ["BarkingBootstrapNodes": "203.0.113.7:4433 @1.2.3.4:1 \(Self.id)@"]
        XCTAssertTrue(BootstrapNodes.entries(info: bad).isEmpty)
    }

    @MainActor
    func testAddUsesDefaultNodesCall() async {
        let device = FakeDevice()
        let core = CoreService(device: device, runner: DirectRunner())
        let info: [String: Any] = ["BarkingBootstrapNodes": "\(Self.id)@203.0.113.7:4433 B@1.2.3.4:1"]
        await BootstrapNodes.add(to: core, info: info)
        XCTAssertEqual(device.defaultNodeCalls, [["\(Self.id)@203.0.113.7:4433", "B@1.2.3.4:1"]])
        XCTAssertTrue(device.addedNodes.isEmpty)
    }

    @MainActor
    func testNoEntryMakesNoCall() async {
        let device = FakeDevice()
        let core = CoreService(device: device, runner: DirectRunner())
        await BootstrapNodes.add(to: core, info: [:])
        XCTAssertTrue(device.defaultNodeCalls.isEmpty)
    }

    @MainActor
    func testResetReturnsRestoredCount() async {
        let device = FakeDevice()
        device.resetDefaultsResult = 2
        let core = CoreService(device: device, runner: DirectRunner())
        let info: [String: Any] = ["BarkingBootstrapNodes": "A@1.2.3.4:1 B@1.2.3.4:2 C@1.2.3.4:3"]
        let restored = await BootstrapNodes.reset(core: core, info: info)
        XCTAssertEqual(restored, 2)
        XCTAssertEqual(device.resetCalls, [["A@1.2.3.4:1", "B@1.2.3.4:2", "C@1.2.3.4:3"]])
        device.resetDefaultsError = NSError(domain: "t", code: 1)
        let failed = await BootstrapNodes.reset(core: core, info: info)
        XCTAssertEqual(failed, 0)
    }
}
