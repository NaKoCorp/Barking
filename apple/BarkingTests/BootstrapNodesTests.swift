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
    func testEachEntryIsAddedToTheCore() async {
        let device = FakeDevice()
        let core = CoreService(device: device, runner: DirectRunner())
        let info: [String: Any] = ["BarkingBootstrapNodes": "\(Self.id)@203.0.113.7:4433 B@1.2.3.4:1"]
        await BootstrapNodes.add(to: core, info: info)
        XCTAssertEqual(device.addedNodes, ["\(Self.id)@203.0.113.7:4433", "B@1.2.3.4:1"])
    }
}
