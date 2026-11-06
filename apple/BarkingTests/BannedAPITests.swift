import XCTest

/// Feature code draws with the design system only (UI review B1): no system
/// red or blue, no stock rounded text fields, no uppercase-tracked labels and
/// no fixed-size system fonts. The sources are read from the repository the
/// test was built from.
final class BannedAPITests: XCTestCase {
    private static let banned = [
        "Color.red", "Color.blue", ".roundedBorder", ".textCase(.uppercase)", ".font(.system(size:",
    ]

    /// Uses that a later batch of the UI review removes, by file. The test
    /// fails if one of them disappears, so the allowance goes with it.
    private static let pending: [String: Set<String>] = [
        // B2 (U-7): BarkingTextField replaces these fields.
        ".roundedBorder": ["SafetyCodeView.swift", "LinkViews.swift", "AddContactView.swift"],
    ]

    private var featuresDirectory: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Barking/Features")
    }

    private func sources() throws -> [(name: String, text: String)] {
        let root = featuresDirectory
        guard let walker = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil) else {
            throw XCTSkip("sources not readable at \(root.path)")
        }
        return try walker.compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" }
            .map { ($0.lastPathComponent, try String(contentsOf: $0, encoding: .utf8)) }
    }

    func testFeatureCodeAvoidsBannedAPIs() throws {
        let files = try sources()
        XCTAssertGreaterThan(files.count, 20, "Features sources not found")
        for pattern in Self.banned {
            let allowed = Self.pending[pattern] ?? []
            let users = Set(files.filter { $0.text.contains(pattern) }.map(\.name))
            for name in users.subtracting(allowed) {
                XCTFail("\(name) uses \(pattern)")
            }
            for name in allowed.subtracting(users) {
                XCTFail("\(name) no longer uses \(pattern): drop it from BannedAPITests.pending")
            }
        }
    }
}
