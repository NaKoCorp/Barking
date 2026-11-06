import XCTest

/// Feature code draws with the design system only (UI review B1): no system
/// red or blue, no stock rounded text fields, no uppercase-tracked labels and
/// no fixed-size system fonts. The sources are read from the repository the
/// test was built from.
final class BannedAPITests: XCTestCase {
    /// Name → pattern. `Color.red`, `.foregroundStyle(.red)`, `.tint(.blue)`;
    /// `Color(.systemRed)`, `UIColor.systemBlue`; any spacing inside calls.
    nonisolated(unsafe) static let banned: [(name: String, regex: NSRegularExpression)] = [
        ("red/blue", #"\.(red|blue)\b"#),
        ("systemRed/Blue", #"\bsystem(Red|Blue)\b"#),
        (".roundedBorder", #"\.roundedBorder\b"#),
        (".textCase(.uppercase)", #"textCase\(\s*\.uppercase\b"#),
        (".system(size:)", #"\.system\(\s*size\s*:"#),
        // B2: one segmented look (BarkingSegmented), menus for long choices.
        (".pickerStyle(.segmented)", #"pickerStyle\(\s*\.segmented\b"#),
        // B2: brand screens are ScrollView + FormCard, CTAs never in a row.
        ("Form {", #"\bForm\s*\{"#),
        (".listRowInsets", #"\.listRowInsets\("#),
        // Final review #2: it redacts only under a `.privacy` redaction
        // reason (widgets, Always-On), never in the app, so it reads as a
        // guard it is not. Secrets use `SecretCover` instead.
        (".privacySensitive()", #"\.privacySensitive\("#),
    ].map { ($0.0, try! NSRegularExpression(pattern: $0.1)) }

    /// The banned forms `text` contains, one entry per use.
    static func violations(in text: String) -> [String] {
        let range = NSRange(text.startIndex..., in: text)
        return banned.flatMap { b in
            Array(repeating: b.name, count: b.regex.numberOfMatches(in: text, range: range))
        }
    }

    /// Every banned spelling is caught; design-system calls are not.
    func testFixtureCatchesEveryBannedForm() {
        let caught = [
            "Color.red", "Color.blue", ".foregroundStyle(.red)", ".tint(.blue)", "Color(.systemRed)",
            "UIColor.systemBlue", "Font.system(size: 12)", ".font( .system(size: 12))", ".font(.system( size: 9))",
            ".textFieldStyle(.roundedBorder)", ".textCase(.uppercase)", ".textCase( .uppercase )",
            ".pickerStyle(.segmented)", "Form {", "Form{", ".listRowInsets(EdgeInsets())",
            ".privacySensitive()", ".privacySensitive(true)",
        ]
        for line in caught {
            XCTAssertEqual(Self.violations(in: line).count, 1, "not caught: \(line)")
        }
        let allowed = [
            "Color(red: 0.5, green: 0.2, blue: 1)", "BarkingFont.sans(.body, size: 15)", ".font(.bSymbol(15))",
            "Color.danger", "let reduced = 1", ".textCase(nil)", "model.redraw", "Color.blueprint",
            "FormCard {", ".pickerStyle(.menu)", "let form = 1",
        ]
        for line in allowed {
            XCTAssertEqual(Self.violations(in: line), [], "false positive: \(line)")
        }
    }

    /// Uses that a later batch of the UI review removes, by file and count:
    /// one more use fails, and so does one less (the allowance goes with it).
    /// Empty since B4: the Recover grid replaced the last `Form`.
    private static let pending: [String: [String: Int]] = [:]

    private func sources() throws -> [(name: String, text: String)] {
        let app = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Barking")
        return try ["Features", "App"].flatMap { dir -> [(name: String, text: String)] in
            let root = app.appendingPathComponent(dir)
            guard let walker = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil) else {
                throw XCTSkip("sources not readable at \(root.path)")
            }
            return try walker.compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" }
                .map { ($0.lastPathComponent, try String(contentsOf: $0, encoding: .utf8)) }
        }
    }

    func testFeatureCodeAvoidsBannedAPIs() throws {
        let files = try sources()
        XCTAssertGreaterThan(files.count, 25, "Features and App sources not found")
        XCTAssertTrue(files.contains { $0.name == "RootView.swift" }, "App/ not scanned")
        var seen: [String: [String: Int]] = [:]
        for file in files {
            for v in Self.violations(in: file.text) { seen[v, default: [:]][file.name, default: 0] += 1 }
        }
        for pattern in Self.banned.map(\.name) {
            let found = seen[pattern] ?? [:]
            let allowed = Self.pending[pattern] ?? [:]
            for name in Set(found.keys).union(allowed.keys) where found[name, default: 0] != allowed[name, default: 0] {
                XCTFail("\(name): \(found[name, default: 0]) use(s) of \(pattern), \(allowed[name, default: 0]) allowed")
            }
        }
    }
}
