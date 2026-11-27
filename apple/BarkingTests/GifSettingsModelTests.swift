import XCTest
@testable import Barking
@testable import BarkingKit

/// Settings › GIFs (spec GIF §9.3): what the switches do and what the screen
/// shows, read from the core.
@MainActor
final class GifSettingsModelTests: XCTestCase {
    private func model(_ d: FakeDevice) -> GifSettingsModel {
        GifSettingsModel(core: CoreService(device: d, runner: DirectRunner()))
    }

    /// Turning on passes the warning version the user just read.
    func testEnableCallsCoreWithWarningVersion() async throws {
        let d = FakeDevice()
        d.gifProviderInfo.warningVersion = 3
        let m = model(d)
        await m.load()
        XCTAssertFalse(m.enabled)
        try await m.enable()
        XCTAssertEqual(d.gifEnabled.map(\.provider), [1])
        XCTAssertEqual(d.gifEnabled.map(\.warningVersion), [3])
        XCTAssertTrue(m.enabled)
    }

    /// Turning off is one call, no confirmation, and the screen follows.
    func testDisableIsImmediate() async {
        let d = FakeDevice()
        d.gifSettingsInfo.enabled = true
        let m = model(d)
        await m.load()
        XCTAssertTrue(m.enabled)
        await m.disable()
        XCTAssertEqual(d.gifDisabled, [1])
        XCTAssertFalse(m.enabled)
    }

    /// Turned on from another of my devices: its name is shown.
    func testEnabledFromOtherDeviceShown() async {
        let d = FakeDevice()
        d.gifSettingsInfo = GifSettingsInfo(enabled: true, autoLoad: false, enabledFromOtherDevice: "iPhone",
                                            enabledAt: 1_795_000_000, consentOutdated: false)
        let m = model(d)
        await m.load()
        XCTAssertEqual(m.enabledFrom, "iPhone")
        XCTAssertEqual(m.enabledAt, Date(timeIntervalSince1970: 1_795_000_000))
    }

    /// The core stored the consent but the read that follows failed: the
    /// switch still shows GIFs on (a read must not undo a stored write).
    func testEnableStandsWhenTheReadBackFails() async throws {
        let d = FakeDevice()
        let m = model(d)
        await m.load()
        d.gifSettingsError = BarkingError.Storage(detail: "locked")
        try await m.enable()
        XCTAssertTrue(m.enabled)
        XCTAssertFalse(m.saveFailed)
    }

    /// Turned on here: no origin line.
    func testEnabledHereShowsNoOrigin() async throws {
        let d = FakeDevice()
        let m = model(d)
        await m.load()
        try await m.enable()
        XCTAssertNil(m.enabledFrom)
    }

    /// A refused activation keeps GIFs off and throws.
    func testEnableFailureKeepsOff() async {
        let d = FakeDevice()
        d.gifError = BarkingError.Storage(detail: "disk")
        let m = model(d)
        await m.load()
        do {
            try await m.enable()
            XCTFail("enable should throw")
        } catch {}
        XCTAssertFalse(m.enabled)
    }

    /// A refused deactivation shows what the core holds, and says so.
    func testDisableFailureSaysSo() async {
        let d = FakeDevice()
        d.gifSettingsInfo.enabled = true
        let m = model(d)
        await m.load()
        d.gifError = BarkingError.Storage(detail: "disk")
        await m.disable()
        XCTAssertTrue(m.enabled)
        XCTAssertTrue(m.saveFailed)
    }

    func testSetAutoLoad() async {
        let d = FakeDevice()
        d.gifSettingsInfo.enabled = true
        let m = model(d)
        await m.load()
        XCTAssertFalse(m.autoLoad, "off by default")
        await m.setAutoLoad(true)
        XCTAssertEqual(d.gifAutoLoad, [true])
        XCTAssertTrue(m.autoLoad)
    }

    /// The warning counts my other devices, not this one.
    func testLinkedDevicesAreTheOtherOnes() async {
        let d = FakeDevice()
        d.devicesList = [
            MyDeviceInfo(id: "a", name: "This", issuedAt: 1, thisDevice: true, admin: true),
            MyDeviceInfo(id: "b", name: "iPad", issuedAt: 1, thisDevice: false, admin: false),
            MyDeviceInfo(id: "c", name: "Mac", issuedAt: 1, thisDevice: false, admin: false),
        ]
        let m = model(d)
        await m.load()
        XCTAssertEqual(m.linkedDevices, 2)
    }

    /// The provider's name and privacy link come from the core.
    func testProviderFromCore() async {
        let d = FakeDevice()
        let m = model(d)
        await m.load()
        XCTAssertEqual(m.provider?.name, "Klipy")
        XCTAssertEqual(m.provider?.privacyUrl, "https://klipy.com/support/privacy-policy")
    }

    /// Before the core named the provider, nothing is named and nothing can
    /// be turned on: no stand-in provider reaches the core.
    func testEnableBeforeLoadRefuses() async {
        let d = FakeDevice()
        let m = model(d)
        XCTAssertNil(m.provider)
        do {
            try await m.enable()
            XCTFail("enable should throw before load")
        } catch {}
        XCTAssertTrue(d.gifEnabled.isEmpty)
        XCTAssertFalse(m.enabled)
    }

    /// A consent for an older warning: off, and the warning says "Updated".
    func testOutdatedConsentShowsUpdated() async throws {
        let d = FakeDevice()
        d.gifSettingsInfo.consentOutdated = true
        let m = model(d)
        await m.load()
        XCTAssertFalse(m.enabled)
        XCTAssertTrue(m.updated)
        try await m.enable()
        XCTAssertTrue(m.enabled)
        XCTAssertFalse(m.updated)
    }

    /// Never turned on: the warning is not "Updated".
    func testNeverEnabledIsNotUpdated() async {
        let d = FakeDevice()
        let m = model(d)
        await m.load()
        XCTAssertFalse(m.updated)
    }

    /// The build's key reaches the core trimmed; none or blank: nil.
    func testKlipyKeyFromInfo() {
        XCTAssertEqual(GifKeys.klipy(info: ["BarkingKlipyKey": " abc123 "]), "abc123")
        XCTAssertNil(GifKeys.klipy(info: ["BarkingKlipyKey": ""]))
        XCTAssertNil(GifKeys.klipy(info: ["BarkingKlipyKey": "  "]))
        XCTAssertNil(GifKeys.klipy(info: [:]))
    }

    /// Every new text of the GIF screens has French.
    func testGifStringsInFrench() throws {
        let fr = try XCTUnwrap(Bundle.main.path(forResource: "Localizable", ofType: "strings", inDirectory: nil,
                                                forLocalization: "fr").flatMap { NSDictionary(contentsOfFile: $0) })
        for key in ["GIFs", "Off (GIFs)", "On · %@ sees your IP address", "Use GIFs from %@", "Use GIFs from %@?",
                    "Off, Barking never contacts %@", "Turned on from %@ · %@", "another device",
                    "Play GIFs automatically",
                    "Each GIF shown is requested from %@ from your address. Off, you choose GIF by GIF",
                    "See what was sent in Transparency ›", "These settings apply to all your linked devices",
                    "Updated", "To search and show GIFs, this phone connects directly to %@, a US company. %@ will receive:",
                    "your IP address, which reveals your approximate location", "your GIF searches",
                    "which GIFs you send and show, and when",
                    "By matching GIF requests, %@ can work out who you exchange GIFs with. Your messages and contacts stay encrypted and are never sent to %@. Barking doesn't control what %@ does with this data.",
                    "You can turn it off anytime in Settings › GIFs.", "%@ privacy policy ›", "Not now", "Use GIFs"] {
            XCTAssertNotNil(fr[key], "missing French for \(key)")
        }
        for lang in ["en", "fr"] {
            let plurals = try XCTUnwrap(Bundle.main.path(forResource: "Localizable", ofType: "stringsdict", inDirectory: nil,
                                                         forLocalization: lang).flatMap { NSDictionary(contentsOfFile: $0) })
            let rule = (plurals["Applies to your %lld linked devices."] as? NSDictionary)?["n"] as? NSDictionary
            XCTAssertNotNil(rule?["one"], lang)
            XCTAssertNotNil(rule?["other"], lang)
        }
    }
}
