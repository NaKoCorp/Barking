import UserNotifications
import XCTest
@testable import Barking
@testable import BarkingKit

/// The relay the app was built with (Info.plist, from the build settings)
/// and the APNs token iOS gives it reach the core.
final class PushRelayTests: XCTestCase {
    private static let relayId = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    private static let seal = String(repeating: "5e", count: 32)
    private let token = Data([0xB0, 0x01, 0x02])

    private func info(host: String = "relay.local", port: String = "4434",
                      seal: String = PushRelayTests.seal,
                      env: String = "development") -> [String: Any] {
        ["BarkingRelayHost": host, "BarkingRelayPort": port, "BarkingRelayId": Self.relayId,
         "BarkingRelaySealId": "1", "BarkingRelaySealPublic": seal, "BarkingApnsEnvironment": env]
    }

    func testSettingsComeFromTheInfoDictionary() throws {
        let s = try XCTUnwrap(PushRelay.settings(info: info(), token: token))
        XCTAssertEqual(s.relayHost, "relay.local")
        XCTAssertEqual(s.relayPort, 4434)
        XCTAssertEqual(s.relayId, Self.relayId)
        XCTAssertEqual(s.sealKeyId, 1)
        XCTAssertEqual(s.sealPublic, Data(repeating: 0x5E, count: 32))
        XCTAssertEqual(s.apnsToken, token)
        XCTAssertTrue(s.sandbox)
        XCTAssertEqual(PushRelay.settings(info: info(env: "production"), token: token)?.sandbox, false)
    }

    func testNoRelayBuiltInMeansPushOff() {
        XCTAssertNil(PushRelay.settings(info: [:], token: token))
        XCTAssertNil(PushRelay.settings(info: info(host: ""), token: token))
        XCTAssertNil(PushRelay.settings(info: info(port: "x"), token: token))
        XCTAssertNil(PushRelay.settings(info: info(seal: "5e"), token: token))
        XCTAssertNil(PushRelay.settings(info: info(seal: String(repeating: "zz", count: 32)), token: token))
        XCTAssertNil(PushRelay.settings(info: info(), token: Data()))
    }

    func testAllowsStatuses() {
        XCTAssertFalse(PushRelay.allows(.notDetermined))
        XCTAssertFalse(PushRelay.allows(.denied))
        XCTAssertTrue(PushRelay.allows(.authorized))
        XCTAssertTrue(PushRelay.allows(.provisional))
        XCTAssertTrue(PushRelay.allows(.ephemeral))
    }

    @MainActor
    func testTokenArrivalHandsTheSettingsToTheCore() async throws {
        let device = FakeDevice()
        let core = CoreService(device: device, runner: DirectRunner())
        let push = PushToken()
        push.info = info()
        push.authorization = { .authorized }
        let delegate = AppDelegate()
        delegate.service = { core }
        delegate.pushToken = push
        delegate.application(UIApplication.shared, didRegisterForRemoteNotificationsWithDeviceToken: token)
        try await waitUntil { device.pushSettings.count == 1 }
        XCTAssertEqual(device.pushSettings.first??.apnsToken, token)
        XCTAssertEqual(push.hex, "b00102")
    }

    @MainActor
    func testWithoutARelayTheCoreIsToldPushIsOff() async throws {
        let device = FakeDevice()
        let core = CoreService(device: device, runner: DirectRunner())
        let push = PushToken()
        push.info = [:]
        push.authorization = { .authorized }
        push.token = token
        await push.apply(to: core)
        XCTAssertEqual(device.pushSettings.count, 1)
        XCTAssertNil(device.pushSettings.first ?? nil)
    }

    @MainActor
    func testNoTokenYetLeavesTheCoreAlone() async {
        let device = FakeDevice()
        let core = CoreService(device: device, runner: DirectRunner())
        let push = PushToken()
        push.info = info()
        push.authorization = { .authorized }
        await push.apply(to: core)
        XCTAssertTrue(device.pushSettings.isEmpty)
    }

    @MainActor
    private func onboardingPush(_ status: UNAuthorizationStatus) async -> FakeDevice {
        let device = FakeDevice()
        let core = CoreService(device: device, runner: DirectRunner())
        let push = PushToken()
        push.info = info()
        push.token = token
        // The core was made while undetermined: push off, then the prompt is answered.
        push.authorization = { .notDetermined }
        await push.apply(to: core)
        push.authorization = { status }
        await OnboardingFlow.askForNotifications(core: core, push: push, request: {})
        return device
    }

    @MainActor
    func testOnboardingPromptAllowedSubscribes() async {
        let device = await onboardingPush(.authorized)
        XCTAssertEqual(device.pushSettings.count, 2)
        XCTAssertNil(device.pushSettings.first ?? nil)
        XCTAssertNotNil(device.pushSettings.last ?? nil)
    }

    @MainActor
    func testOnboardingPromptDeniedStaysOff() async {
        let device = await onboardingPush(.denied)
        XCTAssertNil(device.pushSettings.last ?? nil)
    }

    @MainActor
    private func waitUntil(_ condition: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(2)
        while !condition() {
            if Date() > deadline { XCTFail("timed out"); return }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
}
