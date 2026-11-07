import UserNotifications
import XCTest
@testable import Barking
@testable import BarkingKit

private final class FakeCenter: NotificationPosting, @unchecked Sendable {
    var authorized = true
    private(set) var requests: [UNNotificationRequest] = []
    func isAuthorized() async -> Bool { authorized }
    func add(_ request: UNNotificationRequest) async throws { requests.append(request) }
}

private func failed(_ pairs: (String, Int64)...) -> [DeliveryChange] {
    pairs.map { DeliveryChange(contact: $0.0, messageId: $0.1) }
}

final class FailureNotifierTests: XCTestCase {
    private let center = FakeCenter()

    private func french() throws -> Bundle {
        let kit = Bundle(for: FailureNotifier.Marker.self)
        return try XCTUnwrap(kit.path(forResource: "fr", ofType: "lproj").flatMap(Bundle.init(path:)))
    }

    func testNoNotificationInForeground() async {
        await FailureNotifier(center: center).post(failed(("ann", 1)), appActive: true)
        XCTAssertTrue(center.requests.isEmpty)
    }

    func testNothingWithoutAuthorizationOrFailures() async {
        center.authorized = false
        await FailureNotifier(center: center).post(failed(("ann", 1)), appActive: false)
        center.authorized = true
        await FailureNotifier(center: center).post([], appActive: false)
        XCTAssertTrue(center.requests.isEmpty)
    }

    func testOnePerContactWithPluralText() async {
        await FailureNotifier(center: center)
            .post(failed(("ann", 5), ("bob", 7), ("ann", 3), ("ann", 4), ("ann", 3)), appActive: false)
        let byThread = Dictionary(uniqueKeysWithValues: center.requests.map { ($0.content.threadIdentifier, $0.content) })
        XCTAssertEqual(center.requests.count, 2)
        XCTAssertEqual(byThread["ann"]?.body, "3 messages couldn’t be delivered.")
        XCTAssertEqual(byThread["bob"]?.body, "A message couldn’t be delivered.")
    }

    func testThreadAndUserInfoPointAtTheFirstFailedMessage() async throws {
        await FailureNotifier(center: center).post(failed(("ann", 9), ("ann", 4)), appActive: false)
        let content = try XCTUnwrap(center.requests.first).content
        XCTAssertEqual(content.threadIdentifier, "ann")
        XCTAssertEqual(content.userInfo["contact"] as? String, "ann")
        XCTAssertEqual(content.userInfo["message_id"] as? Int64, 4)
    }

    func testTextHasNoNameNorBody() async throws {
        await FailureNotifier(center: center).post(failed(("aabbccddeeff", 1)), appActive: false)
        let content = try XCTUnwrap(center.requests.first).content
        XCTAssertEqual(content.title, "")
        XCTAssertEqual(content.subtitle, "")
        XCTAssertFalse(content.body.contains("aabbccddeeff"))
        XCTAssertEqual(content.body, "A message couldn’t be delivered.")
    }

    func testFrenchText() async throws {
        let notifier = FailureNotifier(center: center, bundle: try french())
        await notifier.post(failed(("ann", 1), ("bob", 2), ("bob", 3)), appActive: false)
        let bodies = Dictionary(uniqueKeysWithValues: center.requests.map { ($0.content.threadIdentifier, $0.content.body) })
        XCTAssertEqual(bodies["ann"], "Un message n’a pas pu être distribué.")
        XCTAssertEqual(bodies["bob"], "2 messages n’ont pas pu être distribués.")
    }

    // MARK: Where it is called from

    private func core(_ device: FakeDevice, active: Bool) -> CoreService {
        let center = self.center
        return CoreService(device: device, runner: DirectRunner(), onFailed: {
            await FailureNotifier(center: center).post($0, appActive: active)
        })
    }

    private func device(failing: [DeliveryChange]) -> FakeDevice {
        let d = FakeDevice()
        d.summary = SyncSummary(itemsReceived: 1, sent: 0, newMessages: [], networkUp: true, error: nil,
                                deliveryChanges: failing, failed: failing)
        return d
    }

    @MainActor
    func testTheBackgroundWakeQuickSyncPosts() async {
        let service = core(device(failing: failed(("ann", 2))), active: false)
        let delegate = AppDelegate()
        delegate.service = { service }
        _ = await delegate.backgroundWake()
        XCTAssertEqual(center.requests.map(\.content.threadIdentifier), ["ann"])
    }

    func testAFullSyncPostsAndAnActiveAppDoesNot() async {
        _ = await core(device(failing: failed(("ann", 2))), active: false).sync(reason: .timer)
        XCTAssertEqual(center.requests.count, 1)
        _ = await core(device(failing: failed(("bob", 3))), active: true).sync(reason: .timer)
        XCTAssertEqual(center.requests.count, 1)
    }

    // MARK: Tap

    @MainActor
    func testTapOpensTheConversationOnTheFirstUndeliveredMessage() async throws {
        await FailureNotifier(center: center).post(failed(("ann", 8), ("ann", 6)), appActive: false)
        let userInfo = try XCTUnwrap(center.requests.first).content.userInfo
        let router = AppRouter(start: .onboarding)
        XCTAssertTrue(router.open(notification: userInfo))
        XCTAssertEqual(router.takePendingOpen(), AppRouter.OpenTarget(contact: "ann", messageId: 6))
        XCTAssertNil(router.takePendingOpen())
    }

    @MainActor
    func testTapWithoutAContactIsIgnored() {
        let router = AppRouter(start: .onboarding)
        XCTAssertFalse(router.open(notification: ["message_id": 1]))
        XCTAssertFalse(router.open(notification: [:]))
        XCTAssertNil(router.takePendingOpen())
    }

    @MainActor
    func testTapOnANewMessageNotificationOpensTheConversationOnly() {
        let router = AppRouter(start: .onboarding)
        XCTAssertTrue(router.open(notification: ["contact": "ann"]))
        XCTAssertEqual(router.takePendingOpen(), AppRouter.OpenTarget(contact: "ann", messageId: nil))
    }
}
