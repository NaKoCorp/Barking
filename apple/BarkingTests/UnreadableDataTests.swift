import XCTest
@testable import Barking
@testable import BarkingKit

/// The enclave key is gone while `db-key-wrapped` exists (spec §7.2): the
/// app offers linking or recovering, each after erasing the unreadable data.
@MainActor
final class UnreadableDataTests: XCTestCase {
    func testUnavailableKeyIsToldApartFromOtherFailures() {
        guard case .unreadable = AppRouter.initialState(opening: { throw KeyStore.Unavailable() },
                                                        runner: DirectRunner()) else {
            return XCTFail("a key that no longer unwraps offers link or recover")
        }
        guard case .failed = AppRouter.initialState(opening: { throw Boom() }, runner: DirectRunner()) else {
            return XCTFail("other errors keep the retry screen")
        }
    }

    func testEraseThenLink() {
        let router = AppRouter(start: .unreadable)
        var wiped = false
        router.eraseUnreadable(then: .link) { wiped = true }
        XCTAssertTrue(wiped)
        guard case .onboarding = router.state else { return XCTFail("onboarding after the wipe") }
        XCTAssertEqual(router.takeOnboardingStep(), .link)
        XCTAssertNil(router.takeOnboardingStep())
    }

    func testEraseThenRecover() {
        let router = AppRouter(start: .unreadable)
        router.eraseUnreadable(then: .recover) {}
        XCTAssertEqual(router.takeOnboardingStep(), .recover)
    }

    /// A wipe that fails stays on the screen: onboarding would offer a new
    /// identity the leftover marker could erase.
    func testFailedEraseStaysOnTheScreen() {
        let router = AppRouter(start: .unreadable)
        router.eraseUnreadable(then: .link) { throw Boom() }
        guard case .unreadable = router.state else { return XCTFail("stays") }
        XCTAssertTrue(router.eraseFailed)
        XCTAssertNil(router.takeOnboardingStep())
    }

    func testStringsHaveFrench() throws {
        let path = try XCTUnwrap(Bundle.main.path(forResource: "Localizable", ofType: "strings",
                                                  inDirectory: nil, forLocalization: "fr"))
        let fr = try XCTUnwrap(NSDictionary(contentsOfFile: path))
        for key in [UnreadableDataView.explanation, UnreadableDataView.warning, "Erase and continue",
                    "Barking could not erase everything. Try again."] {
            XCTAssertNotNil(fr[key], "missing French for \(key)")
        }
    }
}
