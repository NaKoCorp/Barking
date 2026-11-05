import XCTest
@testable import BarkingKit

/// Time budgets (spec iOS foundations §3.3, §5.3): a call must end, and the
/// lock be released, before iOS cuts the time it grants.
final class BudgetTests: XCTestCase {
    func testAppCallFitsTheBackgroundTime() {
        // iOS grants about 30 s to a background task; keep 4 s of margin.
        XCTAssertLessThanOrEqual(Budget.appLockMs + Budget.appSyncMs + Budget.shutdownMs, 26_000)
    }

    func testExtensionFitsItsTime() {
        // 25 s granted to the extension, 5 s of margin.
        XCTAssertLessThanOrEqual(Budget.extensionLockMs + Budget.extensionWorkMs + Budget.shutdownMs, 20_000)
    }

    func testQuickSyncDeadlineShrinksWithElapsedTime() {
        XCTAssertEqual(Budget.quickSyncDeadline(elapsedMs: 0), Budget.extensionWorkMs)
        XCTAssertEqual(Budget.quickSyncDeadline(elapsedMs: 5_000), Budget.extensionWorkMs - 5_000)
        XCTAssertEqual(Budget.quickSyncDeadline(elapsedMs: 60_000), 0)
    }
}

final class SharedPathsFallbackTests: XCTestCase {
    func testNoSilentFallbackOutsideDebug() {
        XCTAssertThrowsError(try SharedPaths.resolve(nil, fallbackAllowed: false))
        XCTAssertEqual(try SharedPaths.resolve(nil, fallbackAllowed: true), FileManager.default.temporaryDirectory)
        let url = URL(fileURLWithPath: "/group")
        XCTAssertEqual(try SharedPaths.resolve(url, fallbackAllowed: false), url)
    }
}
