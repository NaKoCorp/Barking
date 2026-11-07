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

    /// A keychain error while unwrapping keeps the retry screen (fix round 2).
    func testKeychainErrorWhileUnwrappingKeepsTheRetryScreen() {
        let entries = MemoryEntries()
        entries["db-key-wrapped"] = Data([1])
        let store = KeyStore(entries: entries, wrapper: ThrowingUnwrap())
        guard case .failed = AppRouter.initialState(opening: { _ = try store.read(); return nil },
                                                    runner: DirectRunner()) else {
            return XCTFail("a passing keychain error must not offer to erase")
        }
    }

    /// Fix round 3: an enclave error while the key exists, however it
    /// looks, keeps the retry screen; only a missing key offers to erase.
    func testOnlyAMissingEnclaveKeyOffersToErase() throws {
        for error in [NSError(domain: NSOSStatusErrorDomain, code: -2070),
                      NSError(domain: NSOSStatusErrorDomain, code: Int(errSecDecode))] {
            let entries = MemoryEntries()
            entries["db-key-wrapped"] = Data([1])
            let store = KeyStore(entries: entries, wrapper: ErrorUnwrap(error: error))
            guard case .failed = AppRouter.initialState(opening: { _ = try store.read(); return nil },
                                                        runner: DirectRunner()) else {
                return XCTFail("\(error) must keep the retry screen")
            }
        }
        let entries = MemoryEntries()
        let gone = SoftwareKey()
        let store = KeyStore(entries: entries, wrapper: gone)
        _ = try store.create()
        try gone.delete()
        guard case .unreadable = AppRouter.initialState(opening: { _ = try store.read(); return nil },
                                                        runner: DirectRunner()) else {
            return XCTFail("no key under the tag: link or recover")
        }
    }

    /// Before the first unlock (background launch for a push): the retry
    /// screen, never onboarding over the identity (item 2).
    func testLockedKeychainNeverShowsOnboarding() {
        let entries = MemoryEntries()
        entries["db-key-wrapped"] = Data([1])
        entries.locked = true
        let store = KeyStore(entries: entries, wrapper: SoftwareKey())
        guard case .failed = AppRouter.initialState(opening: { _ = try store.read(); return nil },
                                                    runner: DirectRunner()) else {
            return XCTFail("locked keychain must not look like no identity")
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

private struct ThrowingUnwrap: KeyWrapper {
    var hardware: Bool { true }
    func wrap(_ key: Data) throws -> Data { key }
    func unwrap(_ blob: Data) throws -> Data { throw KeyStore.Failure(status: errSecIO) }
    func delete() throws {}
}

private struct ErrorUnwrap: KeyWrapper {
    let error: NSError
    var hardware: Bool { true }
    func wrap(_ key: Data) throws -> Data { key }
    func unwrap(_ blob: Data) throws -> Data { throw error }
    func delete() throws {}
}
