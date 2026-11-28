import XCTest
@testable import Barking
@testable import BarkingKit

/// A GIF in a conversation (spec GIF §7, §9.5): what its bubble shows, when
/// it is requested from the provider, and that nothing outlives the bubble.
@MainActor
final class GifBubbleStateTests: XCTestCase {
    private let gif = GifInfo(provider: 1, id: "wave-9", width: 480, height: 270)

    private func settings(enabled: Bool, autoLoad: Bool) -> GifSettingsInfo {
        GifSettingsInfo(enabled: enabled, autoLoad: autoLoad, enabledFromOtherDevice: nil, enabledAt: nil,
                        consentOutdated: false, enabledFromUnlistedDevice: false)
    }

    private let klipy = GifProviderInfo(id: 1, name: "Klipy", warningVersion: 1,
                                        privacyUrl: "https://klipy.com/support/privacy-policy")

    private func loads(_ d: FakeDevice, constrained: Bool = false) -> GifLoads {
        let l = GifLoads(core: CoreService(device: d, runner: DirectRunner()))
        l.isConstrained = { constrained }
        return l
    }

    /// Polls until `condition` holds (device calls run on a detached task).
    private func eventually(_ condition: @MainActor () -> Bool, timeout: TimeInterval = 2) async {
        let end = Date().addingTimeInterval(timeout)
        while !condition(), Date() < end { try? await Task.sleep(for: .milliseconds(10)) }
    }

    // MARK: The state a bubble starts in

    func testUnknownProviderIsUnavailable() {
        let s = gifLoadState(gif: gif, settings: settings(enabled: true, autoLoad: true), constrained: false,
                             providerKnown: false)
        XCTAssertEqual(s, .unavailable)
    }

    func testOffWhenGifsAreOff() {
        let s = gifLoadState(gif: gif, settings: settings(enabled: false, autoLoad: true), constrained: false,
                             providerKnown: true)
        XCTAssertEqual(s, .off)
    }

    func testTapToLoadWithoutAutoPlay() {
        let s = gifLoadState(gif: gif, settings: settings(enabled: true, autoLoad: false), constrained: false,
                             providerKnown: true)
        XCTAssertEqual(s, .tapToLoad)
    }

    /// Low Data Mode: never on its own, whatever "Play GIFs automatically" says.
    func testTapToLoadInLowDataMode() {
        let s = gifLoadState(gif: gif, settings: settings(enabled: true, autoLoad: true), constrained: true,
                             providerKnown: true)
        XCTAssertEqual(s, .tapToLoad)
    }

    func testLoadingWithAutoPlay() {
        let s = gifLoadState(gif: gif, settings: settings(enabled: true, autoLoad: true), constrained: false,
                             providerKnown: true)
        XCTAssertEqual(s, .loading)
    }

    // MARK: What a failure shows

    func testErrorMapping() {
        let now = Date(timeIntervalSince1970: 1_000)
        func after(_ kind: GifErrorKind, _ secs: UInt32 = 0) -> GifLoad {
            GifLoad.after(BarkingError.Gif(kind: kind, retryAfterSecs: secs), now: now)
        }
        XCTAssertEqual(after(.notFound), .gone)
        // Too large or unreadable: a retry would get the same, and the GIF
        // is not gone either.
        XCTAssertEqual(after(.tooLarge), .cannotLoad)
        XCTAssertEqual(after(.malformed), .cannotLoad)
        XCTAssertEqual(after(.offline), .failed)
        XCTAssertEqual(after(.unreachable), .failed)
        // No usable key in this build: no retry.
        XCTAssertEqual(after(.notConfigured), .notConfigured)
        XCTAssertFalse(GifLoad.notConfigured.loadable)
        XCTAssertEqual(after(.rateLimited, 60), .rateLimited(until: Date(timeIntervalSince1970: 1_060)))
        XCTAssertEqual(after(.notEnabled), .off)
        XCTAssertEqual(GifLoad.after(BarkingError.Storage(detail: "disk"), now: now), .failed)
    }

    /// "Klipy is busy · Retry in 1 min": the wait in whole minutes, rounded up.
    func testBusyWaitInMinutes() {
        let now = Date(timeIntervalSince1970: 1_000)
        XCTAssertEqual(GifLoad.minutesLeft(until: now.addingTimeInterval(60), now: now), 1)
        XCTAssertEqual(GifLoad.minutesLeft(until: now.addingTimeInterval(61), now: now), 2)
        XCTAssertEqual(GifLoad.minutesLeft(until: now.addingTimeInterval(-5), now: now), 0)
    }

    // MARK: Low Data Mode before the phone's path is known

    /// No path reported yet counts as Low Data Mode: never fail open.
    func testUnknownPathCountsAsConstrained() {
        XCTAssertTrue(GifNetworkPath.isConstrained(known: false, constrained: false))
        XCTAssertTrue(GifNetworkPath.isConstrained(known: true, constrained: true))
        XCTAssertFalse(GifNetworkPath.isConstrained(known: true, constrained: false))
    }

    /// Auto-play on, path unknown at first: tap to load; once the path says
    /// the phone is not constrained, the GIFs shown load.
    func testAutoPlayWaitsForThePath() async {
        let d = FakeDevice()
        let l = loads(d)
        var constrained = true
        l.isConstrained = { constrained }
        l.configure(enabled: true, autoLoad: true, provider: klipy)
        l.appeared(1, gif: gif)
        XCTAssertEqual(l.state(1), .tapToLoad)
        try? await Task.sleep(for: .milliseconds(100))
        XCTAssertEqual(d.gifDataCalls, [])
        constrained = false
        l.pathChanged()
        await eventually { d.gifDataCalls.count == 1 }
        XCTAssertEqual(d.gifDataCalls, ["wave-9"])
    }

    // MARK: When the provider is asked

    /// GIFs off (the default): the bubble asks nothing, even when tapped.
    func testOffBubbleMakesNoRequest() async {
        let d = FakeDevice()
        let l = loads(d)
        l.configure(enabled: false, autoLoad: true, provider: klipy)
        l.appeared(1, gif: gif)
        XCTAssertEqual(l.state(1), .off)
        XCTAssertFalse(l.load(1))
        try? await Task.sleep(for: .milliseconds(100))
        XCTAssertEqual(d.gifDataCalls, [])
    }

    /// Before the settings are read: a neutral slot, nothing asked.
    func testNothingBeforeTheSettingsAreKnown() async {
        let d = FakeDevice()
        let l = loads(d)
        l.appeared(1, gif: gif)
        XCTAssertNil(l.state(1))
        try? await Task.sleep(for: .milliseconds(100))
        XCTAssertEqual(d.gifDataCalls, [])
        l.configure(enabled: true, autoLoad: true, provider: klipy)
        await eventually { d.gifDataCalls.count == 1 }
        XCTAssertEqual(d.gifDataCalls, ["wave-9"])
    }

    /// Auto-play: requested when the bubble appears, never before.
    func testAutoPlayLoadsOnAppearOnly() async {
        let d = FakeDevice()
        d.gifMedia = GifMediaInfo(mp4: Data("MP4".utf8), author: "Ana", title: "Wave")
        let l = loads(d)
        l.configure(enabled: true, autoLoad: true, provider: klipy)
        try? await Task.sleep(for: .milliseconds(100))
        XCTAssertEqual(d.gifDataCalls, [])
        l.appeared(1, gif: gif)
        XCTAssertEqual(l.state(1), .loading)
        await eventually { l.state(1) != .loading }
        XCTAssertEqual(l.state(1), .loaded(Data("MP4".utf8), author: "Ana", title: "Wave"))
        XCTAssertEqual(d.gifDataCalls, ["wave-9"])
    }

    /// Low Data Mode with auto-play on: tap to load, then it loads.
    func testLowDataModeWaitsForATap() async {
        let d = FakeDevice()
        let l = loads(d, constrained: true)
        l.configure(enabled: true, autoLoad: true, provider: klipy)
        l.appeared(1, gif: gif)
        XCTAssertEqual(l.state(1), .tapToLoad)
        try? await Task.sleep(for: .milliseconds(100))
        XCTAssertEqual(d.gifDataCalls, [])
        XCTAssertTrue(l.load(1))
        await eventually { d.gifDataCalls.count == 1 }
    }

    /// The media lives as long as the bubble: gone with it, asked again
    /// when it comes back (spec GIF §6.3).
    func testDisappearReleasesTheMedia() async {
        let d = FakeDevice()
        let l = loads(d)
        l.configure(enabled: true, autoLoad: true, provider: klipy)
        l.appeared(1, gif: gif)
        await eventually { l.state(1) != .loading }
        XCTAssertNotNil(l.state(1)?.media)
        l.disappeared(1)
        XCTAssertNil(l.state(1))
        l.appeared(1, gif: gif)
        await eventually { d.gifDataCalls.count == 2 }
        XCTAssertEqual(d.gifDataCalls.count, 2)
    }

    /// Out and back while the request is on the way: that request serves
    /// it, no second one.
    func testBackWhileLoadingJoinsTheRequest() async {
        let d = FakeDevice()
        d.gifDataDelay = 0.3
        let l = loads(d)
        l.configure(enabled: true, autoLoad: true, provider: klipy)
        l.appeared(1, gif: gif)
        await eventually { d.gifDataCalls.count == 1 }
        l.disappeared(1)
        l.appeared(1, gif: gif)
        XCTAssertEqual(l.state(1), .loading)
        await eventually { l.state(1) != .loading }
        XCTAssertNotNil(l.state(1)?.media)
        XCTAssertEqual(d.gifDataCalls, ["wave-9"])
    }

    /// A reply for a bubble no longer on screen is dropped.
    func testReplyAfterTheBubbleLeftIsDropped() async {
        let d = FakeDevice()
        d.gifDataDelay = 0.2
        let l = loads(d)
        l.configure(enabled: true, autoLoad: true, provider: klipy)
        l.appeared(1, gif: gif)
        await eventually { d.gifDataCalls.count == 1 }
        l.disappeared(1)
        try? await Task.sleep(for: .milliseconds(400))
        XCTAssertNil(l.state(1))
        XCTAssertFalse(l.isLoading(1))
    }

    /// A reload of the conversation keeps the bubbles: nothing asked again.
    func testSameBubbleAppearingTwiceAsksOnce() async {
        let d = FakeDevice()
        let l = loads(d)
        l.configure(enabled: true, autoLoad: true, provider: klipy)
        l.appeared(1, gif: gif)
        await eventually { l.state(1) != .loading }
        l.appeared(1, gif: gif)
        l.configure(enabled: true, autoLoad: true, provider: klipy)
        try? await Task.sleep(for: .milliseconds(100))
        XCTAssertEqual(d.gifDataCalls, ["wave-9"])
        XCTAssertNotNil(l.state(1)?.media)
    }

    func testTapLoadsThatGifOnly() async {
        let d = FakeDevice()
        let l = loads(d)
        l.configure(enabled: true, autoLoad: false, provider: klipy)
        l.appeared(1, gif: gif)
        l.appeared(2, gif: GifInfo(provider: 1, id: "dog-3", width: 200, height: 200))
        XCTAssertEqual(l.state(1), .tapToLoad)
        XCTAssertTrue(l.load(2))
        await eventually { l.state(2) != .loading }
        XCTAssertEqual(d.gifDataCalls, ["dog-3"])
        XCTAssertEqual(l.state(1), .tapToLoad)
    }

    /// "Use GIFs" from a bubble: once on, that GIF loads; the others wait
    /// for a tap (auto-play off).
    func testConsentFromABubbleLoadsIt() async {
        let d = FakeDevice()
        let l = loads(d)
        l.configure(enabled: false, autoLoad: false, provider: klipy)
        l.appeared(1, gif: gif)
        l.appeared(2, gif: GifInfo(provider: 1, id: "dog-3", width: 200, height: 200))
        l.configure(enabled: true, autoLoad: false, provider: klipy)
        XCTAssertEqual(l.state(2), .tapToLoad)
        XCTAssertTrue(l.load(1))
        await eventually { l.state(1) != .loading }
        XCTAssertEqual(d.gifDataCalls, ["wave-9"])
    }

    /// Auto-play turned on from the conversation's sheet: the bubbles on
    /// screen load.
    func testAutoPlayTurnedOnLoadsWhatIsShown() async {
        let d = FakeDevice()
        let l = loads(d)
        l.configure(enabled: true, autoLoad: false, provider: klipy)
        l.appeared(1, gif: gif)
        l.configure(enabled: true, autoLoad: true, provider: klipy)
        await eventually { d.gifDataCalls.count == 1 }
        XCTAssertEqual(d.gifDataCalls, ["wave-9"])
    }

    /// GIFs turned off: what was loaded goes, the bubbles say off.
    func testTurningOffDropsTheMedia() async {
        let d = FakeDevice()
        let l = loads(d)
        l.configure(enabled: true, autoLoad: true, provider: klipy)
        l.appeared(1, gif: gif)
        await eventually { l.state(1) != .loading }
        l.configure(enabled: false, autoLoad: true, provider: klipy)
        XCTAssertEqual(l.state(1), .off)
    }

    /// Turned off on another device: the core refuses, the bubble says off
    /// and the settings are read again.
    func testRefusedAsOffShowsOff() async {
        let d = FakeDevice()
        d.gifDataError = BarkingError.Gif(kind: .notEnabled, retryAfterSecs: 0)
        let l = loads(d)
        var turnedOff = 0
        l.onTurnedOff = { turnedOff += 1 }
        l.configure(enabled: true, autoLoad: false, provider: klipy)
        l.appeared(1, gif: gif)
        XCTAssertTrue(l.load(1))
        await eventually { l.state(1) != .loading }
        XCTAssertEqual(l.state(1), .off)
        XCTAssertEqual(turnedOff, 1)
    }

    /// Klipy's quota: Retry does nothing before the delay, then asks again.
    func testBusyRetriesOnlyAfterTheDelay() async {
        let d = FakeDevice()
        d.gifDataError = BarkingError.Gif(kind: .rateLimited, retryAfterSecs: 60)
        let l = loads(d)
        var clock = Date(timeIntervalSince1970: 1_000)
        l.now = { clock }
        l.configure(enabled: true, autoLoad: false, provider: klipy)
        l.appeared(1, gif: gif)
        XCTAssertTrue(l.load(1))
        await eventually { l.state(1) != .loading }
        XCTAssertEqual(l.state(1), .rateLimited(until: Date(timeIntervalSince1970: 1_060)))
        XCTAssertFalse(l.load(1))
        clock = Date(timeIntervalSince1970: 1_061)
        d.gifDataError = nil
        XCTAssertTrue(l.load(1))
        await eventually { l.state(1) != .loading }
        XCTAssertEqual(d.gifDataCalls.count, 2)
    }

    /// "Couldn't load · Retry" asks again; "GIF no longer available" never.
    func testRetryAfterFailureButNotWhenGone() async {
        let d = FakeDevice()
        d.gifDataError = BarkingError.Gif(kind: .unreachable, retryAfterSecs: 0)
        let l = loads(d)
        l.configure(enabled: true, autoLoad: false, provider: klipy)
        l.appeared(1, gif: gif)
        XCTAssertTrue(l.load(1))
        await eventually { l.state(1) != .loading }
        XCTAssertEqual(l.state(1), .failed)
        d.gifDataError = BarkingError.Gif(kind: .notFound, retryAfterSecs: 0)
        XCTAssertTrue(l.load(1))
        await eventually { l.state(1) != .loading }
        XCTAssertEqual(l.state(1), .gone)
        XCTAssertFalse(l.load(1))
        XCTAssertEqual(d.gifDataCalls.count, 2)
    }

    /// Too large or unreadable: "Couldn't load", without Retry.
    func testCannotLoadOffersNoRetry() async {
        let d = FakeDevice()
        d.gifDataError = BarkingError.Gif(kind: .tooLarge, retryAfterSecs: 0)
        let l = loads(d)
        l.configure(enabled: true, autoLoad: false, provider: klipy)
        l.appeared(1, gif: gif)
        XCTAssertTrue(l.load(1))
        await eventually { l.state(1) != .loading }
        XCTAssertEqual(l.state(1), .cannotLoad)
        XCTAssertFalse(l.load(1))
        XCTAssertEqual(d.gifDataCalls.count, 1)
    }

    /// No usable key in this build (none, or refused): "GIFs are
    /// unavailable in this version", without Retry.
    func testNotConfiguredOffersNoRetry() async {
        let d = FakeDevice()
        d.gifDataError = BarkingError.Gif(kind: .notConfigured, retryAfterSecs: 0)
        let l = loads(d)
        l.configure(enabled: true, autoLoad: false, provider: klipy)
        l.appeared(1, gif: gif)
        XCTAssertTrue(l.load(1))
        await eventually { l.state(1) != .loading }
        XCTAssertEqual(l.state(1), .notConfigured)
        XCTAssertFalse(l.load(1))
        XCTAssertEqual(d.gifDataCalls.count, 1)
        XCTAssertEqual(GifBubble.identifier(.notConfigured), "gifBubble.notConfigured")
    }

    func testUnknownProviderAsksNothing() async {
        let d = FakeDevice()
        let l = loads(d)
        l.configure(enabled: true, autoLoad: true, provider: klipy)
        l.appeared(1, gif: GifInfo(provider: 9, id: "x", width: 10, height: 10))
        XCTAssertEqual(l.state(1), .unavailable)
        XCTAssertFalse(l.load(1))
        try? await Task.sleep(for: .milliseconds(100))
        XCTAssertEqual(d.gifDataCalls, [])
    }

    // MARK: "Play GIFs automatically ›"

    /// Under the first GIF not loaded, once per opening: it never moves on.
    func testAutoPlayHintUnderTheFirstGifOnly() async {
        let d = FakeDevice()
        let l = loads(d)
        let other = GifInfo(provider: 9, id: "x", width: 10, height: 10)
        let gifs: [(Int64, GifInfo)] = [(1, other), (2, gif), (3, gif)]
        l.configure(enabled: true, autoLoad: false, provider: klipy)
        l.pinHint(gifs)
        XCTAssertEqual(l.hintAnchor, 2)
        l.pinHint([(4, gif)] + gifs)
        XCTAssertEqual(l.hintAnchor, 2)
        l.appeared(2, gif: gif)
        XCTAssertTrue(l.load(2))
        await eventually { l.state(2) != .loading }
        XCTAssertNil(l.hintAnchor, "the hint left with the GIF loaded")
        l.pinHint(gifs)
        XCTAssertNil(l.hintAnchor, "the hint moved to another GIF")
    }

    /// Never under a GIF that cannot load: gone, unknown, or failing for good.
    func testAutoPlayHintOnlyUnderALoadableGif() async {
        let d = FakeDevice()
        d.gifDataError = BarkingError.Gif(kind: .notFound, retryAfterSecs: 0)
        let l = loads(d)
        l.configure(enabled: true, autoLoad: false, provider: klipy)
        l.appeared(1, gif: gif)
        XCTAssertTrue(l.load(1))
        await eventually { l.state(1) != .loading }
        XCTAssertEqual(l.state(1), .gone)
        l.pinHint([(1, gif), (2, gif)])
        XCTAssertEqual(l.hintAnchor, 2, "pinned under a GIF no longer available")
    }

    /// Pinned, then found gone: the hint leaves (and does not move on).
    func testAutoPlayHintLeavesAGoneGif() async {
        let d = FakeDevice()
        d.gifDataError = BarkingError.Gif(kind: .notFound, retryAfterSecs: 0)
        let l = loads(d)
        l.configure(enabled: true, autoLoad: false, provider: klipy)
        l.pinHint([(1, gif), (2, gif)])
        XCTAssertEqual(l.hintAnchor, 1)
        l.appeared(1, gif: gif)
        XCTAssertTrue(l.load(1))
        await eventually { l.state(1) != .loading }
        XCTAssertNil(l.hintAnchor)
    }

    /// Not while GIFs are off (that would be a nudge, spec §9.6), nor with
    /// auto-play on.
    func testNoAutoPlayHintWhenOffOrAlreadyOn() {
        let l = loads(FakeDevice())
        l.configure(enabled: false, autoLoad: false, provider: klipy)
        l.pinHint([(1, gif)])
        XCTAssertNil(l.hintAnchor)
        l.configure(enabled: true, autoLoad: true, provider: klipy)
        l.pinHint([(1, gif)])
        XCTAssertNil(l.hintAnchor)
        l.configure(enabled: true, autoLoad: false, provider: klipy)
        l.pinHint([(1, gif)])
        XCTAssertEqual(l.hintAnchor, 1)
    }

    // MARK: Words

    /// What VoiceOver reads as the bubble's value: the caption shown.
    func testCaptionsForVoiceOver() {
        let now = Date(timeIntervalSince1970: 1_000)
        func caption(_ s: GifLoad?) -> String? {
            GifBubble.caption(s, providerName: "Klipy", now: now, bundle: .main, locale: Locale(identifier: "en"))
        }
        XCTAssertEqual(caption(.off), "GIF · from Klipy, off")
        XCTAssertEqual(caption(.unavailable), "GIF unavailable")
        XCTAssertEqual(caption(.gone), "GIF no longer available")
        XCTAssertEqual(caption(.failed), "Couldn't load · Retry")
        XCTAssertEqual(caption(.cannotLoad), "Couldn't load")
        XCTAssertEqual(caption(.notConfigured), "GIFs are unavailable in this version")
        XCTAssertEqual(caption(.rateLimited(until: now.addingTimeInterval(60))), "Klipy is busy · Retry in 1 min")
        XCTAssertEqual(caption(.tapToLoad), "Tap to load")
        XCTAssertNil(caption(.loading))
        XCTAssertNil(caption(nil))
    }

    /// "Double-tap to load" only where a tap loads.
    func testHintOnlyWhereATapLoads() {
        let now = Date(timeIntervalSince1970: 1_000)
        XCTAssertEqual(GifBubble.hintKey(.off, now: now), "GIFs are off")
        XCTAssertEqual(GifBubble.hintKey(.tapToLoad, now: now), "Double-tap to load")
        XCTAssertEqual(GifBubble.hintKey(.failed, now: now), "Double-tap to load")
        XCTAssertNil(GifBubble.hintKey(.rateLimited(until: now.addingTimeInterval(30)), now: now))
        XCTAssertEqual(GifBubble.hintKey(.rateLimited(until: now), now: now), "Double-tap to load")
        XCTAssertNil(GifBubble.hintKey(.cannotLoad, now: now))
        XCTAssertNil(GifBubble.hintKey(.gone, now: now))
        XCTAssertNil(GifBubble.hintKey(.unavailable, now: now))
        XCTAssertNil(GifBubble.hintKey(.notConfigured, now: now))
    }

    func testBubbleStringsInFrench() throws {
        let fr = try XCTUnwrap(Bundle.main.path(forResource: "Localizable", ofType: "strings", inDirectory: nil,
                                                forLocalization: "fr").flatMap { NSDictionary(contentsOfFile: $0) })
        for key in ["GIF unavailable", "GIF · from %@, off", "Tap to load", "GIF no longer available",
                    "Couldn't load · Retry", "Couldn't load", "%@ is busy · Retry in %lld min", "Play GIFs automatically ›",
                    "Double-tap to load", "GIFs are off", "GIF: %@", "Plays the GIF.", "Play",
                    "GIFs are unavailable in this version"] {
            XCTAssertNotNil(fr[key], "missing French for \(key)")
        }
    }

    // MARK: The conversation's rows

    /// A GIF row keeps its GIF; a failed GIF is not hidden by a later one
    /// (the old retry rule matched on the text, "GIF" for every GIF).
    func testConversationRowsCarryTheGif() async {
        let d = FakeDevice()
        d.contactList = [Contact(fingerprint: "b", alias: "bob", displayName: "Bob", verified: false)]
        let failed = Delivery.state(.notDelivered)
        d.messageList = ["b": [
            Message(id: 1, outgoing: true, body: "GIF", at: 1, delivery: failed, gif: gif),
            Message(id: 2, outgoing: true, body: "GIF", at: 2, delivery: .state(.received),
                    gif: GifInfo(provider: 1, id: "dog-3", width: 200, height: 200)),
            Message(id: 3, outgoing: false, body: "hi", at: 3),
        ]]
        let m = ConversationModel(contact: "b", core: CoreService(device: d, runner: DirectRunner()))
        await m.onAppear()
        XCTAssertEqual(m.items.map(\.id), [1, 2, 3])
        XCTAssertEqual(m.items[0].gif, gif)
        XCTAssertNil(m.items[2].gif)
        // Nothing to copy in a GIF; reply and react stay.
        XCTAssertEqual(m.items.map(\.canCopy), [false, false, true])
        XCTAssertEqual(m.items[1].canReplyOrReact, true)
    }
}
