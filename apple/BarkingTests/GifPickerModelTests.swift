import AVFoundation
import XCTest
@testable import Barking
@testable import BarkingKit

/// The GIF picker (spec GIF §9.4): trending first, a search after 400 ms
/// without typing, the results in the provider's order, and one state per
/// failure.
@MainActor
final class GifPickerModelTests: XCTestCase {
    private func model(_ d: FakeDevice, online: Bool = true,
                       send: @escaping @MainActor (GifInfo) async -> Bool = { _ in true }) -> GifPickerModel {
        let m = GifPickerModel(core: CoreService(device: d, runner: DirectRunner()), send: send)
        m.isOnline = { online }
        return m
    }

    private func result(_ id: String) -> GifResultInfo {
        GifResultInfo(gif: GifInfo(provider: 1, id: id, width: 480, height: 270), title: id,
                      previewMp4Url: "https://static.klipy.com/\(id).mp4")
    }

    /// Polls until `condition` holds (calls run on a detached task).
    private func eventually(_ condition: @MainActor () -> Bool, timeout: TimeInterval = 2) async {
        let end = Date().addingTimeInterval(timeout)
        while !condition(), Date() < end { try? await Task.sleep(for: .milliseconds(10)) }
    }

    /// Three keystrokes within the wait give one search, for the last text.
    func testDebounce400ms() async {
        let d = FakeDevice()
        d.gifPage = GifPageInfo(results: [result("cat-1")], next: nil)
        let m = model(d)
        let gate = SleepGate()
        m.sleep = { try await gate.sleep($0) }
        m.query = "c"
        await gate.waitForSleepers(1)
        m.query = "ca"
        await gate.waitForSleepers(2)
        m.query = "cat"
        await gate.waitForSleepers(3)
        await gate.release()
        await eventually { m.state == .results([self.result("cat-1")]) }
        XCTAssertEqual(d.gifSearches, ["cat"])
        let waits = await gate.durations
        XCTAssertEqual(waits, [.milliseconds(400), .milliseconds(400), .milliseconds(400)])
    }

    func testErrorStates() async {
        let d = FakeDevice()
        let m = model(d)
        d.gifSearchError = BarkingError.Gif(kind: .offline, retryAfterSecs: 0)
        await m.run("cat")
        XCTAssertEqual(m.state, .offline)
        d.gifSearchError = BarkingError.Gif(kind: .rateLimited, retryAfterSecs: 60)
        await m.run("cat")
        XCTAssertEqual(m.state, .rateLimited)
        d.gifSearchError = BarkingError.Gif(kind: .unreachable, retryAfterSecs: 0)
        await m.run("cat")
        XCTAssertEqual(m.state, .unreachable)
        // No key in this build, or a reply not understood: Klipy can't be used now.
        d.gifSearchError = BarkingError.Gif(kind: .notConfigured, retryAfterSecs: 0)
        await m.run("cat")
        XCTAssertEqual(m.state, .unreachable)
        d.gifSearchError = nil
        d.gifPage = GifPageInfo(results: [], next: nil)
        await m.run("cat")
        XCTAssertEqual(m.state, .empty(query: "cat"))
        XCTAssertFalse(m.done)
    }

    /// Offline per the phone: nothing is asked of the core.
    func testOfflineMakesNoCall() async {
        let d = FakeDevice()
        let m = model(d, online: false)
        await m.load()
        XCTAssertEqual(m.state, .offline)
        XCTAssertEqual(d.gifTrendingCalls, 0)
        XCTAssertEqual(d.gifSearches, [])
    }

    /// Turned off meanwhile (another device, Settings): the picker closes.
    func testNotEnabledCloses() async {
        let d = FakeDevice()
        d.gifSearchError = BarkingError.Gif(kind: .notEnabled, retryAfterSecs: 0)
        let m = model(d)
        await m.load()
        XCTAssertTrue(m.done)
    }

    /// Kept whole and in the order the provider gave: no sort, no filter.
    func testResultsKeepProviderOrder() async {
        let d = FakeDevice()
        let order = [result("zebra-3"), result("apple-1"), result("mango-2"), result("apple-1b")]
        d.gifPage = GifPageInfo(results: order, next: 2)
        let m = model(d)
        await m.run("fruit")
        XCTAssertEqual(m.state, .results(order))
    }

    /// Trending first, with an empty field; a blank query is trending again.
    func testTrendingFirstAndForBlankQuery() async {
        let d = FakeDevice()
        d.gifPage = GifPageInfo(results: [result("hi-1")], next: nil)
        let m = model(d)
        await m.load()
        XCTAssertEqual(d.gifTrendingCalls, 1)
        await m.run("  ")
        XCTAssertEqual(d.gifTrendingCalls, 2)
        XCTAssertEqual(d.gifSearches, [])
    }

    /// Retry runs the current text again.
    func testRetryRunsTheQueryAgain() async {
        let d = FakeDevice()
        d.gifSearchError = BarkingError.Gif(kind: .unreachable, retryAfterSecs: 0)
        let m = model(d)
        let gate = SleepGate()
        m.sleep = { try await gate.sleep($0) }
        m.query = "owl"
        await gate.waitForSleepers(1)
        await gate.release()
        await eventually { m.state == .unreachable }
        d.gifSearchError = nil
        d.gifPage = GifPageInfo(results: [result("owl-1")], next: nil)
        await m.retry()
        XCTAssertEqual(m.state, .results([result("owl-1")]))
        XCTAssertEqual(d.gifSearches, ["owl", "owl"])
    }

    /// Sending hands the GIF to the conversation, then the picker closes.
    func testSendHandsTheGifOnAndCloses() async {
        let d = FakeDevice()
        var sent: [GifInfo] = []
        let m = model(d) { sent.append($0); return true }
        await m.send(result("wave-9"))
        XCTAssertEqual(sent, [result("wave-9").gif])
        XCTAssertTrue(m.done)
    }

    // MARK: Previews

    /// A preview comes from the core (consent, hosts and count are its
    /// job), once per URL while the page is shown.
    func testPreviewThroughTheCoreOncePerPage() async {
        let d = FakeDevice()
        let m = model(d)
        let url = "https://static.klipy.com/a.mp4"
        let first = await m.preview(url)
        let again = await m.preview(url)
        XCTAssertEqual(first, Data("MP4".utf8))
        XCTAssertEqual(again, first)
        XCTAssertEqual(d.gifPreviews, [url])
        // A new request: the previews of the old page are not kept.
        await m.run("cat")
        _ = await m.preview(url)
        XCTAssertEqual(d.gifPreviews, [url, url])
    }

    /// GIFs turned off while the picker is open: the core refuses the
    /// preview and the picker closes.
    func testPreviewRefusedClosesThePicker() async {
        let d = FakeDevice()
        d.gifPreviewError = BarkingError.Gif(kind: .notEnabled, retryAfterSecs: 0)
        let m = model(d)
        let got = await m.preview("https://static.klipy.com/a.mp4")
        XCTAssertNil(got)
        XCTAssertTrue(m.done)
        // Closed: no further request.
        _ = await m.preview("https://static.klipy.com/b.mp4")
        XCTAssertEqual(d.gifPreviews.count, 1)
    }

    /// A cell gone before its preview started sends nothing.
    func testCancelledBeforeStartSendsNothing() async {
        let d = FakeDevice()
        let m = model(d)
        let url = "https://static.klipy.com/a.mp4"
        let t = Task { await m.preview(url) }
        t.cancel()
        let got = await t.value
        XCTAssertNil(got)
        XCTAssertEqual(d.gifPreviews, [])
    }

    /// A cell that scrolls out and back while its preview is on the way
    /// joins that request: one call to the provider, not two.
    func testPreviewInFlightIsShared() async {
        let d = FakeDevice()
        d.gifPreviewDelay = 0.3
        let m = model(d)
        let url = "https://static.klipy.com/a.mp4"
        let first = Task { await m.preview(url) }
        await eventually { d.gifPreviews.count == 1 }
        // The first cell leaves; its request keeps going in the core.
        first.cancel()
        let again = await m.preview(url)
        XCTAssertEqual(again, Data("MP4".utf8))
        XCTAssertEqual(d.gifPreviews, [url])
        // Done and kept for this page: scrolling back again sends nothing.
        _ = await m.preview(url)
        XCTAssertEqual(d.gifPreviews, [url])
    }

    /// A new page forgets requests on the way too: the old reply is dropped
    /// and the URL is fetched again for the new page.
    func testNewPageForgetsPreviewsInFlight() async {
        let d = FakeDevice()
        d.gifPreviewDelay = 0.2
        let m = model(d)
        let url = "https://static.klipy.com/a.mp4"
        let old = Task { await m.preview(url) }
        await eventually { d.gifPreviews.count == 1 }
        await m.run("cat")
        let stale = await old.value
        XCTAssertNil(stale)
        _ = await m.preview(url)
        XCTAssertEqual(d.gifPreviews, [url, url])
    }

    // MARK: Player

    /// An MP4 held in memory plays without a file: its video track loads.
    func testPlayerAssetFromMemoryLoadsTracks() async throws {
        let data = try await TinyMP4.make()
        let source = GifMemoryAsset(data: data)
        let tracks = try await source.asset.loadTracks(withMediaType: .video)
        XCTAssertEqual(tracks.count, 1)
        let duration = try await source.asset.load(.duration)
        XCTAssertGreaterThan(duration.seconds, 0)
    }

    /// In a window: the layer gets a frame; playing, time runs; still, it
    /// holds at the start (Reduce Motion, autoplay off).
    func testPlayerShowsAFramePlayingOrStill() async throws {
        let data = try await TinyMP4.make()
        let window = UIWindow(frame: CGRect(x: 0, y: 0, width: 128, height: 128))
        window.isHidden = false
        for playing in [true, false] {
            let view = PlayerUIView(frame: window.bounds)
            window.addSubview(view)
            view.show(data, playing: playing)
            let layer = try XCTUnwrap(view.layer as? AVPlayerLayer)
            let end = Date().addingTimeInterval(5)
            while !layer.isReadyForDisplay, Date() < end { try await Task.sleep(for: .milliseconds(20)) }
            XCTAssertTrue(layer.isReadyForDisplay, "no frame (playing: \(playing))")
            let player = try XCTUnwrap(layer.player)
            if playing {
                XCTAssertGreaterThan(player.rate, 0)
            } else {
                try await Task.sleep(for: .milliseconds(300))
                XCTAssertEqual(player.rate, 0)
                XCTAssertEqual(player.currentTime().seconds, 0, accuracy: 0.05)
            }
            XCTAssertTrue(player.isMuted)
            XCTAssertFalse(player.allowsExternalPlayback)
            view.stop()
            view.removeFromSuperview()
        }
    }

    // MARK: Sending from the conversation

    /// Bob's conversation with one received message (id 7).
    private func conversation() async -> (FakeDevice, ConversationModel) {
        let d = FakeDevice()
        d.contactList = [Contact(fingerprint: "b", alias: "bob", displayName: "Bob", verified: false)]
        d.messageList = ["b": [Message(id: 7, outgoing: false, body: "hi", at: 1)]]
        let m = ConversationModel(contact: "b", core: CoreService(device: d, runner: DirectRunner()))
        await m.onAppear()
        return (d, m)
    }

    /// A GIF goes as a text does: to the reply target, with the delay set,
    /// both cleared once sent; the draft is left alone.
    func testConversationSendsGifWithReplyAndDelay() async throws {
        let (d, m) = await conversation()
        m.draft = "half typed"
        m.startReply(7)
        m.ttl = 300
        let gif = GifInfo(provider: 1, id: "wave-9", width: 480, height: 270)
        let ok = await m.sendGif(gif)
        XCTAssertTrue(ok)
        let sent = try XCTUnwrap(d.gifSent.first)
        XCTAssertEqual(sent.gif, gif)
        XCTAssertEqual(sent.replyTo, 7)
        XCTAssertEqual(sent.ttlSecs, 300)
        XCTAssertNil(m.replyingTo)
        XCTAssertNil(m.ttl)
        XCTAssertEqual(m.draft, "half typed")
    }

    /// A GIF tapped while another send runs is not sent, and says so.
    func testConversationGifRefusedWhileSendingSaysSo() async {
        let (d, m) = await conversation()
        d.syncDelay = 0.3
        m.draft = "text first"
        async let text: Void = m.send()
        try? await Task.sleep(for: .milliseconds(50))
        let ok = await m.sendGif(GifInfo(provider: 1, id: "wave-9", width: 480, height: 270))
        await text
        XCTAssertFalse(ok)
        XCTAssertTrue(d.gifSent.isEmpty)
        XCTAssertEqual(m.sendError, "Not sent. Try again in a moment.")
    }

    /// This device was removed from the account: the GIF is refused with
    /// the app's removed-device wording, never "Try again".
    func testConversationGifOnRemovedDeviceSaysRemoved() async {
        let d = FakeDevice()
        d.contactList = [Contact(fingerprint: "b", alias: "bob", displayName: "Bob", verified: false)]
        d.removedInfo = RemovedInfo(version: 3, at: 1)
        let m = ConversationModel(contact: "b", core: CoreService(device: d, runner: DirectRunner()))
        await m.onAppear()
        let ok = await m.sendGif(GifInfo(provider: 1, id: "wave-9", width: 480, height: 270))
        XCTAssertFalse(ok)
        XCTAssertTrue(d.gifSent.isEmpty)
        XCTAssertEqual(m.sendError, "This device was removed from your account")
    }

    /// Removed while the conversation was open: the core refuses it the
    /// same way.
    func testConversationGifRefusedAsRemovedByTheCore() async {
        let (d, m) = await conversation()
        d.sendError = BarkingError.DeviceRemoved
        let ok = await m.sendGif(GifInfo(provider: 1, id: "wave-9", width: 480, height: 270))
        XCTAssertFalse(ok)
        XCTAssertEqual(m.sendError, "This device was removed from your account")
    }

    /// The contact was removed meanwhile: the conversation's own banner
    /// says so, and no "Try again".
    func testConversationGifToRemovedContactSaysSo() async {
        let (d, m) = await conversation()
        d.sendError = BarkingError.NotFound
        let ok = await m.sendGif(GifInfo(provider: 1, id: "wave-9", width: 480, height: 270))
        XCTAssertFalse(ok)
        XCTAssertNil(m.sendError)
        XCTAssertEqual(m.notice, .contactRemoved)
    }

    /// A refused send keeps the reply target and the delay, and says so.
    func testConversationGifSendFailureKeepsReply() async {
        let (d, m) = await conversation()
        m.startReply(7)
        m.ttl = 300
        d.sendError = BarkingError.Storage(detail: "disk")
        let ok = await m.sendGif(GifInfo(provider: 1, id: "wave-9", width: 480, height: 270))
        XCTAssertFalse(ok)
        XCTAssertEqual(m.replyingTo?.id, 7)
        XCTAssertEqual(m.ttl, 300)
        XCTAssertNotNil(m.sendError)
    }
}

/// A sleep the test ends by hand; a cancelled sleeper throws.
private actor SleepGate {
    private(set) var durations: [Duration] = []
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var released = false

    func sleep(_ d: Duration) async throws {
        durations.append(d)
        if !released { await withCheckedContinuation { waiters.append($0) } }
        try Task.checkCancellation()
    }

    /// Waits until `n` sleeps started; gives up after 2 s (the test then fails).
    func waitForSleepers(_ n: Int) async {
        let end = Date().addingTimeInterval(2)
        while durations.count < n, Date() < end { try? await Task.sleep(for: .milliseconds(5)) }
    }

    func release() {
        released = true
        waiters.forEach { $0.resume() }
        waiters = []
    }
}

/// A short silent MP4 written by AVAssetWriter, read back into memory.
enum TinyMP4 {
    static func make() async throws -> Data {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("tiny-\(UUID().uuidString).mp4")
        defer { try? FileManager.default.removeItem(at: url) }
        let writer = try AVAssetWriter(outputURL: url, fileType: .mp4)
        let input = AVAssetWriterInput(mediaType: .video, outputSettings: [
            AVVideoCodecKey: AVVideoCodecType.h264, AVVideoWidthKey: 64, AVVideoHeightKey: 64,
        ])
        let adaptor = AVAssetWriterInputPixelBufferAdaptor(assetWriterInput: input, sourcePixelBufferAttributes: [
            kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA,
            kCVPixelBufferWidthKey as String: 64, kCVPixelBufferHeightKey as String: 64,
        ])
        writer.add(input)
        writer.startWriting()
        writer.startSession(atSourceTime: .zero)
        for i in 0..<10 {
            while !input.isReadyForMoreMediaData { try await Task.sleep(for: .milliseconds(5)) }
            var buffer: CVPixelBuffer?
            CVPixelBufferCreate(nil, 64, 64, kCVPixelFormatType_32BGRA, nil, &buffer)
            guard let buffer else { throw CocoaError(.fileWriteUnknown) }
            adaptor.append(buffer, withPresentationTime: CMTime(value: CMTimeValue(i), timescale: 10))
        }
        input.markAsFinished()
        await writer.finishWriting()
        guard writer.status == .completed else { throw writer.error ?? CocoaError(.fileWriteUnknown) }
        return try Data(contentsOf: url)
    }
}
