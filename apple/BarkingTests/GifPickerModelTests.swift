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

    /// With real time: three keystrokes 100 ms apart, then one search.
    func testDebounceInRealTime() async throws {
        let d = FakeDevice()
        let m = model(d)
        for q in ["d", "do", "dog"] {
            m.query = q
            try await Task.sleep(for: .milliseconds(100))
        }
        XCTAssertEqual(d.gifSearches, [], "searched before the pause")
        await eventually({ !d.gifSearches.isEmpty }, timeout: 3)
        try await Task.sleep(for: .milliseconds(500))
        XCTAssertEqual(d.gifSearches, ["dog"])
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

    /// Only Klipy's media hosts, over HTTPS on 443, without user info.
    func testPreviewURLPolicy() {
        for ok in ["https://static.klipy.com/a.mp4", "https://static1.klipy.com/x/y.mp4",
                   "https://static2.klipy.com/b.mp4", "https://static.klipy.com:443/c.mp4"] {
            XCTAssertNotNil(GifPreviewPolicy.url(ok), ok)
        }
        for bad in ["", "http://static.klipy.com/a.mp4", "https://api.klipy.com/a.mp4",
                    "https://static.klipy.com:8443/a.mp4", "https://user@static.klipy.com/a.mp4",
                    "https://static.klipy.com.evil.net/a.mp4", "https://cdn.example.com/a.mp4",
                    "file:///tmp/a.mp4", "https://STATIC.klipy.com.example/a.mp4"] {
            XCTAssertNil(GifPreviewPolicy.url(bad), bad)
        }
    }

    /// No cookie, no cache, a fixed user agent.
    func testPreviewSessionKeepsNothing() {
        let c = GifPreviewLoader.configuration()
        XCTAssertNil(c.urlCache)
        XCTAssertNil(c.httpCookieStorage)
        XCTAssertNil(c.urlCredentialStorage)
        XCTAssertFalse(c.httpShouldSetCookies)
        XCTAssertEqual(c.requestCachePolicy, .reloadIgnoringLocalCacheData)
        XCTAssertEqual(c.httpAdditionalHeaders?["User-Agent"] as? String, "Barking")
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

    func waitForSleepers(_ n: Int) async {
        while durations.count < n { await Task.yield() }
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
