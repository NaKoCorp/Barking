import BarkingKit
import Foundation
import Network
import Observation

/// What the picker shows (spec GIF §9.4).
enum GifPickerState: Equatable {
    case loading
    /// Whole and in the provider's order: no sort, no filter here.
    case results([GifResultInfo])
    /// "No GIFs for “{query}”".
    case empty(query: String)
    case offline
    /// The provider could not be used now: unreachable, refused key, or a
    /// reply this version does not understand. Offers a retry.
    case unreachable
    /// The provider's quota.
    case rateLimited
}

/// The GIF picker: trending with an empty field, a search once typing has
/// paused for 400 ms. Only reachable with GIFs on; if they were turned off
/// meanwhile (`notEnabled`), it closes.
@MainActor @Observable
final class GifPickerModel {
    /// The search field. A change waits `debounce` before searching; a
    /// later change replaces the wait.
    var query = "" {
        didSet { if query != oldValue { scheduleSearch() } }
    }
    private(set) var state: GifPickerState = .loading
    /// The picker should close: a GIF was handed to the conversation, or
    /// GIFs are off.
    private(set) var done = false

    var debounce: Duration = .milliseconds(400)
    /// How the debounce waits (tests end the wait by hand).
    var sleep: @Sendable (Duration) async throws -> Void = { try await Task.sleep(for: $0) }
    /// The phone has a network path: without one, the provider is not called.
    var isOnline: @MainActor () -> Bool = { GifNetworkPath.shared.isOnline }

    private let core: CoreService
    private let sendGif: @MainActor (GifInfo) async -> Bool
    private var pending: Task<Void, Never>?
    /// The previews of the results shown now, in memory only; emptied at
    /// each new request and when the picker closes.
    private var previews: [String: Data] = [:]
    /// The latest request: an older reply arriving later is dropped (a
    /// device call cannot be cancelled).
    private var generation = 0

    /// `send` queues the GIF in the conversation (true once queued).
    init(core: CoreService, send: @escaping @MainActor (GifInfo) async -> Bool) {
        self.core = core
        self.sendGif = send
    }

    /// Trending, or what the field holds.
    func load() async { await run(query) }

    /// "Retry": the current text again, at once.
    func retry() async {
        pending?.cancel()
        await run(query)
    }

    /// Stops a search still waiting and forgets the previews (the sheet
    /// closes, or GIFs were turned off).
    func stop() {
        pending?.cancel()
        pending = nil
        generation += 1
        previews = [:]
    }

    /// A result's preview, fetched by the core (spec GIF §6.2): consent is
    /// checked right before the request and the request is counted in
    /// Transparency. Nil if it failed, or if the cell or the results it
    /// belongs to went meanwhile. GIFs turned off meanwhile close the picker.
    func preview(_ url: String) async -> Data? {
        if let d = previews[url] { return d }
        guard !done else { return nil }
        let mine = generation
        do {
            let d = try await core.gifPreview(url)
            guard mine == generation, !Task.isCancelled else { return nil }
            previews[url] = d
            return d
        } catch {
            if case BarkingError.Gif(kind: .notEnabled, _) = error {
                stop()
                done = true
            }
            return nil
        }
    }

    /// Hands the GIF to the conversation, then closes; the conversation says
    /// if it was not sent.
    func send(_ result: GifResultInfo) async {
        guard !done else { return }
        stop()
        _ = await sendGif(result.gif)
        done = true
    }

    private func scheduleSearch() {
        pending?.cancel()
        let wait = debounce
        let sleep = sleep
        pending = Task { [weak self] in
            do { try await sleep(wait) } catch { return }
            guard !Task.isCancelled, let self else { return }
            await self.run(self.query)
        }
    }

    /// One request for `text` (trending when blank); its reply is shown
    /// only if no later request started.
    func run(_ text: String) async {
        generation += 1
        // A new page: the previews of the last one are not kept.
        previews = [:]
        let mine = generation
        guard isOnline() else {
            state = .offline
            return
        }
        state = .loading
        let q = text.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            let page = q.isEmpty ? try await core.gifTrending(page: 1) : try await core.gifSearch(q, page: 1)
            guard mine == generation else { return }
            state = page.results.isEmpty ? .empty(query: q) : .results(page.results)
        } catch {
            guard mine == generation else { return }
            if case BarkingError.Gif(kind: .notEnabled, _) = error {
                stop()
                done = true
                return
            }
            state = Self.state(for: error)
        }
    }

    static func state(for error: Error) -> GifPickerState {
        guard case BarkingError.Gif(let kind, _) = error else { return .unreachable }
        switch kind {
        case .offline: return .offline
        case .rateLimited: return .rateLimited
        case .notEnabled, .notConfigured, .unreachable, .notFound, .tooLarge, .malformed: return .unreachable
        }
    }
}

/// Whether the phone has a network path at all, watched for the app's
/// life. Unknown until the first update: taken as online then.
final class GifNetworkPath: @unchecked Sendable {
    static let shared = GifNetworkPath()
    private let monitor = NWPathMonitor()
    private let lock = NSLock()
    private var satisfied = true

    private init() {
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            self.lock.withLock { self.satisfied = path.status == .satisfied }
        }
        monitor.start(queue: DispatchQueue(label: "barking.gif.path"))
    }

    var isOnline: Bool { lock.withLock { satisfied } }
}
