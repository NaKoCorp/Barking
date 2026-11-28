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
    /// The provider could not be used now: unreachable, or a reply this
    /// version does not understand. Offers a retry.
    case unreachable
    /// This build has no usable key for the provider (none, or refused):
    /// no retry, it would get the same.
    case notConfigured
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
    /// The previews on the way, by URL: a cell that scrolls out and back
    /// joins its request instead of starting a second one. Emptied with
    /// `previews`.
    private var inFlight: [String: Task<Data?, Never>] = [:]
    /// The latest request: an older reply arriving later is dropped (a
    /// device call cannot be cancelled).
    private var generation = 0
    /// Preview requests at once: at most six, the others wait their turn
    /// (a fast scroll is not a burst at the provider).
    let previewSlots = PreviewSlots(limit: 6)

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
        inFlight = [:]
    }

    /// A result's preview, fetched by the core (spec GIF §6.2): consent is
    /// checked right before the request and the request is counted in
    /// Transparency. One request per URL and page: a call while the same
    /// URL is on the way waits for it. A cell gone before its request
    /// started sends nothing; one gone during it lets the request finish
    /// (a device call cannot be cancelled) and the preview is kept for the
    /// page. Nil if it failed, or if the cell or the results it belongs to
    /// went meanwhile. GIFs turned off meanwhile close the picker. At most
    /// six requests at once (`previewSlots`): a cell gone while waiting for
    /// its turn sends nothing and gives its turn up.
    func preview(_ url: String) async -> Data? {
        if let d = previews[url] { return d }
        guard !done, !Task.isCancelled else { return nil }
        if inFlight[url] == nil {
            let mine = generation
            guard await previewSlots.acquire() else { return nil }
            // Things moved while it waited: give the turn back, then look
            // again (a new page, a preview kept or on the way, the picker
            // closed, the cell gone).
            guard mine == generation, !done, !Task.isCancelled, previews[url] == nil, inFlight[url] == nil else {
                previewSlots.release()
                return Task.isCancelled ? nil : await preview(url)
            }
            start(url)
        }
        guard let request = inFlight[url] else { return previews[url] }
        let d = await request.value
        return Task.isCancelled ? nil : d
    }

    /// Starts the request of `url`, holding a turn of `previewSlots` that
    /// it gives back once the core answered.
    private func start(_ url: String) {
        let mine = generation
        let core = core
        let slots = previewSlots
        inFlight[url] = Task<Data?, Never> { [weak self] in
            let result: Result<Data, Error>
            do { result = .success(try await core.gifPreview(url)) } catch { result = .failure(error) }
            slots.release()
            return self?.finish(url, result, generation: mine)
        }
    }

    /// Keeps a preview of the page still shown; a failure may be retried
    /// when the cell comes back.
    private func finish(_ url: String, _ result: Result<Data, Error>, generation mine: Int) -> Data? {
        guard mine == generation else { return nil }
        inFlight[url] = nil
        switch result {
        case .success(let d):
            previews[url] = d
            return d
        case .failure(let error):
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
        inFlight = [:]
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
        case .notConfigured: return .notConfigured
        case .notEnabled, .unreachable, .notFound, .tooLarge, .malformed: return .unreachable
        }
    }
}

/// At most `limit` holders at once; the others wait in line, first come
/// first served. A waiter whose task is cancelled leaves the line without
/// ever holding a turn, so no turn is lost.
@MainActor
final class PreviewSlots {
    let limit: Int
    /// Turns held now.
    private(set) var running = 0
    private var line: [(id: Int, go: CheckedContinuation<Bool, Never>)] = []
    private var lastID = 0

    /// Waiters in line.
    var waiting: Int { line.count }

    init(limit: Int) {
        self.limit = limit
    }

    /// True once a turn is held, to `release` after use; false if the task
    /// was cancelled first (nothing to release then).
    func acquire() async -> Bool {
        if Task.isCancelled { return false }
        if running < limit {
            running += 1
            return true
        }
        lastID += 1
        let id = lastID
        return await withTaskCancellationHandler {
            await withCheckedContinuation { go in line.append((id, go)) }
        } onCancel: {
            Task { @MainActor in self.leave(id) }
        }
    }

    /// Gives a turn back: to the first waiter, if any.
    func release() {
        if line.isEmpty {
            running = max(0, running - 1)
        } else {
            line.removeFirst().go.resume(returning: true)
        }
    }

    private func leave(_ id: Int) {
        guard let i = line.firstIndex(where: { $0.id == id }) else { return }
        line.remove(at: i).go.resume(returning: false)
    }
}

/// Whether the phone has a network path at all, and whether it is in Low
/// Data Mode, watched for the app's life (started at launch). Until the
/// first update: online (the picker tries, the core says if it fails), but
/// constrained, so no GIF loads on its own before the path is known.
final class GifNetworkPath: @unchecked Sendable {
    static let shared = GifNetworkPath()
    /// Posted on the main queue when the path changed.
    static let changed = Notification.Name("barking.gif.pathChanged")
    private let monitor = NWPathMonitor()
    private let lock = NSLock()
    private var satisfied = true
    private var known = false
    private var constrained = false

    private init() {
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            self.lock.withLock {
                self.satisfied = path.status == .satisfied
                self.constrained = path.isConstrained
                self.known = true
            }
            DispatchQueue.main.async { NotificationCenter.default.post(name: Self.changed, object: nil) }
        }
        monitor.start(queue: DispatchQueue(label: "barking.gif.path"))
    }

    /// Starts watching, so the path is known by the time a GIF shows.
    static func start() { _ = shared }

    var isOnline: Bool { lock.withLock { satisfied } }
    /// Low Data Mode (`NWPath.isConstrained`): no GIF loads on its own.
    var isConstrained: Bool { lock.withLock { Self.isConstrained(known: known, constrained: constrained) } }

    /// A path not known yet counts as constrained: never fail open.
    static func isConstrained(known: Bool, constrained: Bool) -> Bool { !known || constrained }
}
