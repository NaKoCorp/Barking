import BarkingKit
import Foundation
import Observation
import SwiftUI

/// What a GIF bubble shows (spec GIF §7).
enum GifLoad: Equatable {
    /// GIFs are off for its provider (the default): nothing is asked.
    case off
    /// On, auto-play off (or Low Data Mode): asked on a tap.
    case tapToLoad
    case loading
    /// In memory while the bubble is on screen, never kept.
    case loaded(Data, author: String?, title: String)
    /// A provider this client does not know.
    case unavailable
    /// Removed, or above the content filter: never asked again.
    case gone
    /// Offline, or the provider unreachable: a retry is offered.
    case failed
    /// Too large, or a reply this version cannot read: "Couldn't load",
    /// without Retry (it would get the same). Not "no longer available":
    /// the GIF may well exist.
    case cannotLoad
    /// The provider's quota: a retry is offered from `until`.
    case rateLimited(until: Date)

    /// What a failed request shows. `notEnabled` means GIFs were turned
    /// off meanwhile (here or on another device).
    static func after(_ error: Error, now: Date) -> GifLoad {
        guard case BarkingError.Gif(let kind, let secs) = error else { return .failed }
        switch kind {
        case .notEnabled: return .off
        case .notFound: return .gone
        case .tooLarge, .malformed: return .cannotLoad
        case .rateLimited: return .rateLimited(until: now.addingTimeInterval(TimeInterval(max(secs, 1))))
        case .offline, .unreachable, .notConfigured: return .failed
        }
    }

    /// The wait before a retry, in whole minutes, rounded up.
    static func minutesLeft(until: Date, now: Date) -> Int {
        max(0, Int((until.timeIntervalSince(now) / 60).rounded(.up)))
    }

    /// A tap may still load it (now or once the quota's wait is over).
    var loadable: Bool {
        switch self {
        case .tapToLoad, .loading, .failed, .rateLimited: true
        default: false
        }
    }

    /// The MP4, once loaded.
    var media: Data? {
        if case .loaded(let data, _, _) = self { return data }
        return nil
    }
}

/// The state a GIF bubble starts in, from the settings the core holds
/// and the phone's network (Low Data Mode: never on its own).
func gifLoadState(gif: GifInfo, settings: GifSettingsInfo, constrained: Bool, providerKnown: Bool) -> GifLoad {
    guard providerKnown else { return .unavailable }
    guard settings.enabled else { return .off }
    guard settings.autoLoad, !constrained else { return .tapToLoad }
    return .loading
}

/// The GIFs of one open conversation: their state while their bubble is
/// on screen, and their requests. A GIF is asked for only once its bubble
/// appeared; its media goes when the bubble does (spec GIF §6.3, §7). A
/// bubble that comes back while its request is on the way joins it.
@MainActor @Observable
final class GifLoads {
    private let core: CoreService
    /// Low Data Mode (tests set it).
    var isConstrained: () -> Bool = { GifNetworkPath.shared.isConstrained }
    var now: () -> Date = Date.init
    /// The core said GIFs are off while the app thought them on (turned
    /// off on another device): the settings should be read again.
    var onTurnedOff: () -> Void = {}

    /// Nil until the core's settings and provider are known: the bubbles
    /// stay neutral and nothing is asked.
    private var settings: GifSettingsInfo?
    private var provider: GifProviderInfo?
    /// The bubbles on screen.
    private var shown: [Int64: GifInfo] = [:]
    private var states: [Int64: GifLoad] = [:]
    /// Requests on the way, by message.
    private var inFlight: [Int64: Task<Void, Never>] = [:]
    /// The GIF "Play GIFs automatically ›" goes under: chosen once per
    /// opening, never moved to another.
    private var hintPinned: Int64?

    init(core: CoreService) {
        self.core = core
    }

    /// What the bubble of `id` shows; nil while it is neutral.
    func state(_ id: Int64) -> GifLoad? { states[id] }

    /// A request for `id` is on the way.
    func isLoading(_ id: Int64) -> Bool { inFlight[id] != nil }

    /// The phone's path changed (Low Data Mode on or off, or known at
    /// last): the bubbles on screen follow, as after a settings change.
    func pathChanged() {
        for (id, gif) in shown { follow(id, gif) }
    }

    /// The settings as the core holds them. The bubbles on screen follow:
    /// GIFs off drops what was loaded; auto-play on loads what is shown.
    func configure(enabled: Bool, autoLoad: Bool, provider: GifProviderInfo?) {
        self.provider = provider
        settings = provider == nil ? nil : GifSettingsInfo(enabled: enabled, autoLoad: autoLoad,
                                                           enabledFromOtherDevice: nil, enabledAt: nil,
                                                           consentOutdated: false, enabledFromUnlistedDevice: false)
        for (id, gif) in shown { follow(id, gif) }
    }

    func appeared(_ id: Int64, gif: GifInfo) {
        shown[id] = gif
        if inFlight[id] != nil, let start = initial(gif), start != .off, start != .unavailable {
            states[id] = .loading
            return
        }
        follow(id, gif)
    }

    /// The media goes with the bubble. A request on the way is not
    /// cancelled (a device call cannot be): its reply is dropped unless
    /// the bubble is back by then.
    func disappeared(_ id: Int64) {
        shown[id] = nil
        states[id] = nil
    }

    /// "Tap to load", "Retry", or the warning's "Use GIFs" for this GIF.
    /// False when there is nothing to ask: GIFs off, unknown provider,
    /// gone, loaded, already on the way, or the quota's wait not over.
    @discardableResult
    func load(_ id: Int64) -> Bool {
        guard let gif = shown[id], let state = states[id] else { return false }
        switch state {
        case .tapToLoad, .failed:
            begin(id, gif)
            return true
        case .rateLimited(let until) where now() >= until:
            begin(id, gif)
            return true
        default:
            return false
        }
    }

    /// Pins "Play GIFs automatically ›" under the first GIF not loaded of
    /// `gifs` (in the conversation's order), once per opening. Only while
    /// GIFs are on and auto-play is off: never a nudge to turn GIFs on.
    func pinHint(_ gifs: [(id: Int64, gif: GifInfo)]) {
        guard hintPinned == nil, let settings, let provider, settings.enabled, !settings.autoLoad else { return }
        hintPinned = gifs.first { $0.gif.provider == provider.id && states[$0.id]?.loadable ?? true }?.id
    }

    /// The GIF the hint shows under now: one a tap can still load. Nil once
    /// that GIF is loaded or cannot load, or with auto-play on.
    var hintAnchor: Int64? {
        guard let id = hintPinned, let settings, settings.enabled, !settings.autoLoad,
              states[id]?.loadable ?? true else { return nil }
        return id
    }

    private func initial(_ gif: GifInfo) -> GifLoad? {
        guard let settings, let provider else { return nil }
        return gifLoadState(gif: gif, settings: settings, constrained: isConstrained(),
                            providerKnown: gif.provider == provider.id)
    }

    /// The bubble `id` after a change of settings, or as it appears: off
    /// or unknown always wins; otherwise a bubble not started yet takes
    /// the new start, and one started keeps its state.
    private func follow(_ id: Int64, _ gif: GifInfo) {
        guard let start = initial(gif) else { return }
        switch (start, states[id]) {
        case (.off, _), (.unavailable, _):
            states[id] = start
        case (_, nil), (_, .off?), (_, .unavailable?), (_, .tapToLoad?):
            if start == .loading { begin(id, gif) } else { states[id] = start }
        default:
            break
        }
    }

    private func begin(_ id: Int64, _ gif: GifInfo) {
        states[id] = .loading
        guard inFlight[id] == nil else { return }
        let core = core
        inFlight[id] = Task { [weak self] in
            let result: Result<GifMediaInfo, Error>
            do { result = .success(try await core.gifData(provider: gif.provider, id: gif.id)) } catch {
                result = .failure(error)
            }
            self?.finish(id, result)
        }
    }

    /// Shown only to a bubble still on screen and still waiting for it.
    private func finish(_ id: Int64, _ result: Result<GifMediaInfo, Error>) {
        inFlight[id] = nil
        guard shown[id] != nil, states[id] == .loading else { return }
        switch result {
        case .success(let m):
            states[id] = .loaded(m.mp4, author: m.author, title: m.title)
        case .failure(let error):
            let next = GifLoad.after(error, now: now())
            states[id] = next
            if next == .off { onTurnedOff() }
        }
    }
}

/// A GIF message: the slot its width and height reserve from the start
/// (within the bubble's width), then the GIF, the author under it when the
/// provider names one (spec GIF §7, §9.5). Its tap is `action`, except
/// once loaded (the bubble's own tap then opens the message).
struct GifBubble: View {
    let gif: GifInfo
    let outgoing: Bool
    /// Nil: neutral, the settings are not read yet.
    let state: GifLoad?
    /// The provider's name, as the core gives it.
    let providerName: String
    var quote: QuoteLine?
    var highlighted = false
    var onQuote: () -> Void = {}
    /// Load, retry, or open the warning.
    let action: () -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.accessibilityPlayAnimatedImages) private var playAnimatedImages
    @Environment(\.locale) private var locale
    /// The discreet indicator, after 300 ms only (no flash).
    @State private var spinner = false
    /// A still GIF started by its play button; stops when the bubble leaves.
    @State private var playing = false
    /// The quota's wait is over: Retry works.
    @State private var retryOpen = false

    /// The reserved shape, within reason (a 1 × 400 GIF stays usable).
    static func ratio(_ gif: GifInfo) -> CGFloat {
        guard gif.width > 0, gif.height > 0 else { return 1 }
        return min(max(CGFloat(gif.width) / CGFloat(gif.height), 0.5), 2.5)
    }

    /// Played on its own, or still on its first frame (Reduce Motion,
    /// animated images or video autoplay off).
    private var still: Bool {
        !GifPlayer.plays(reduceMotion: reduceMotion || !playAnimatedImages,
                         videoAutoplay: UIAccessibility.isVideoAutoplayEnabled)
    }

    var body: some View {
        let shape = Bubble.shape(outgoing: outgoing)
        VStack(alignment: .leading, spacing: 0) {
            if let quote {
                Group {
                    if quote.available {
                        QuoteView(line: quote, outgoing: outgoing).onTapGesture(perform: onQuote)
                    } else {
                        QuoteView(line: quote, outgoing: outgoing)
                    }
                }
                .padding(8)
            }
            slot
            if case .loaded(_, let author?, _) = state, !author.isEmpty {
                Text(verbatim: author).font(.bMeta)
                    .foregroundStyle(outgoing ? Color.white.opacity(0.85) : Color.fgMuted)
                    .lineLimit(1)
                    .padding(.horizontal, 12).padding(.vertical, 6)
            }
        }
        .frame(maxWidth: max(CGFloat(gif.width), 220), alignment: .leading)
        .foregroundStyle(outgoing ? Color.white : Color.fg)
        .background(outgoing ? Color.accentFill : Color.surfaceCard, in: shape)
        .clipShape(shape)
        .overlay(shape.stroke(outgoing ? Color.clear : Color.border, lineWidth: 1))
        .overlay {
            shape.stroke(outgoing ? Color.fg : Color.accent, lineWidth: 3).opacity(highlighted ? 1 : 0)
                .animation(highlighted ? nil : Motion.gated(Bubble.highlightFade, reduceMotion: reduceMotion),
                           value: highlighted)
                .allowsHitTesting(false)
        }
        .contentShape(.contextMenuPreview, shape)
        .task(id: state == .loading) {
            spinner = false
            guard state == .loading else { return }
            try? await Task.sleep(for: .milliseconds(300))
            if !Task.isCancelled { spinner = true }
        }
        .task(id: rateLimitedUntil) {
            retryOpen = false
            guard let until = rateLimitedUntil else { return }
            let wait = until.timeIntervalSinceNow
            if wait > 0 { try? await Task.sleep(for: .seconds(wait)) }
            if !Task.isCancelled { retryOpen = true }
        }
        .onDisappear { playing = false }
    }

    private var rateLimitedUntil: Date? {
        if case .rateLimited(let until) = state { return until }
        return nil
    }

    @ViewBuilder private var slot: some View {
        let neutral = Color.surfaceAlt
            .aspectRatio(Self.ratio(gif), contentMode: .fit)
            .frame(maxWidth: .infinity)
        if case .loaded(let data, _, let title) = state {
            neutral
                .overlay { GifPlayer(data: data, play: playing) }
                // Loaded, a tap opens the message (`action`), as a text
                // bubble's does; the play button above keeps its own tap.
                .contentShape(.rect)
                .onTapGesture(perform: action)
                .overlay {
                    if still && !playing {
                        Button { playing = true } label: {
                            Image(systemName: "play.fill").font(.bSymbol(18, relativeTo: .body))
                                .foregroundStyle(Color.white)
                                .frame(width: 44, height: 44)
                                .background(Color.black.opacity(0.45), in: .circle)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel(Text("Play"))
                        .accessibilityHint(Text("Plays the GIF."))
                    }
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(title.isEmpty ? Text("GIF") : Text("GIF: \(title)"))
                .accessibilityActions {
                    if still && !playing { Button("Play") { playing = true } }
                }
        } else {
            Button(action: action) {
                neutral.overlay { caption.padding(12) }
            }
            .buttonStyle(.plain)
            .disabled(!tappable)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text("GIF"))
        }
    }

    /// Whether a tap does something here.
    private var tappable: Bool {
        switch state {
        case .off?, .tapToLoad?, .failed?: true
        case .rateLimited?: retryOpen
        default: false
        }
    }

    @ViewBuilder private var caption: some View {
        let muted = Color.fgMuted
        let text = Self.caption(state, providerName: providerName, now: .now, bundle: .strings(for: locale),
                                locale: locale) ?? ""
        switch state {
        case nil, .loaded?:
            EmptyView()
        case .loading?:
            if spinner { ProgressView().controlSize(.small) }
        case .off?:
            VStack(spacing: Space.s2) {
                Text(verbatim: "GIF").font(BarkingFont.mono(.caption, size: 12)).fontWeight(.semibold)
                    .foregroundStyle(muted)
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .overlay(RoundedRectangle(cornerRadius: Radius.tag).stroke(muted, lineWidth: 1))
                line(text, color: muted)
            }
        case .tapToLoad?:
            Label { Text(verbatim: text) } icon: { Image(systemName: "arrow.down.circle") }
                .font(BarkingFont.sans(.footnote, size: 13, weight: .semibold)).foregroundStyle(Color.accent)
        case .failed?:
            line(text, color: Color.accent)
        case .rateLimited?:
            line(text, color: retryOpen ? Color.accent : muted)
        case .unavailable?, .gone?, .cannotLoad?:
            line(text, color: muted)
        }
    }

    private func line(_ text: String, color: Color) -> some View {
        Text(verbatim: text).font(BarkingFont.sans(.footnote, size: 13)).foregroundStyle(color)
            .multilineTextAlignment(.center)
            .fixedSize(horizontal: false, vertical: true)
    }

    /// The caption shown in `state` (spec GIF §7), also VoiceOver's value
    /// for the bubble; nil when none shows.
    static func caption(_ state: GifLoad?, providerName: String, now: Date, bundle: Bundle = .main,
                        locale: Locale = .current) -> String? {
        switch state {
        case nil, .loading?, .loaded?: nil
        case .off?: String(localized: "GIF · from \(providerName), off", bundle: bundle, locale: locale)
        case .tapToLoad?: String(localized: "Tap to load", bundle: bundle, locale: locale)
        case .unavailable?: String(localized: "GIF unavailable", bundle: bundle, locale: locale)
        case .gone?: String(localized: "GIF no longer available", bundle: bundle, locale: locale)
        case .failed?: String(localized: "Couldn't load · Retry", bundle: bundle, locale: locale)
        case .cannotLoad?: String(localized: "Couldn't load", bundle: bundle, locale: locale)
        case .rateLimited(let until)?:
            String(localized: "\(providerName) is busy · Retry in \(max(1, GifLoad.minutesLeft(until: until, now: now))) min",
                   bundle: bundle, locale: locale)
        }
    }
}

extension GifBubble {
    /// VoiceOver's hint for the bubble in `state` (spec GIF §7): "Double-tap
    /// to load" only where a tap loads now; nil otherwise.
    static func hintKey(_ state: GifLoad?, now: Date) -> LocalizedStringKey? {
        switch state {
        case .off?: "GIFs are off"
        case .tapToLoad?, .failed?: "Double-tap to load"
        case .rateLimited(let until)? where now >= until: "Double-tap to load"
        default: nil
        }
    }

    /// The bubble's state for UI tests (`gifBubble.<name>`).
    static func identifier(_ state: GifLoad?) -> String {
        let name = switch state {
        case nil: "neutral"
        case .off?: "off"
        case .tapToLoad?: "tapToLoad"
        case .loading?: "loading"
        case .loaded?: "loaded"
        case .unavailable?: "unavailable"
        case .gone?: "gone"
        case .failed?: "failed"
        case .cannotLoad?: "cannotLoad"
        case .rateLimited?: "rateLimited"
        }
        return "gifBubble.\(name)"
    }
}
