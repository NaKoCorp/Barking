import BarkingKit
import SwiftUI

// Delivery components (spec Lot M §6.1, §6.2, §7.1). The four states come
// from the core (`BarkingKit.DeliveryState`); this file only says how they
// look and how VoiceOver reads them.

extension DeliveryState {
    /// The states in the order the legend and lists show them.
    static let ordered: [DeliveryState] = [.pending, .onNetwork, .received, .notDelivered]

    /// Compile-time guard: a new state breaks this switch, and so `ordered`.
    private var exhaustive: Void {
        switch self { case .pending, .onNetwork, .received, .notDelivered: () }
    }

    /// SF symbol name (§6.2). Received is two `checkmark`s composed by
    /// `DoubleCheck`, so it follows size, weight and tint like a symbol.
    var symbol: String {
        switch self {
        case .pending: "clock"
        case .onNetwork, .received: "checkmark"
        case .notDelivered: "exclamationmark.triangle.fill"
        }
    }

    /// Drawn as two checkmarks.
    var isDouble: Bool { self == .received }

    /// Asset name of the tint. Never red: `danger` is for "Delete".
    var tintToken: String {
        switch self {
        case .pending, .onNetwork: "fgSoft"
        case .received: "accent"
        case .notDelivered: "warnFg"
        }
    }

    var tint: Color { Color(tintToken) }

    var word: LocalizedStringKey {
        switch self {
        case .pending: "Pending"
        case .onNetwork: "On the network"
        case .received: "Received"
        case .notDelivered: "Not delivered"
        }
    }

    /// The word in a given language (tests and VoiceOver phrases).
    func wordString(bundle: Bundle = .main, locale: Locale = .current) -> String {
        switch self {
        case .pending: String(localized: "Pending", bundle: bundle, locale: locale)
        case .onNetwork: String(localized: "On the network", bundle: bundle, locale: locale)
        case .received: String(localized: "Received", bundle: bundle, locale: locale)
        case .notDelivered: String(localized: "Not delivered", bundle: bundle, locale: locale)
        }
    }

    /// The symbol at `size` points (font size). Inherits weight and foreground style.
    @ViewBuilder func symbolView(size: CGFloat) -> some View {
        if isDouble { DoubleCheck(size: size) } else { Image(systemName: symbol) }
    }

    /// VoiceOver value (§7.1): "Pending since 14:02", "Received at 14:05, on
    /// 1 of 2 devices". `self` is the state to speak; `delivery` carries the times.
    func spoken(_ delivery: Delivery, bundle: Bundle = .main, locale: Locale = .current,
                timeZone: TimeZone = .current) -> String {
        func time(_ seconds: UInt64) -> String {
            Date(timeIntervalSince1970: TimeInterval(seconds)).formatted(
                Date.FormatStyle(date: .omitted, time: .shortened, locale: locale, timeZone: timeZone))
        }
        switch self {
        case .pending:
            return String(localized: "Pending since \(time(delivery.sealedAt))", bundle: bundle, locale: locale)
        case .onNetwork:
            return String(localized: "On the network since \(time(delivery.depositedAt ?? delivery.sealedAt))",
                          bundle: bundle, locale: locale)
        case .received:
            let at = time(delivery.receivedAt ?? delivery.depositedAt ?? delivery.sealedAt)
            if delivery.devices > 1 && delivery.devicesReceived < delivery.devices {
                return String(localized: "Received at \(at), on \(Int(delivery.devicesReceived)) of \(Int(delivery.devices)) devices",
                              bundle: bundle, locale: locale)
            }
            return String(localized: "Received at \(at)", bundle: bundle, locale: locale)
        case .notDelivered:
            guard let expired = delivery.expiredAt else {
                return String(localized: "Not delivered.", bundle: bundle, locale: locale)
            }
            return String(localized: "Not delivered. Expired at \(time(expired)).", bundle: bundle, locale: locale)
        }
    }
}

/// Two checkmarks: one full check in front and the second behind it,
/// shifted right. The back one is cut away where it would touch the front
/// check (grown by about a stroke) and left of the front check's long arm,
/// so only its long arm and a short stub show: no crossing, no sliver. Built
/// from the system `checkmark`, so it takes the font weight, baseline and
/// foreground style of its context. `size` is the font size in points.
struct DoubleCheck: View {
    let size: CGFloat

    private var offset: CGFloat { size * 0.42 }
    private var gap: CGFloat { size * 0.11 }

    var body: some View {
        let check = Image(systemName: "checkmark")
        ZStack(alignment: .leading) {
            check.padding(.leading, offset).mask {
                Rectangle().overlay(alignment: .leading) {
                    ZStack(alignment: .leading) {
                        ForEach(0..<16, id: \.self) { i in
                            let a = Double(i) * .pi / 8
                            check.offset(x: cos(a) * gap, y: sin(a) * gap)
                        }
                        // Everything left of the front check's long arm
                        // (in the checkmark's own frame).
                        check.hidden().overlay {
                            GeometryReader { g in
                                Path { p in
                                    let w = g.size.width, h = g.size.height
                                    let ax = w * 0.37, ay = h * 0.92, dx = w * 0.56, dy = -h * 0.85
                                    p.move(to: .init(x: ax + 3 * dx, y: ay + 3 * dy))
                                    p.addLine(to: .init(x: ax - 2 * dx, y: ay - 2 * dy))
                                    p.addLine(to: .init(x: -3 * w, y: ay - 2 * dy))
                                    p.addLine(to: .init(x: -3 * w, y: ay + 3 * dy))
                                    p.closeSubpath()
                                }
                            }
                        }
                    }
                    .blendMode(.destinationOut)
                }
                .compositingGroup()
            }
            check
        }
        .fixedSize()
    }
}

/// The symbol, tinted, scaled with a text style. Hidden from VoiceOver:
/// the parent element speaks the state. `maximum` is the width of the
/// column it sits in; the symbol never outgrows it, and is centred.
struct DeliveryGlyph: View {
    let state: DeliveryState
    let style: Font.TextStyle
    let maximum: CGFloat?
    @ScaledMetric private var scaled: CGFloat

    init(_ state: DeliveryState, relativeTo style: Font.TextStyle = .caption, maximum: CGFloat? = nil) {
        self.state = state
        self.style = style
        self.maximum = maximum
        _scaled = ScaledMetric(wrappedValue: 12, relativeTo: style)
    }

    private var size: CGFloat { maximum.map { min(scaled, $0 * 0.7) } ?? scaled }

    var body: some View {
        state.symbolView(size: size)
            .font(.system(size: size, weight: .semibold))
            .foregroundStyle(state.tint)
            .contentTransition(.symbolEffect(.replace))
            .barkingAnimation(Motion.feedback, value: state)
            .frame(width: maximum, height: maximum)
            .accessibilityHidden(true)
    }
}

/// Spoken for a sent message with no delivery record.
extension BubbleMeta {
    static func sentElsewhere(bundle: Bundle = .main, locale: Locale = .current) -> String {
        String(localized: "Sent from another of your devices", bundle: bundle, locale: locale)
    }
}

/// Time + glyph under an outgoing bubble, on the background. For .notDelivered,
/// a separate 44 pt "Retry" button follows. Time only when state is nil.
/// The time and glyph are hidden from VoiceOver (the bubble speaks them);
/// the Retry button stays a separate element.
struct BubbleMeta: View {
    let state: DeliveryState?
    let at: Date
    let alignment: HorizontalAlignment
    let retry: (() -> Void)?

    init(state: DeliveryState?, at: Date, alignment: HorizontalAlignment, retry: (() -> Void)?) {
        self.state = state
        self.at = at
        self.alignment = alignment
        self.retry = retry
    }

    var body: some View {
        VStack(alignment: alignment, spacing: 0) {
            HStack(spacing: Space.s1) {
                Text(at, format: .dateTime.hour().minute()).font(.bMeta).foregroundStyle(Color.fgSoft)
                if let state { DeliveryGlyph(state) }
            }
            .accessibilityHidden(true)
            .accessibilityShowsLargeContentViewer {
                if let state { Label { Text(state.word) } icon: { state.symbolView(size: 24) } }
            }
            if state == .notDelivered, let retry {
                TextLink("Retry", tint: .warnFg, action: retry).frame(minWidth: 44)
            }
        }
        .frame(maxWidth: .infinity, alignment: Alignment(horizontal: alignment, vertical: .center))
    }
}

/// The states as compact chips; the current one highlighted
/// (Tag .accent, or warnBg/warnFg for .notDelivered). "Not delivered" only when current.
struct DeliveryLegend: View {
    let current: DeliveryState
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    init(current: DeliveryState) { self.current = current }

    /// The chips to show: "Not delivered" only when it is the current state.
    static func states(current: DeliveryState) -> [DeliveryState] {
        [.pending, .onNetwork, .received] + (current == .notDelivered ? [.notDelivered] : [])
    }

    var body: some View {
        let states = Self.states(current: current)
        Group {
            if dynamicTypeSize >= .accessibility3 {
                VStack(alignment: .leading, spacing: Space.s1) {
                    ForEach(states, id: \.self) { chip($0) }
                }
            } else {
                FlowLayout { ForEach(states, id: \.self) { chip($0) } }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("Current state: \(current.wordString())."))
    }

    private func chip(_ state: DeliveryState) -> some View {
        let on = state == current
        let warn = on && state == .notDelivered
        let shape = RoundedRectangle(cornerRadius: Radius.tag)
        return HStack(spacing: Space.s1) {
            DeliveryGlyph(state, relativeTo: .caption2)
            Text(state.word).font(.bTag).lineLimit(2).multilineTextAlignment(.leading)
        }
        .foregroundStyle(on ? (warn ? Color.warnFg : Color.accent) : Color.fgMuted)
        .padding(.horizontal, 6).padding(.vertical, 2)
        .background(on ? (warn ? Color.warnBg : Color.wash) : Color.field, in: shape)
        .overlay { if warn { shape.strokeBorder(Color.warnBorder, lineWidth: 1) } }
    }
}

/// Traceroute-like log: one line per step, the same glyphs as the bubble,
/// solid connector where the message went, dashed ahead, times in tabular Fira.
struct DeliveryTimeline: View {
    struct Step: Identifiable {
        let id: String
        let glyph: DeliveryState?        // nil: a neutral dot (sealed)
        let title: Text                  // "Deposited on relay K7QX2M4A"
        let at: Date?                    // nil: "not yet"
        let detail: Text?                // what a relay could see, a reason line
        let phase: Phase
        /// The detail says what a relay could see: it gets the purple rule.
        var privacy = false
    }
    enum Phase { case done, ahead, stopped }
    enum Connector: Equatable { case solid, dashed }

    let steps: [Step]
    init(steps: [Step]) { self.steps = steps }

    @ScaledMetric(relativeTo: .caption) private var column: CGFloat = 16
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @Environment(\.locale) private var locale

    /// The line below each step but the last: solid between two steps the
    /// message went through, dashed ahead (and into a stop).
    static func connectors(of steps: [Step]) -> [Connector] {
        zip(steps, steps.dropFirst()).map { $0.phase == .done && $1.phase == .done ? .solid : .dashed }
    }

    /// `HH:mm:ss`, with the weekday in front when it is not today ("jeu. 09:12:03").
    static func timeText(_ at: Date, now: Date, calendar: Calendar, locale: Locale) -> String {
        let f = DateFormatter()
        f.locale = locale
        f.calendar = calendar
        f.timeZone = calendar.timeZone
        f.dateFormat = calendar.isDate(at, inSameDayAs: now) ? "HH:mm:ss" : "EEE HH:mm:ss"
        return f.string(from: at)
    }

    var body: some View {
        let lines = Self.connectors(of: steps)
        VStack(alignment: .leading, spacing: 0) {
            ForEach(Array(steps.enumerated()), id: \.element.id) { i, step in
                row(step, below: i < lines.count ? lines[i] : nil)
            }
        }
    }

    private func row(_ step: Step, below: Connector?) -> some View {
        let width = min(column, 20)
        let accessible = dynamicTypeSize.isAccessibilitySize
        return HStack(alignment: .top, spacing: Space.s3) {
            VStack(spacing: 2) {
                marker(step, width: width).frame(width: width, height: width)
                if let below {
                    VerticalLine()
                        .stroke(below == .solid ? Color.accent : Color.borderStrong,
                                style: StrokeStyle(lineWidth: below == .solid ? 2 : 1.5, dash: below == .solid ? [] : [3, 3]))
                        .frame(width: 2).frame(maxHeight: .infinity)
                }
            }
            VStack(alignment: .leading, spacing: 2) {
                if accessible {
                    title(step)
                    timeLabel(step)
                } else {
                    HStack(alignment: .firstTextBaseline, spacing: Space.s2) {
                        title(step)
                        Spacer(minLength: Space.s2)
                        timeLabel(step)
                    }
                }
                if let detail = step.detail { detailView(detail, step) }
            }
            .padding(.bottom, below == nil ? 0 : Space.s3)
        }
        .fixedSize(horizontal: false, vertical: true)
        .accessibilityElement(children: .combine)
        .accessibilityValue(step.phase == .done ? Text("done") : step.phase == .stopped ? Text("stopped") : Text(""))
        .barkingAnimation(Motion.feedback, value: step.phase)
    }

    @ViewBuilder private func marker(_ step: Step, width: CGFloat) -> some View {
        switch step.phase {
        case .ahead:
            Circle().strokeBorder(Color.borderStrong, lineWidth: 1.5).frame(width: 10, height: 10)
        case .done, .stopped:
            if let glyph = step.glyph {
                DeliveryGlyph(glyph, maximum: width)
            } else {
                Circle().fill(step.phase == .stopped ? Color.warnFg : Color.fgSoft).frame(width: 8, height: 8)
            }
        }
    }

    private func title(_ step: Step) -> some View {
        step.title.font(.bBody).foregroundStyle(step.phase == .ahead ? Color.fgSoft : Color.fg)
            .fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder private func timeLabel(_ step: Step) -> some View {
        let text: Text? = if let at = step.at {
            Text(verbatim: Self.timeText(at, now: .now, calendar: .current, locale: locale))
        } else {
            switch step.phase {
            case .done: Text("not recorded")
            case .ahead: Text("not yet")
            case .stopped: nil
            }
        }
        if let text { text.font(.bMeta).monospacedDigit().foregroundStyle(Color.fgSoft) }
    }

    private func detailView(_ detail: Text, _ step: Step) -> some View {
        detail.font(BarkingFont.mono(.caption, size: 12, weight: .medium))
            .foregroundStyle(step.phase == .ahead ? Color.fgSoft : Color.fgMuted)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.leading, step.privacy ? Space.s2 : 0)
            .overlay(alignment: .leading) { if step.privacy { Rectangle().fill(Color.accent).frame(width: 2) } }
    }
}

private struct VerticalLine: Shape {
    func path(in rect: CGRect) -> Path {
        var p = Path()
        p.move(to: CGPoint(x: rect.midX, y: rect.minY))
        p.addLine(to: CGPoint(x: rect.midX, y: rect.maxY))
        return p
    }
}

/// A row of "Deliveries" or "Pending": glyph column, title, one-line excerpt, meta.
/// No chevron unless asked for (`chevron()`); the list owns selection and chevrons.
struct DeliveryRow: View {
    let state: DeliveryState
    let title: String?
    let excerpt: String
    let meta: Text
    let warnMeta: Bool
    private var showsChevron = false

    init(state: DeliveryState, title: String?, excerpt: String, meta: Text, warnMeta: Bool = false) {
        self.state = state
        self.title = title
        self.excerpt = excerpt
        self.meta = meta
        self.warnMeta = warnMeta
    }

    @ScaledMetric(relativeTo: .body) private var column: CGFloat = 24
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    func chevron(_ shown: Bool = true) -> DeliveryRow {
        var copy = self
        copy.showsChevron = shown
        return copy
    }

    /// Line breaks become spaces: the excerpt is one line.
    static func oneLine(_ text: String) -> String {
        text.components(separatedBy: .newlines).filter { !$0.isEmpty }.joined(separator: " ")
    }

    var body: some View {
        let accessible = dynamicTypeSize.isAccessibilitySize
        HStack(alignment: .top, spacing: Space.s3) {
            DeliveryGlyph(state, relativeTo: .body, maximum: min(column, 28))
            VStack(alignment: .leading, spacing: 2) {
                if accessible { metaLabel }
                if let title { Text(verbatim: title).font(BarkingFont.sans(.subheadline, size: 15, weight: .semibold)).foregroundStyle(Color.fg) }
                Text(verbatim: Self.oneLine(excerpt)).font(.bBodySmall).foregroundStyle(Color.fgMuted)
                    .lineLimit(accessible ? 2 : 1)
            }
            Spacer(minLength: Space.s2)
            if !accessible {
                metaLabel
            }
            if showsChevron && !accessible {
                Text(verbatim: "›").font(.bMeta).foregroundStyle(Color.fgSoft).accessibilityHidden(true)
            }
        }
        .frame(minHeight: 56)
        .accessibilityElement(children: .combine)
    }

    private var metaLabel: some View {
        HStack(spacing: Space.s1) {
            if warnMeta { Image(systemName: "exclamationmark.triangle.fill").accessibilityHidden(true) }
            meta
        }
        .font(.bMeta)
        .foregroundStyle(warnMeta ? Color.warnFg : Color.fgSoft)
    }
}

#if DEBUG
private enum Sample {
    static let time = Date(timeIntervalSince1970: 1_794_060_127)
    static let steps: [DeliveryTimeline.Step] = [
        .init(id: "sealed", glyph: nil, title: Text(verbatim: "Sealed and saved on this iPhone"), at: time,
              detail: Text(verbatim: "2 devices · 1 KB"), phase: .done),
        .init(id: "relay", glyph: .onNetwork, title: Text(verbatim: "Deposited on relay K7QX2M4A"), at: time + 34,
              detail: Text(verbatim: "Could see: a sealed packet of 1 KB for a mailbox that changes every day."),
              phase: .done, privacy: true),
        .init(id: "some", glyph: .received, title: Text(verbatim: "Received on 1 of 2 devices"), at: time + 185,
              detail: nil, phase: .done),
        .init(id: "all", glyph: .received, title: Text(verbatim: "Received on all their devices"), at: nil,
              detail: nil, phase: .ahead),
    ]
    static let stopped: [DeliveryTimeline.Step] = [
        steps[0],
        .init(id: "stop", glyph: .notDelivered, title: Text(verbatim: "Not delivered"), at: nil,
              detail: Text(verbatim: "Expired on Nov 13 at 11:50 before a relay accepted it. It never left this iPhone."),
              phase: .stopped),
    ]
}

#Preview("Delivery glyphs and meta") {
    PreviewMatrix {
        HStack(spacing: 16) { ForEach(DeliveryState.ordered, id: \.self) { DeliveryGlyph($0) } }
        HStack(spacing: 16) { ForEach(DeliveryState.ordered, id: \.self) { DeliveryGlyph($0, relativeTo: .title) } }
        BubbleMeta(state: .received, at: Sample.time, alignment: .trailing, retry: nil)
        BubbleMeta(state: nil, at: Sample.time, alignment: .leading, retry: nil)
        BubbleMeta(state: .notDelivered, at: Sample.time, alignment: .trailing, retry: {})
    }
}

#Preview("Delivery legend") {
    PreviewMatrix {
        DeliveryLegend(current: .onNetwork)
        DeliveryLegend(current: .received)
        DeliveryLegend(current: .notDelivered)
    }
}

#Preview("Delivery timeline") {
    PreviewMatrix {
        DeliveryTimeline(steps: Sample.steps)
        DeliveryTimeline(steps: Sample.stopped)
    }
}

#Preview("Delivery row") {
    PreviewMatrix {
        DeliveryRow(state: .notDelivered, title: nil, excerpt: "On se voit au marché\nà 18 h", meta: Text(verbatim: "14:02")).chevron()
        DeliveryRow(state: .pending, title: "Alice", excerpt: "On se voit au marché à 18 h",
                    meta: Text(verbatim: "expires in 1 h"), warnMeta: true)
        DeliveryRow(state: .received, title: nil, excerpt: "Merci", meta: Text(verbatim: "Mon 14:02")).chevron()
    }
}
#endif
