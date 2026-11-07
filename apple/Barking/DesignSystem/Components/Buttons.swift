import SwiftUI

/// The three button shapes of the app.
enum ButtonKind { case primary, secondary, danger }

/// What a button can do right now. Loading wins over the other flags: the
/// action already runs and a second tap must not start it again.
enum ButtonState: Equatable {
    case enabled, disabled, loading

    init(enabled: Bool, isLoading: Bool) {
        self = isLoading ? .loading : (enabled ? .enabled : .disabled)
    }

    var isInteractive: Bool { self == .enabled }
}

/// Colour tokens of a button (asset names, `white` for the label on purple).
/// Disabled is a slot (`fillDisabled`, `fgDisabled`, `borderDisabled`), never
/// an opacity on purple: it must not read as enabled on Ink or vanish on Paper.
struct ButtonTokens: Equatable {
    let fill: String?
    let label: String
    let border: String?

    static func of(_ kind: ButtonKind, _ state: ButtonState) -> ButtonTokens {
        if state == .disabled { return .init(fill: "fillDisabled", label: "fgDisabled", border: "borderDisabled") }
        return switch kind {
        case .primary: .init(fill: "accentFill", label: "white", border: nil)
        case .secondary: .init(fill: nil, label: "fg", border: "borderStrong")
        case .danger: .init(fill: nil, label: "danger", border: "danger")
        }
    }
}

/// What a press draws. Under the outlined `danger` label no tint is laid:
/// `danger` on a `danger` tint falls below 4.5:1 on Paper, so the outline
/// thickens instead (as the hold does).
enum PressedLook: Equatable {
    case darken
    case tint(String, Double)
    case thickerOutline(CGFloat)
}

extension ButtonTokens {
    static func pressed(_ kind: ButtonKind) -> PressedLook {
        switch kind {
        case .primary: .darken
        case .secondary: .tint("wash", 0.6)
        case .danger: .thickerOutline(2)
        }
    }
}

private extension Color {
    init(token: String) { self = token == "white" ? .white : Color(token) }
}

/// 52 pt, radius 6, Fira Code 600 15, clipped inside the component so a
/// `List` or `Form` row cannot turn it into a capsule.
struct BarkingButtonStyle: ButtonStyle {
    let kind: ButtonKind
    let state: ButtonState

    func makeBody(configuration: Configuration) -> some View {
        let t = ButtonTokens.of(kind, state)
        let shape = RoundedRectangle(cornerRadius: Radius.button)
        return configuration.label
            .font(.bButton)
            .multilineTextAlignment(.center)
            .foregroundStyle(Color(token: t.label))
            .padding(.horizontal, Space.s4)
            .padding(.vertical, Space.s2)
            .frame(maxWidth: .infinity, minHeight: 52)
            .background(t.fill.map { Color(token: $0) } ?? Color.clear)
            // Pressed: purple-d on the fill, `wash` under the neutral outline,
            // a heavier `danger` outline (never a tint under its label).
            .overlay {
                if configuration.isPressed {
                    switch ButtonTokens.pressed(kind) {
                    case .darken: Color.black.opacity(0.14)
                    case .tint(let token, let opacity): Color(token: token).opacity(opacity)
                    case .thickerOutline: Color.clear
                    }
                }
            }
            .clipShape(shape)
            .overlay {
                if let b = t.border {
                    let width: CGFloat = if configuration.isPressed, case .thickerOutline(let w) = ButtonTokens.pressed(kind) { w } else { 1 }
                    shape.strokeBorder(Color(token: b), lineWidth: width)
                }
            }
            .contentShape(shape)
    }
}

extension ButtonStyle where Self == BarkingButtonStyle {
    /// The primary look for a control that is not a `PrimaryButton` (a
    /// `ShareLink`).
    static var barkingPrimary: BarkingButtonStyle { BarkingButtonStyle(kind: .primary, state: .enabled) }
}

/// The label and, while loading, a spinner in the label's colour.
private struct ButtonLabel: View {
    let title: LocalizedStringKey
    let kind: ButtonKind
    let state: ButtonState

    var body: some View {
        HStack(spacing: Space.s2) {
            if state == .loading {
                ProgressView().tint(Color(token: ButtonTokens.of(kind, state).label))
                    .accessibilityHidden(true)
            }
            Text(title)
        }
    }
}

/// Primary action: purple fill, white Fira Code 600, 52 pt. Disabled, it can
/// say why under the button (`reason`, also the VoiceOver value).
struct PrimaryButton: View {
    let title: LocalizedStringKey
    let state: ButtonState
    let reason: LocalizedStringKey?
    let identifier: String?
    let action: () -> Void

    /// `identifier` goes on the button itself, not on the stack that also
    /// holds the reason line.
    init(_ title: LocalizedStringKey, enabled: Bool = true, isLoading: Bool = false,
         reason: LocalizedStringKey? = nil, identifier: String? = nil, action: @escaping () -> Void) {
        self.title = title
        self.state = ButtonState(enabled: enabled, isLoading: isLoading)
        self.reason = reason
        self.identifier = identifier
        self.action = action
    }

    var body: some View {
        let why = state == .disabled ? reason : nil
        VStack(spacing: Space.s2) {
            Button(action: action) { ButtonLabel(title: title, kind: .primary, state: state) }
                .buttonStyle(BarkingButtonStyle(kind: .primary, state: state))
                .disabled(!state.isInteractive)
                // The reason is the value only: as a hint too, VoiceOver read it twice.
                .accessibilityValue(state == .loading ? Text("In progress") : (why.map { Text($0) } ?? Text(verbatim: "")))
                .accessibilityIdentifier(ifPresent: identifier)
            if let why {
                Text(why)
                    .font(.bBodySmall).foregroundStyle(Color.fgMuted)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: .infinity)
                    .accessibilityHidden(true)
            }
        }
    }
}

/// Secondary action: 1 px outline, 52 pt.
struct SecondaryButton: View {
    let title: LocalizedStringKey
    let state: ButtonState
    let action: () -> Void

    init(_ title: LocalizedStringKey, enabled: Bool = true, action: @escaping () -> Void) {
        self.title = title
        self.state = ButtonState(enabled: enabled, isLoading: false)
        self.action = action
    }

    var body: some View {
        Button(action: action) { ButtonLabel(title: title, kind: .secondary, state: state) }
            .buttonStyle(BarkingButtonStyle(kind: .secondary, state: state))
            .disabled(!state.isInteractive)
    }
}

/// Destructive action: 1 px `danger` outline, `danger` Fira Code 600, 52 pt.
/// The shape matches the other buttons, so colour is not the only signal;
/// it belongs in a zone of its own and opens a confirmation.
struct DangerButton: View {
    let title: LocalizedStringKey
    let hint: LocalizedStringKey?
    let identifier: String?
    let action: () -> Void

    /// `identifier` goes on the button itself, not on the stack that also
    /// holds the hint line.
    init(_ title: LocalizedStringKey, hint: LocalizedStringKey? = nil, identifier: String? = nil,
         action: @escaping () -> Void) {
        self.title = title
        self.hint = hint
        self.identifier = identifier
        self.action = action
    }

    var body: some View {
        VStack(spacing: Space.s2) {
            Button(action: action) { ButtonLabel(title: title, kind: .danger, state: .enabled) }
                .buttonStyle(BarkingButtonStyle(kind: .danger, state: .enabled))
                .accessibilityHint(hint.map { Text($0) } ?? Text(verbatim: ""))
                .accessibilityIdentifier(ifPresent: identifier)
            if let hint {
                Text(hint)
                    .font(.bMeta).foregroundStyle(Color.fgMuted)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: .infinity)
                    .accessibilityHidden(true)
            }
        }
    }
}

/// What a hold-to-confirm draws while the finger is down: a `danger`
/// sweep across the button, or, under Reduce Motion, the whole seconds left
/// ("2… 1…") and nothing that moves.
enum HoldIndicator: Equatable {
    case idle
    case sweep(Double)
    case counter(Int)

    static func of(elapsed: TimeInterval?, duration: TimeInterval, reduceMotion: Bool) -> HoldIndicator {
        guard let elapsed else { return .idle }
        if reduceMotion { return .counter(max(1, Int((duration - elapsed).rounded(.up)))) }
        return .sweep(min(max(elapsed / duration, 0), 1))
    }
}

enum HoldMetrics {
    /// The sweep is solid `danger`; where it has passed, the label turns
    /// `surface`. A tint of `danger` under a `danger` label falls below
    /// 4.5:1 on Paper (4.8:1 with no tint at all), so the swept part swaps
    /// the pair instead.
    static let sweepFill = "danger"
    static let labelOnSweep = "surface"

    /// A scene phase that ends a hold. A transient `.inactive` (Control
    /// Center, a notification banner) keeps the finger's hold; going to the
    /// background cancels the touch without telling the gesture.
    static func resetsHold(on phase: ScenePhase) -> Bool { phase == .background }
}

/// A destructive action that needs a hold (Erase Barking, UI review U-8):
/// the `DangerButton` shape, a 2 s `danger` sweep (a counter under Reduce
/// Motion), a warning haptic when the hold completes, then `onConfirmed`,
/// which opens the confirmation. A tap does nothing. VoiceOver cannot hold:
/// its double-tap and a named action open the same confirmation.
struct HoldToConfirmButton: View {
    let title: LocalizedStringKey
    let duration: TimeInterval
    let hint: LocalizedStringKey
    let identifier: String?
    let onConfirmed: () -> Void
    @State private var pressedAt: Date?
    @State private var completed = 0
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.scenePhase) private var scenePhase

    init(_ title: LocalizedStringKey, duration: Duration = .seconds(2), hint: LocalizedStringKey,
         identifier: String? = nil, onConfirmed: @escaping () -> Void) {
        self.title = title
        self.duration = TimeInterval(duration.components.seconds)
            + TimeInterval(duration.components.attoseconds) / 1e18
        self.hint = hint
        self.identifier = identifier
        self.onConfirmed = onConfirmed
    }

    var body: some View {
        // Ticks only while the finger is down; a few times a second is
        // enough for the counter.
        TimelineView(.animation(minimumInterval: reduceMotion ? 0.1 : nil, paused: pressedAt == nil)) { context in
            let indicator = HoldIndicator.of(elapsed: pressedAt.map { context.date.timeIntervalSince($0) },
                                             duration: duration, reduceMotion: reduceMotion)
            VStack(spacing: Space.s2) {
                HoldFace(title: title, indicator: indicator)
                    .onLongPressGesture(minimumDuration: duration, maximumDistance: 30) {
                        pressedAt = nil
                        completed += 1
                        onConfirmed()
                    } onPressingChanged: { pressing in
                        pressedAt = pressing ? .now : nil
                    }
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel(Text(title))
                    .accessibilityAddTraits(.isButton)
                    .accessibilityHint(Text("Asks for confirmation first."))
                    // VoiceOver's double-tap, and the same as a named action.
                    .accessibilityAction { onConfirmed() }
                    .accessibilityAction(named: Text(title)) { onConfirmed() }
                    .accessibilityIdentifier(ifPresent: identifier)
                HoldCaption(hint: hint, indicator: indicator)
            }
        }
        .sensoryFeedback(Haptic.holdCompleted.feedback, trigger: completed)
        // A touch the system cancels without telling the gesture (the app
        // leaving) must not leave a sweep drawn; a pull of Control Center
        // (`.inactive`) is not that.
        .onChange(of: scenePhase) { _, phase in if HoldMetrics.resetsHold(on: phase) { pressedAt = nil } }
        .onDisappear { pressedAt = nil }
    }
}

/// The face of a `HoldToConfirmButton`: the `DangerButton` shape and the
/// sweep. Under Reduce Motion nothing moves; the outline thickens and the
/// caption counts.
struct HoldFace: View {
    let title: LocalizedStringKey
    let indicator: HoldIndicator
    @Environment(\.isEnabled) private var isEnabled

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: Radius.button)
        let swept: CGFloat = if case .sweep(let f) = indicator { f } else { 0 }
        label(isEnabled ? Color.danger : Color.fgDisabled)
            .background(alignment: .leading) {
                GeometryReader { g in Color(HoldMetrics.sweepFill).frame(width: g.size.width * swept) }
            }
            .overlay {
                label(Color(HoldMetrics.labelOnSweep))
                    .mask(alignment: .leading) {
                        GeometryReader { g in Rectangle().frame(width: g.size.width * swept) }
                    }
            }
            .clipShape(shape)
            // Held (the sweep, or the still counter): a heavier outline.
            .overlay {
                shape.strokeBorder(isEnabled ? Color.danger : Color.borderDisabled,
                                   lineWidth: indicator == .idle ? 1 : 2)
            }
            .contentShape(shape)
    }

    private func label(_ color: Color) -> some View {
        Text(title)
            .font(.bButton)
            .multilineTextAlignment(.center)
            .foregroundStyle(color)
            .padding(.horizontal, Space.s4)
            .padding(.vertical, Space.s2)
            .frame(maxWidth: .infinity, minHeight: 52)
    }
}

/// The line under the face: the hint, or under Reduce Motion the seconds
/// left while held. VoiceOver has its own hint on the face.
struct HoldCaption: View {
    let hint: LocalizedStringKey
    let indicator: HoldIndicator

    var body: some View {
        Group {
            // The counter is the only feedback under Reduce Motion: it is
            // drawn like the label, not like the hint.
            if case .counter(let left) = indicator {
                Text(verbatim: "\(left)…").font(.bButton).foregroundStyle(Color.danger)
            } else {
                Text(hint).font(.bMeta).foregroundStyle(Color.fgMuted)
            }
        }
        .multilineTextAlignment(.center)
        .frame(maxWidth: .infinity)
        .accessibilityHidden(true)
    }
}

/// An inline action in Fira Code 13 `accent`, 44 pt tall: "Suggest",
/// "Check now ›", "+ Add a relay". The glyph is drawn after the title and
/// is not read by VoiceOver.
struct TextLink: View {
    let title: LocalizedStringKey
    let glyph: String?
    let tint: Color
    let action: () -> Void

    init(_ title: LocalizedStringKey, glyph: String? = nil, tint: Color = .accent, action: @escaping () -> Void) {
        self.title = title
        self.glyph = glyph
        self.tint = tint
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            HStack(spacing: Space.s1) {
                Text(title)
                if let glyph { Text(verbatim: glyph).accessibilityHidden(true) }
            }
            .font(BarkingFont.mono(.footnote, size: 13, weight: .medium))
            .foregroundStyle(tint)
            .frame(minHeight: 44)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
    }
}

#if DEBUG
#Preview("Buttons") {
    PreviewMatrix {
        PrimaryButton("Create my identity") {}
        PrimaryButton("Create my identity", enabled: false, reason: "Type your name") {}
        PrimaryButton("Sync now", isLoading: true) {}
        SecondaryButton("They don't match") {}
        SecondaryButton("They don't match", enabled: false) {}
        DangerButton("Delete this contact", hint: "The history is kept.") {}
        HoldToConfirmButton("Erase Barking", hint: "Press and hold for 2 seconds") {}
        HoldFace(title: "Erase Barking", indicator: .sweep(0.5))
        HoldFace(title: "Erase Barking", indicator: .counter(1))
        HoldCaption(hint: "Press and hold for 2 seconds", indicator: .counter(1))
        TextLink("Check now", glyph: "›") {}
    }
}
#endif
