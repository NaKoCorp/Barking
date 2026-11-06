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
            // Pressed: purple-d on the fill; under an outline, a tint of the
            // outline's own colour (danger stays danger, never purple).
            .overlay {
                if configuration.isPressed {
                    switch (kind, t.fill) {
                    case (_, .some): Color.black.opacity(0.14)
                    case (.danger, nil): Color.danger.opacity(0.10)
                    default: Color.wash.opacity(0.6)
                    }
                }
            }
            .clipShape(shape)
            .overlay { if let b = t.border { shape.strokeBorder(Color(token: b), lineWidth: 1) } }
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
    let action: () -> Void

    init(_ title: LocalizedStringKey, enabled: Bool = true, isLoading: Bool = false,
         reason: LocalizedStringKey? = nil, action: @escaping () -> Void) {
        self.title = title
        self.state = ButtonState(enabled: enabled, isLoading: isLoading)
        self.reason = reason
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
    let action: () -> Void

    init(_ title: LocalizedStringKey, hint: LocalizedStringKey? = nil, action: @escaping () -> Void) {
        self.title = title
        self.hint = hint
        self.action = action
    }

    var body: some View {
        VStack(spacing: Space.s2) {
            Button(action: action) { ButtonLabel(title: title, kind: .danger, state: .enabled) }
                .buttonStyle(BarkingButtonStyle(kind: .danger, state: .enabled))
                .accessibilityHint(hint.map { Text($0) } ?? Text(verbatim: ""))
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

/// An inline action in Fira Code 13 `accent`, 44 pt tall: "Suggest",
/// "Check now ›", "+ Add a relay". The glyph is drawn after the title and
/// is not read by VoiceOver.
struct TextLink: View {
    let title: LocalizedStringKey
    let glyph: String?
    let action: () -> Void

    init(_ title: LocalizedStringKey, glyph: String? = nil, action: @escaping () -> Void) {
        self.title = title
        self.glyph = glyph
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            HStack(spacing: Space.s1) {
                Text(title)
                if let glyph { Text(verbatim: glyph).accessibilityHidden(true) }
            }
            .font(BarkingFont.mono(.footnote, size: 13, weight: .medium))
            .foregroundStyle(Color.accent)
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
        TextLink("Check now", glyph: "›") {}
    }
}
#endif
