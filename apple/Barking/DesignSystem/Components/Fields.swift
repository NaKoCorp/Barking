import SwiftUI
import UIKit

/// What a text field shows right now. An error wins over focus: the ring
/// turns `danger` and the line under the field says why in words.
enum FieldState: Equatable {
    case idle, focused, error

    init(focused: Bool, hasError: Bool) {
        self = hasError ? .error : (focused ? .focused : .idle)
    }
}

/// Colour tokens of a text field (asset names): a `field` slot, `fg` text,
/// an `fgSoft` prompt, and a 1.5 pt ring when focused or wrong.
struct FieldTokens: Equatable {
    let fill: String
    let text: String
    let prompt: String
    let border: String?
    let borderWidth: CGFloat

    static func of(_ state: FieldState) -> FieldTokens {
        switch state {
        case .idle: .init(fill: "field", text: "fg", prompt: "fgSoft", border: nil, borderWidth: 0)
        case .focused: .init(fill: "field", text: "fg", prompt: "fgSoft", border: "focusRing", borderWidth: 1.5)
        case .error: .init(fill: "field", text: "fg", prompt: "fgSoft", border: "danger", borderWidth: 1.5)
        }
    }
}

/// What VoiceOver hears as the field's hint: the error when there is one
/// (the ring alone is colour), else the footer.
enum FieldHint: Equatable {
    case error, footer, none

    static func of(hasError: Bool, hasFooter: Bool) -> FieldHint {
        hasError ? .error : (hasFooter ? .footer : .none)
    }
}

extension View {
    /// Sets the identifier only when there is one: an empty identifier
    /// would replace SwiftUI's own and make empty-id queries ambiguous.
    @ViewBuilder func accessibilityIdentifier(ifPresent id: String?) -> some View {
        if let id, !id.isEmpty { accessibilityIdentifier(id) } else { self }
    }
}

/// A trailing button inside a field, 44 pt.
enum FieldAction {
    /// Replaces the text with the pasteboard's.
    case paste
    /// Copies the text (for a secure field, on this iPhone only, for 2 min).
    case copy
    /// Shows or hides a secure field's text.
    case reveal
}

/// A copied secret (a PDF password) stays on this iPhone, out of Universal
/// Clipboard, and leaves the pasteboard after two minutes.
enum SecretPasteboard {
    static let lifetime: TimeInterval = 120

    static func options(now: Date = .now) -> [UIPasteboard.OptionsKey: Any] {
        [.localOnly: true, .expirationDate: now.addingTimeInterval(lifetime)]
    }

    static func copy(_ secret: String) {
        UIPasteboard.general.setItems([[UIPasteboard.typeAutomatic: secret]], options: options())
    }
}

/// The one text field of the app (UI review §4): a visible Fira label above
/// a 48 pt `field` slot (radius 10, focus ring 1.5 pt `focusRing`), then a
/// footer or an error line. The label is the field's VoiceOver label.
struct BarkingTextField: View {
    let label: LocalizedStringKey
    @Binding var text: String
    var prompt: LocalizedStringKey?
    var footer: LocalizedStringKey?
    var error: LocalizedStringKey?
    var secure = false
    var trailing: FieldAction?
    var identifier: String?
    var onSubmit: () -> Void = {}

    /// Which of the two inputs has the keyboard: a secure field keeps both
    /// a hidden and a plain input, so revealing never drops the focus.
    private enum Slot: Hashable { case secure, plain }
    @FocusState private var focus: Slot?
    @State private var revealed = false
    @State private var copied = false

    init(_ label: LocalizedStringKey, text: Binding<String>, prompt: LocalizedStringKey? = nil,
         footer: LocalizedStringKey? = nil, error: LocalizedStringKey? = nil, secure: Bool = false,
         trailing: FieldAction? = nil, identifier: String? = nil, onSubmit: @escaping () -> Void = {}) {
        self.label = label
        _text = text
        self.prompt = prompt
        self.footer = footer
        self.error = error
        self.secure = secure
        self.trailing = trailing
        self.identifier = identifier
        self.onSubmit = onSubmit
    }

    var body: some View {
        let t = FieldTokens.of(FieldState(focused: focus != nil, hasError: error != nil))
        let shape = RoundedRectangle(cornerRadius: Radius.field)
        VStack(alignment: .leading, spacing: Space.s2) {
            Text(label)
                .font(.bSectionLabel).foregroundStyle(Color.fgMuted)
                // The field itself carries the label for VoiceOver.
                .accessibilityHidden(true)
            HStack(spacing: 0) {
                input(t)
                    .font(.bBodyLarge)
                    .foregroundStyle(Color(t.text))
                    .onSubmit(onSubmit)
                    .padding(.horizontal, Space.s3)
                    .padding(.vertical, Space.s2)
                    .frame(maxWidth: .infinity, minHeight: 48, alignment: .leading)
                if let trailing { action(trailing) }
            }
            .background(Color(t.fill), in: shape)
            .overlay { if let b = t.border { shape.strokeBorder(Color(b), lineWidth: t.borderWidth) } }
            .contentShape(shape)
            .onTapGesture { focus = visibleSlot }
            if let error {
                HStack(alignment: .firstTextBaseline, spacing: Space.s1) {
                    Text(verbatim: "✗").font(.bSymbol(13, relativeTo: .footnote)).accessibilityHidden(true)
                    Text(error).font(BarkingFont.sans(.footnote, size: 13))
                        .fixedSize(horizontal: false, vertical: true)
                }
                .foregroundStyle(Color.danger)
                // The field's hint says it: read once, on the field.
                .accessibilityHidden(true)
            } else if let footer {
                Text(footer)
                    .font(BarkingFont.sans(.footnote, size: 13)).foregroundStyle(Color.fgMuted)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityHidden(true)
            }
        }
    }

    private var visibleSlot: Slot { secure && !revealed ? .secure : .plain }

    /// The error (or the footer) is also the field's hint, so VoiceOver
    /// says it without leaving the field.
    private var hint: Text {
        switch FieldHint.of(hasError: error != nil, hasFooter: footer != nil) {
        case .error: error.map { Text($0) } ?? Text(verbatim: "")
        case .footer: footer.map { Text($0) } ?? Text(verbatim: "")
        case .none: Text(verbatim: "")
        }
    }

    /// A secure field draws both inputs on top of each other and shows one,
    /// so the eye swaps them without closing the keyboard.
    @ViewBuilder private func input(_ t: FieldTokens) -> some View {
        // No prompt: an empty one, so the label is not repeated inside the slot.
        let promptText = prompt.map { Text($0).foregroundStyle(Color.fgSoft) } ?? Text(verbatim: "")
        if secure {
            ZStack(alignment: .leading) {
                SecureField(text: $text, prompt: promptText) { Text(label) }
                    .focused($focus, equals: .secure)
                    .modifier(Shown(on: !revealed, identifier: identifier, hint: hint))
                TextField(text: $text, prompt: promptText) { Text(label) }
                    .focused($focus, equals: .plain)
                    .modifier(Shown(on: revealed, identifier: identifier, hint: hint))
            }
        } else {
            TextField(text: $text, prompt: promptText) { Text(label) }
                .focused($focus, equals: .plain)
                .accessibilityHint(hint)
                .accessibilityIdentifier(ifPresent: identifier)
        }
    }

    /// One of the two stacked inputs: the hidden one takes no taps and is
    /// not read by VoiceOver.
    private struct Shown: ViewModifier {
        let on: Bool
        let identifier: String?
        let hint: Text

        func body(content: Content) -> some View {
            content
                .opacity(on ? 1 : 0)
                .allowsHitTesting(on)
                .accessibilityHidden(!on)
                .accessibilityHint(hint)
                .accessibilityIdentifier(ifPresent: on ? identifier : nil)
        }
    }

    private func action(_ a: FieldAction) -> some View {
        Button {
            switch a {
            case .paste: if let s = UIPasteboard.general.string { text = s }
            case .copy:
                if secure { SecretPasteboard.copy(text) } else { UIPasteboard.general.string = text }
                copied = true
            case .reveal:
                let typing = focus != nil
                revealed.toggle()
                // Keep the keyboard: move the focus to the input now shown.
                if typing { focus = visibleSlot }
            }
        } label: {
            Group {
                switch a {
                case .paste: Image(systemName: "doc.on.clipboard")
                case .copy: Image(systemName: copied ? "checkmark" : "doc.on.doc")
                case .reveal: Image(systemName: revealed ? "eye.slash" : "eye")
                }
            }
            .font(.bSymbol(15, relativeTo: .body, maximum: 24))
            .foregroundStyle(Color.accent)
            .frame(width: 44, height: 44)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .accessibilityLabel(actionLabel(a))
    }

    private func actionLabel(_ a: FieldAction) -> Text {
        switch a {
        case .paste: Text("Paste")
        case .copy: copied ? Text("Copied") : Text("Copy")
        case .reveal: revealed ? Text("Hide") : Text("Show")
        }
    }
}

/// Sizes of the segmented control: labels never truncate, so at the
/// accessibility text sizes the segments become a menu.
enum SegmentedMetrics {
    static func usesMenu(_ size: DynamicTypeSize) -> Bool { size.isAccessibilitySize }
}

/// The one segmented control of the app (Appearance, the journal filter,
/// Add a contact): a `field` track (radius 10), a `segment` thumb with a
/// 1 px `borderStrong` edge (a ground, not purple), Fira 13, 44 pt. At AX
/// sizes it is a menu instead.
struct BarkingSegmented<T: Hashable>: View {
    let label: LocalizedStringKey
    @Binding var selection: T
    let options: [(value: T, title: LocalizedStringKey)]
    var identifier: String?
    var optionID: ((T) -> String)?
    /// Shows `label` above the menu at AX sizes, where no section label of
    /// the screen names the control (Add a contact).
    var labelAtAXSizes = false
    @Environment(\.dynamicTypeSize) private var size

    init(_ label: LocalizedStringKey, selection: Binding<T>, options: [(T, LocalizedStringKey)],
         identifier: String? = nil, optionID: ((T) -> String)? = nil, labelAtAXSizes: Bool = false) {
        self.label = label
        _selection = selection
        self.options = options.map { (value: $0.0, title: $0.1) }
        self.identifier = identifier
        self.optionID = optionID
        self.labelAtAXSizes = labelAtAXSizes
    }

    var body: some View {
        if SegmentedMetrics.usesMenu(size) {
            VStack(alignment: .leading, spacing: Space.s2) {
                if labelAtAXSizes { SectionLabel(label) }
                menu
            }
        } else {
            HStack(spacing: Space.s1) {
                ForEach(options, id: \.value) { o in segment(o.value, o.title) }
            }
            .padding(Space.s1)
            .background(Color.field, in: .rect(cornerRadius: Radius.field))
            .accessibilityElement(children: .contain)
            .accessibilityLabel(Text(label))
            .accessibilityIdentifier(ifPresent: identifier)
        }
    }

    /// A menu with its own label, flush with the screen's leading edge (the
    /// system menu picker adds an inset and can hyphenate its value). Each
    /// option keeps its identifier and says which one is chosen.
    private var menu: some View {
        Menu {
            ForEach(options, id: \.value) { o in
                Button { selection = o.value } label: {
                    if o.value == selection { Label(o.title, systemImage: "checkmark") } else { Text(o.title) }
                }
                .accessibilityAddTraits(o.value == selection ? .isSelected : [])
                .accessibilityIdentifier(ifPresent: optionID?(o.value))
            }
        } label: {
            HStack(spacing: Space.s1) {
                Text(options.first { $0.value == selection }?.title ?? label).font(.bBody)
                    .fixedSize(horizontal: false, vertical: true)
                Image(systemName: "chevron.up.chevron.down")
                    .font(.bSymbol(12, relativeTo: .footnote, weight: .semibold, maximum: 20))
            }
            .foregroundStyle(Color.accent)
            .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
            .contentShape(.rect)
        }
        .accessibilityLabel(Text(label))
        .accessibilityValue(options.first { $0.value == selection }.map { Text($0.title) } ?? Text(verbatim: ""))
        .accessibilityIdentifier(ifPresent: identifier)
    }

    private func segment(_ value: T, _ title: LocalizedStringKey) -> some View {
        let on = selection == value
        let thumb = RoundedRectangle(cornerRadius: Radius.button)
        return Button { selection = value } label: {
            Text(title)
                .font(BarkingFont.mono(.footnote, size: 13, weight: on ? .semibold : .regular))
                .foregroundStyle(on ? Color.fg : Color.fgMuted)
                .multilineTextAlignment(.center)
                .lineLimit(2)
                .padding(.horizontal, Space.s1)
                .frame(maxWidth: .infinity, minHeight: 44)
                .background(on ? Color.segment : Color.clear, in: thumb)
                .overlay { if on { thumb.strokeBorder(Color.borderStrong, lineWidth: 1) } }
                .contentShape(thumb)
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(on ? .isSelected : [])
        .accessibilityIdentifier(ifPresent: optionID?(value))
    }
}

#if DEBUG
#Preview("Fields") {
    @Previewable @State var name = "Alice"
    @Previewable @State var empty = ""
    @Previewable @State var pick = 0
    PreviewMatrix {
        BarkingTextField("Your name", text: $name,
                         footer: "Your name travels in your contact card. No phone number, no email.")
        BarkingTextField("Password", text: $empty, error: "At least 12 characters.", secure: true, trailing: .reveal)
        BarkingSegmented("Appearance", selection: $pick, options: [(0, "System"), (1, "Light"), (2, "Dark")])
    }
}
#endif
