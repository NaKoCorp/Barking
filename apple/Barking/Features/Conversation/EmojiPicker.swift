import SwiftUI
import UIKit

/// The "+" of the reaction row: a sheet holding one text field that opens on
/// the emoji keyboard. The first emoji typed is the pick; the sheet then
/// closes. Anything else typed is ignored.
struct EmojiPicker: View {
    let pick: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    /// The first grapheme of `text` that is an emoji (one scalar sequence the
    /// core accepts as one reaction), or nil. Letters, digits, `#` and `*`
    /// are not emoji here unless they form a keycap.
    static func firstEmoji(in text: String) -> String? {
        text.first { character in
            let scalars = character.unicodeScalars
            guard let first = scalars.first else { return false }
            if scalars.contains(where: { $0.value == 0x20E3 }) {
                return "0123456789#*".unicodeScalars.contains(first)
            }
            guard first.properties.isEmoji else { return false }
            return first.value > 0xFF || scalars.contains { $0.value == 0xFE0F }
        }.map(String.init)
    }

    var body: some View {
        NavigationStack {
            EmojiField { emoji in
                pick(emoji)
                dismiss()
            }
            .frame(height: 56)
            .padding(.horizontal, Space.gutter)
            .frame(maxHeight: .infinity, alignment: .top)
            .padding(.top, Space.s3)
            .background(Color.surface)
            .navigationTitle("More emoji")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } }
            }
        }
        .presentationDetents([.height(220)])
        .presentationBackground(Color.surface)
    }
}

/// A field that asks for the emoji keyboard and hands back the first emoji
/// typed, leaving itself empty.
private struct EmojiField: UIViewRepresentable {
    let pick: (String) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(pick: pick) }

    func makeUIView(context: Context) -> EmojiTextField {
        let field = EmojiTextField()
        field.delegate = context.coordinator
        field.textAlignment = .center
        field.font = .systemFont(ofSize: 34)
        field.tintColor = .clear
        field.attributedPlaceholder = NSAttributedString(
            string: "🙂", attributes: [.font: UIFont.systemFont(ofSize: 34)])
        field.accessibilityLabel = String(localized: "More emoji")
        DispatchQueue.main.async { field.becomeFirstResponder() }
        return field
    }

    func updateUIView(_ field: EmojiTextField, context: Context) {
        context.coordinator.pick = pick
    }

    final class Coordinator: NSObject, UITextFieldDelegate {
        var pick: (String) -> Void
        private var done = false

        init(pick: @escaping (String) -> Void) { self.pick = pick }

        func textField(_ textField: UITextField, shouldChangeCharactersIn range: NSRange,
                       replacementString string: String) -> Bool {
            if !done, let emoji = EmojiPicker.firstEmoji(in: string) {
                done = true
                pick(emoji)
            }
            return false
        }
    }
}

/// A text field whose keyboard is the emoji one, when the user has it.
final class EmojiTextField: UITextField {
    override var textInputMode: UITextInputMode? {
        UITextInputMode.activeInputModes.first { $0.primaryLanguage == "emoji" } ?? super.textInputMode
    }

    /// A context of its own: the system does not restore the last keyboard.
    override var textInputContextIdentifier: String? { "" }
}
