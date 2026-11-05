import SwiftUI

/// Primary action: purple fill, white Fira Code 600, 52 pt.
struct PrimaryButton: View {
    let title: LocalizedStringKey
    var enabled = true
    let action: () -> Void

    init(_ title: LocalizedStringKey, enabled: Bool = true, action: @escaping () -> Void) {
        self.title = title
        self.enabled = enabled
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(BarkingFont.mono(.body, size: 15, weight: .semibold))
                .frame(maxWidth: .infinity, minHeight: 52)
                .foregroundStyle(.white)
                .background(Color.accentFill.opacity(enabled ? 1 : 0.4), in: .rect(cornerRadius: Radius.button))
        }
        .disabled(!enabled)
    }
}

/// Secondary action: 1 px outline, 52 pt.
struct SecondaryButton: View {
    let title: LocalizedStringKey
    let action: () -> Void

    init(_ title: LocalizedStringKey, action: @escaping () -> Void) {
        self.title = title
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(BarkingFont.mono(.body, size: 15, weight: .semibold))
                .frame(maxWidth: .infinity, minHeight: 52)
                .foregroundStyle(Color.fg)
                .overlay(RoundedRectangle(cornerRadius: Radius.button).stroke(Color.borderStrong, lineWidth: 1))
        }
    }
}
