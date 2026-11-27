import SwiftUI

/// The header of a tab's list (screen 3): its title, one round action and
/// the search field, on the card surface above a hairline. Shared by Chats
/// and Contacts so the two tabs read as one app.
struct ListHeader: View {
    let title: LocalizedStringKey
    let symbol: String
    let actionLabel: LocalizedStringKey
    @Binding var query: String
    let action: () -> Void

    var body: some View {
        VStack(spacing: 12) {
            HStack {
                Text(title).font(BarkingFont.mono(.largeTitle, size: 30, weight: .semibold))
                    .tracking(-0.5).foregroundStyle(Color.fg)
                    .accessibilityAddTraits(.isHeader)
                Spacer()
                Button(action: action) {
                    Image(systemName: symbol).font(.bSymbol(18, maximum: 26))
                        .foregroundStyle(Color.accent)
                        .frame(width: 44, height: 44)
                        .background(Color.wash, in: .circle)
                }
                .accessibilityLabel(Text(actionLabel))
            }
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(Color.fgSoft).accessibilityHidden(true)
                TextField(text: $query, prompt: Text("Search").foregroundStyle(Color.fgSoft)) { Text("Search") }
                    .font(.bBody).foregroundStyle(Color.fg)
                    .submitLabel(.search)
            }
            .padding(.horizontal, 12)
            .frame(height: 40)
            .background(Color.field, in: .rect(cornerRadius: 10))
        }
        .padding(.horizontal, 20)
        .padding(.top, 8)
        .padding(.bottom, 12)
        .background(Color.surfaceCard)
        .overlay(alignment: .bottom) { Rectangle().fill(Color.border).frame(height: 1) }
    }
}

/// A list's empty state: what is missing, one sentence on what to do, one
/// action. Centred in the space the list leaves.
struct ListEmptyState: View {
    let title: LocalizedStringKey
    let message: LocalizedStringKey
    let action: LocalizedStringKey
    let perform: () -> Void

    var body: some View {
        VStack(spacing: 8) {
            Text(title).font(BarkingFont.mono(.headline, size: 16, weight: .semibold))
                .foregroundStyle(Color.fg)
                .accessibilityAddTraits(.isHeader)
            Text(message).font(.bBodySmall).foregroundStyle(Color.fgMuted)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            PrimaryButton(action, action: perform).padding(.top, 8)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 40)
    }
}
