import BarkingKit
import SwiftUI

/// A contact request among the chats (design decision 1): the chat row's
/// frame, the declared name in quotes and an "Invitation" tag, then its
/// history. No time and no count: nothing of theirs is shown before it is
/// accepted.
struct RequestRowView: View {
    let request: ContactRequestInfo
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @Environment(\.locale) private var locale

    /// In the app's language, as the conversation's lines (`Bundle.strings`).
    private var history: String {
        let strings = Bundle.strings(for: locale)
        let line = RequestHistory.short(request, now: .now, bundle: strings, locale: locale)
        guard request.pendingMessages > 0 else { return line }
        return line + " · " + RequestHistory.waiting(Int(request.pendingMessages), bundle: strings, locale: locale)
    }

    var body: some View {
        HStack(spacing: Space.s3) {
            Avatar(name: request.initialName, fingerprint: request.fingerprint, size: 44)
            VStack(alignment: .leading, spacing: 2) {
                HStack(alignment: .firstTextBaseline, spacing: Space.s2) {
                    Text(verbatim: DeclaredName.quoted(request.displayName, fingerprint: request.fingerprint))
                        .font(BarkingFont.sans(.headline, size: 16, weight: .semibold))
                        .foregroundStyle(Color.fg).lineLimit(1)
                    Tag("Invitation", style: .neutral)
                    Spacer(minLength: 0)
                }
                // Up to two lines (three at accessibility sizes): cut to one,
                // "· 2 messages wai…" hides what the row is for (Ruling 10).
                Text(verbatim: history).font(.bBodySmall).foregroundStyle(Color.fgMuted)
                    .lineLimit(dynamicTypeSize.isAccessibilitySize ? 3 : 2)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(minHeight: 64)
    }
}

extension ContactRequestInfo {
    /// The name the avatar's initial comes from: the declared one, else the
    /// fingerprint's start, as in the quotes.
    var initialName: String {
        let name = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        return name.isEmpty ? String(fingerprint.prefix(8)) : name
    }
}
