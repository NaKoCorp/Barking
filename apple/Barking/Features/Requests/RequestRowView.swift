import BarkingKit
import SwiftUI

/// A contact request among the chats (design decision 1): the chat row's
/// frame, the declared name in quotes and an "Invitation" tag, then its
/// history. No time and no count: nothing of theirs is shown before it is
/// accepted.
struct RequestRowView: View {
    let request: ContactRequestInfo

    private var history: String {
        let line = RequestHistory.short(request, now: .now)
        guard request.pendingMessages > 0 else { return line }
        return line + " · " + RequestHistory.waiting(Int(request.pendingMessages))
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
                Text(verbatim: history).font(.bBodySmall).foregroundStyle(Color.fgMuted).lineLimit(1)
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
