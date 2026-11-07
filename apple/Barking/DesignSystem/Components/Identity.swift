import SwiftUI

/// One way to write a fingerprint everywhere (UI review U-17): groups of 4,
/// a space between groups and a `·` every 2 groups, `zab2 2ccf · kzfa fsms`.
/// The short form is the first 4 groups. A no-break space before each `·`
/// keeps a line from starting with it, so a full fingerprint wraps on group
/// boundaries only.
enum FingerprintFormat {
    static func groups(_ fingerprint: String) -> [String] {
        let parts = fingerprint.lowercased()
            .split(whereSeparator: { !($0.isLetter || $0.isNumber) }).map(String.init)
        guard parts.count == 1, let one = parts.first, one.count > 4 else { return parts }
        return stride(from: 0, to: one.count, by: 4).map { i in
            let start = one.index(one.startIndex, offsetBy: i)
            return String(one[start..<(one.index(start, offsetBy: 4, limitedBy: one.endIndex) ?? one.endIndex)])
        }
    }

    /// The groups the form shows, or nil when the text is too short for it
    /// (it is then shown as it is, never padded).
    private static func shown(_ fingerprint: String, form: FingerprintText.Form) -> [String]? {
        let g = groups(fingerprint)
        switch form {
        case .short: return g.count >= 4 ? Array(g.prefix(4)) : nil
        case .full: return g
        }
    }

    static func grouped(_ fingerprint: String, form: FingerprintText.Form) -> String {
        guard let g = shown(fingerprint, form: form) else { return fingerprint }
        return g.enumerated().map { i, group in
            i == 0 ? group : (i % 2 == 0 ? "\u{00A0}· " : " ") + group
        }.joined()
    }

    /// What VoiceOver reads: one group at a time, character by character.
    static func spoken(_ fingerprint: String, form: FingerprintText.Form) -> String {
        let g = shown(fingerprint, form: form) ?? groups(fingerprint)
        return g.map { $0.map(String.init).joined(separator: " ") }.joined(separator: ", ")
    }
}

/// A fingerprint in Fira Code, grouped by `FingerprintFormat`.
struct FingerprintText: View {
    enum Form { case short, full }

    let fingerprint: String
    let form: Form

    init(_ fingerprint: String, form: Form = .short) {
        self.fingerprint = fingerprint
        self.form = form
    }

    var body: some View {
        Text(verbatim: FingerprintFormat.grouped(fingerprint, form: form))
            .font(BarkingFont.mono(.footnote, size: 13))
            .foregroundStyle(Color.fg)
            .fixedSize(horizontal: false, vertical: true)
            .textSelection(.enabled)
            .accessibilityLabel(Text(verbatim: FingerprintFormat.spoken(fingerprint, form: form)))
    }
}

#if DEBUG
#Preview("Fingerprint") {
    PreviewMatrix {
        FingerprintText("zab2-2ccf-kzfa-fsms-q7ws-a2bd-3k1x-pp0e")
        FingerprintText("zab2-2ccf-kzfa-fsms-q7ws-a2bd-3k1x-pp0e-77aa-bb3c-x9x9-k2k2", form: .full)
    }
}
#endif
