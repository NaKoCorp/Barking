import BarkingKit
import SafariServices
import SwiftUI

/// The GIF warning (spec GIF §9.2): what the provider receives, before
/// anything reaches it. The only path to turning GIFs on. "Not now" is the
/// highlighted choice; it and a swipe down close the sheet without turning
/// anything on. `onUse` runs after "Use GIFs", then the sheet closes.
struct GifWarningSheet: View {
    /// The active provider (`gifProvider()`): its name and privacy link.
    let provider: GifProviderInfo
    /// My other devices: the consent applies to them too. No line at 0.
    let linkedDevices: Int
    /// The warning changed since the version accepted: "Updated" under the title.
    let updated: Bool
    let onUse: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var showsPolicy = false

    var body: some View {
        let name = provider.name
        ScrollView {
            VStack(alignment: .leading, spacing: Space.s3) {
                VStack(alignment: .leading, spacing: Space.s2) {
                    ScreenTitle("Use GIFs from \(name)?", size: 22)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityIdentifier("gifWarning")
                    if updated {
                        Tag("Updated", style: .accent).accessibilityIdentifier("gifWarning.updated")
                    }
                }
                paragraph("To search and show GIFs, this phone connects directly to \(name), a US company. \(name) will receive:")
                VStack(alignment: .leading, spacing: Space.s1) {
                    bullet("your IP address, which reveals your approximate location")
                    bullet("your GIF searches")
                    bullet("which GIFs you send and show, and when")
                }
                paragraph("By matching GIF requests, \(name) can work out who you exchange GIFs with. Your messages and contacts stay encrypted and are never sent to \(name). Barking doesn't control what \(name) does with this data.")
                VStack(alignment: .leading, spacing: Space.s1) {
                    if linkedDevices > 0 {
                        paragraph("Applies to your \(linkedDevices) linked devices.")
                    }
                    paragraph("You can turn it off anytime in Settings › GIFs.")
                }
                if let url = URL(string: provider.privacyUrl), url.scheme == "https" {
                    Button { showsPolicy = true } label: {
                        Text("\(name) privacy policy ›").font(.bBody.weight(.semibold)).foregroundStyle(Color.accent)
                            .frame(minHeight: 44, alignment: .leading)
                    }
                    .buttonStyle(.plain)
                    .accessibilityIdentifier("gifWarning.privacy")
                    .sheet(isPresented: $showsPolicy) { SafariView(url: url).ignoresSafeArea() }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, Space.gutter)
            .padding(.top, Space.s4)
            .padding(.bottom, Space.s3)
        }
        .background(Color.surface)
        .ctaBar {
            PrimaryButton("Not now", identifier: "gifWarning.notNow") { dismiss() }
            SecondaryButton("Use GIFs") {
                onUse()
                dismiss()
            }
            .accessibilityIdentifier("gifWarning.use")
        }
        .presentationDetents([.medium, .large])
        .presentationBackground(Color.surface)
    }

    private func paragraph(_ text: LocalizedStringKey) -> some View {
        Text(text).font(.bBody).foregroundStyle(Color.fg)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func bullet(_ text: LocalizedStringKey) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: Space.s2) {
            Text(verbatim: "•").font(.bBody).foregroundStyle(Color.fgMuted).accessibilityHidden(true)
            paragraph(text)
        }
    }
}

/// The provider's page in the in-app browser (`SFSafariViewController`).
private struct SafariView: UIViewControllerRepresentable {
    let url: URL

    func makeUIViewController(context: Context) -> SFSafariViewController { SFSafariViewController(url: url) }
    func updateUIViewController(_ controller: SFSafariViewController, context: Context) {}
}

#Preview("Warning") {
    Color.surface.sheet(isPresented: .constant(true)) {
        GifWarningSheet(provider: GifProviderInfo(id: 1, name: "Klipy", warningVersion: 1,
                                                  privacyUrl: "https://klipy.com/support/privacy-policy"),
                        linkedDevices: 2, updated: true, onUse: {})
    }
}
