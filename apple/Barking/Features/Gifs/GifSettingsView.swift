import BarkingKit
import SwiftUI

/// Settings › GIFs (spec GIF §9.3). Turning on goes through the warning
/// sheet only: the switch flips after "Use GIFs". Turning off is immediate.
struct GifSettingsView: View {
    let core: CoreService
    let model: GifSettingsModel
    @State private var showsWarning = false

    var body: some View {
        let name = model.provider.name
        Group {
            VStack(alignment: .leading, spacing: Space.s2) {
                FormCard {
                    Toggle(isOn: Binding(get: { model.enabled }, set: { on in
                        if on { showsWarning = true } else { Task { await model.disable() } }
                    })) {
                        Text("Use GIFs from \(name)").font(.bBody.weight(.semibold)).foregroundStyle(Color.fg)
                    }
                    .tint(Color.toggleOn)
                    .padding(.horizontal, FormRowMetrics.inset)
                    .frame(minHeight: FormRowMetrics.minHeight(hasSubtitle: false))
                    .accessibilityIdentifier("gifs.use")
                    .accessibilityHint(Text("Off, Barking never contacts \(name)"))
                }
                note("Off, Barking never contacts \(name)").accessibilityHidden(true)
                if model.enabled, let from = model.enabledFrom {
                    note(origin(from)).accessibilityIdentifier("gifs.origin")
                }
            }
            if model.enabled {
                VStack(alignment: .leading, spacing: Space.s2) {
                    FormCard {
                        Toggle(isOn: Binding(get: { model.autoLoad },
                                             set: { on in Task { await model.setAutoLoad(on) } })) {
                            Text("Play GIFs automatically").font(.bBody.weight(.semibold)).foregroundStyle(Color.fg)
                        }
                        .tint(Color.toggleOn)
                        .padding(.horizontal, FormRowMetrics.inset)
                        .frame(minHeight: FormRowMetrics.minHeight(hasSubtitle: false))
                        .accessibilityIdentifier("gifs.autoLoad")
                        .accessibilityHint(Text("Each GIF shown is requested from \(name) from your address. Off, you choose GIF by GIF"))
                    }
                    note("Each GIF shown is requested from \(name) from your address. Off, you choose GIF by GIF")
                        .accessibilityHidden(true)
                }
            }
            if model.saveFailed {
                Banner(kind: .danger, title: "Not saved. Try again.")
            }
            VStack(alignment: .leading, spacing: Space.s2) {
                NavigationLink { TransparencyView(core: core) } label: {
                    Text("See what was sent in Transparency ›").font(.bBody.weight(.semibold))
                        .foregroundStyle(Color.accent)
                        .frame(minHeight: 44, alignment: .leading)
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("gifs.transparency")
                note("These settings apply to all your linked devices")
            }
        }
        .barkingScreen()
        .navigationTitle(Text("GIFs"))
        .task { await model.load() }
        .sheet(isPresented: $showsWarning) {
            GifWarningSheet(provider: model.provider, linkedDevices: model.linkedDevices, updated: model.updated) {
                Task { try? await model.enable() }
            }
        }
    }

    /// "Turned on from iPhone · 27 Nov".
    private func origin(_ device: String) -> LocalizedStringKey {
        let who = device == "another device" ? String(localized: "another device") : device
        let day = model.enabledAt?.formatted(.dateTime.day().month(.abbreviated)) ?? ""
        return "Turned on from \(who) · \(day)"
    }

    private func note(_ text: LocalizedStringKey) -> some View {
        Text(text).font(BarkingFont.sans(.footnote, size: 13)).foregroundStyle(Color.fgMuted)
            .fixedSize(horizontal: false, vertical: true)
    }
}
