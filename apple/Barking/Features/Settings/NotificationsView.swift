import BarkingKit
import SwiftUI

/// Settings › Notifications (spec §5.3): the instant wake-up switch and how
/// much a notification shows.
struct NotificationsView: View {
    @Environment(\.openURL) private var openURL
    @State private var model: NotificationsModel

    init(core: CoreService) {
        _model = State(initialValue: NotificationsModel(core: core))
    }

    private var switchEnabled: Bool { model.state == .on || model.state == .off }

    var body: some View {
        Group {
            VStack(alignment: .leading, spacing: Space.s2) {
                SectionLabel("Notifications")
                FormCard {
                    Toggle(isOn: Binding(get: { model.instant }, set: { on in Task { await model.setInstant(on) } })) {
                        Text("Instant notifications").font(.bBody.weight(.semibold)).foregroundStyle(Color.fg)
                    }
                    .tint(Color.toggleOn)
                    .disabled(!switchEnabled)
                    .padding(.horizontal, FormRowMetrics.inset)
                    .frame(minHeight: FormRowMetrics.minHeight(hasSubtitle: false))
                    .accessibilityIdentifier("notifications.instant")
                }
                stateNote
                action
            }
            if model.saveFailed {
                Banner(kind: .danger, title: "Not saved. Try again.")
            }
            VStack(alignment: .leading, spacing: Space.s2) {
                SectionLabel("Preview")
                FormCard {
                    choice("Name and text", .nameAndText, id: "notifications.preview.nameAndText")
                    choice("Name only", .nameOnly, id: "notifications.preview.nameOnly")
                    choice("“New message”", .generic, id: "notifications.preview.generic")
                }
                Text("With the app lock, always “New message”.")
                    .font(model.appLocked ? BarkingFont.sans(.footnote, size: 13).weight(.semibold)
                                          : BarkingFont.sans(.footnote, size: 13))
                    .foregroundStyle(model.appLocked ? Color.fg : Color.fgMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .barkingScreen()
        .navigationTitle(Text("Notifications"))
        .task { await model.load() }
    }

    /// The line under the switch: what it does, or why it is off the table.
    @ViewBuilder private var stateNote: some View {
        switch model.state {
        case .noRelay:
            note("No wake-up relay in this build")
        case .denied:
            note("Notifications are off in the iPhone's Settings")
        case .notAsked:
            note("A node asks the relay to wake this iPhone when a message arrives.")
        case .on, .off:
            note("A node asks the relay to wake this iPhone when a message arrives.")
            note("Off: messages arrive when you open the app or during an iOS refresh.")
        }
    }

    @ViewBuilder private var action: some View {
        switch model.state {
        case .notAsked:
            SecondaryButton("Allow notifications") { Task { await model.requestPermission() } }
        case .denied:
            SecondaryButton("Open iPhone Settings") {
                if let url = URL(string: UIApplication.openNotificationSettingsURLString) { openURL(url) }
            }
        default:
            EmptyView()
        }
    }

    private func note(_ text: LocalizedStringKey) -> some View {
        Text(text).font(BarkingFont.sans(.footnote, size: 13)).foregroundStyle(Color.fgMuted)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func choice(_ title: LocalizedStringKey, _ value: PushPreview, id: String) -> some View {
        Button { Task { await model.setPreview(value) } } label: {
            HStack(spacing: Space.s3) {
                Text(title).font(.bBody.weight(.semibold)).foregroundStyle(Color.fg)
                    .frame(maxWidth: .infinity, alignment: .leading)
                if model.preview == value {
                    Image(systemName: "checkmark").font(.bSymbol(14, relativeTo: .subheadline, weight: .semibold))
                        .foregroundStyle(Color.accent).accessibilityHidden(true)
                }
            }
            .padding(.horizontal, FormRowMetrics.inset)
            .frame(minHeight: FormRowMetrics.minHeight(hasSubtitle: false))
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(model.preview == value ? .isSelected : [])
        .accessibilityIdentifier(id)
    }
}
