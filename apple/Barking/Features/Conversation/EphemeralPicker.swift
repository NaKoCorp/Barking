import SwiftUI

/// How long a message lasts once sent, chosen in the composer (spec iOS
/// deletion/ephemeral §5.5). The core owns the bounds; this keeps the picker
/// inside them so a send never refuses.
struct EphemeralDelay: Equatable {
    let seconds: UInt32

    static let minSeconds: UInt32 = 60
    static let maxSeconds: UInt32 = 604_800

    static let presets: [EphemeralDelay] = [300, 3_600, 86_400, 604_800].map { EphemeralDelay(seconds: $0) }

    /// nil below 1 minute, above 7 days, or with a negative part.
    static func custom(days: Int, hours: Int, minutes: Int) -> EphemeralDelay? {
        guard days >= 0, hours >= 0, minutes >= 0 else { return nil }
        let total = days * 86_400 + hours * 3_600 + minutes * 60
        guard total >= Int(minSeconds), total <= Int(maxSeconds) else { return nil }
        return EphemeralDelay(seconds: UInt32(total))
    }

    private var parts: (days: Int, hours: Int, minutes: Int) {
        let s = Int(seconds)
        return (s / 86_400, s % 86_400 / 3_600, s % 3_600 / 60)
    }

    /// "5 min", "1 h", "1 d", "1 d 2 h 3 min": the hourglass button's text.
    var shortLabel: String { shortLabel(bundle: .main, locale: .current) }

    func shortLabel(bundle: Bundle, locale: Locale) -> String {
        let p = parts
        var out: [String] = []
        if p.days > 0 { out.append(String(localized: "\(p.days) d", bundle: bundle, locale: locale)) }
        if p.hours > 0 { out.append(String(localized: "\(p.hours) h", bundle: bundle, locale: locale)) }
        if p.minutes > 0 { out.append(String(localized: "\(p.minutes) min", bundle: bundle, locale: locale)) }
        return out.joined(separator: " ")
    }

    /// "5 min", "1 hour", "2 days": the banner's sentence, with plurals.
    var longLabel: String { longLabel(bundle: .main, locale: .current) }

    func longLabel(bundle: Bundle, locale: Locale) -> String {
        let p = parts
        var out: [String] = []
        if p.days > 0 { out.append(String(localized: "\(p.days) days", bundle: bundle, locale: locale)) }
        if p.hours > 0 { out.append(String(localized: "\(p.hours) hours", bundle: bundle, locale: locale)) }
        if p.minutes > 0 { out.append(String(localized: "\(p.minutes) min", bundle: bundle, locale: locale)) }
        return out.joined(separator: " ")
    }
}

/// The hourglass's menu: no delay, the four shortcuts, and "Custom…".
struct EphemeralMenu: View {
    @Bindable var model: ConversationModel
    @Environment(\.locale) private var locale
    @State private var customizing = false

    private static let titles: [UInt32: LocalizedStringKey] = [
        300: "5 min", 3_600: "1 hour", 86_400: "1 day", 604_800: "1 week",
    ]

    private var isCustom: Bool {
        model.ttl.map { ttl in !EphemeralDelay.presets.contains { $0.seconds == ttl } } ?? false
    }

    var body: some View {
        Menu {
            choice("No delay", selected: model.ttl == nil) { model.ttl = nil }
            ForEach(EphemeralDelay.presets, id: \.seconds) { delay in
                choice(Self.titles[delay.seconds] ?? "", selected: model.ttl == delay.seconds) {
                    model.ttl = delay.seconds
                }
            }
            choice("Custom…", selected: isCustom) { customizing = true }
        } label: {
            label
        }
        .accessibilityLabel(Text("Disappearing delay"))
        .accessibilityValue(Text(verbatim: model.ttl.map {
            EphemeralDelay(seconds: $0).longLabel(bundle: .strings(for: locale), locale: locale)
        } ?? String(localized: "No delay", bundle: .strings(for: locale), locale: locale)))
        .accessibilityIdentifier("composer.delay")
        .sheet(isPresented: $customizing) {
            CustomDelaySheet(initial: model.ttl) { model.ttl = $0.seconds }
        }
    }

    private func choice(_ title: LocalizedStringKey, selected: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            if selected { Label(title, systemImage: "checkmark") } else { Text(title) }
        }
    }

    /// Tinted, with the short delay, once one is set.
    private var label: some View {
        let on = model.ttl != nil
        return HStack(spacing: 4) {
            Image(systemName: "hourglass").font(.bSymbol(17, weight: .semibold, maximum: 26))
            if let ttl = model.ttl {
                Text(verbatim: EphemeralDelay(seconds: ttl).shortLabel(bundle: .strings(for: locale), locale: locale))
                    .font(BarkingFont.sans(.footnote, size: 13, weight: .semibold))
                    .lineLimit(1)
            }
        }
        .foregroundStyle(on ? Color.accent : Color.fgMuted)
        .padding(.horizontal, on ? 10 : 0)
        .frame(minWidth: 44, minHeight: 44)
        .background(on ? Color.surfaceAlt : Color.clear, in: .capsule)
        .contentShape(.rect)
    }
}

/// Days 0 to 7, hours, minutes. "Set" stays off while the total is under a
/// minute or over seven days.
struct CustomDelaySheet: View {
    let set: (EphemeralDelay) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var days: Int
    @State private var hours: Int
    @State private var minutes: Int

    init(initial: UInt32?, set: @escaping (EphemeralDelay) -> Void) {
        self.set = set
        let s = Int(initial ?? 3_600)
        _days = State(initialValue: min(s / 86_400, 7))
        _hours = State(initialValue: s % 86_400 / 3_600)
        _minutes = State(initialValue: s % 3_600 / 60)
    }

    private var delay: EphemeralDelay? { .custom(days: days, hours: hours, minutes: minutes) }

    var body: some View {
        NavigationStack {
            HStack(spacing: 0) {
                wheel($days, range: 0...7, unit: "days")
                wheel($hours, range: 0...23, unit: "hours")
                wheel($minutes, range: 0...59, unit: "minutes")
            }
            .padding(.horizontal, Space.gutter)
            .frame(maxHeight: .infinity, alignment: .top)
            .background(Color.surface)
            .navigationTitle("Custom delay")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Set") {
                        if let delay { set(delay) }
                        dismiss()
                    }
                    .disabled(delay == nil)
                    .accessibilityIdentifier("composer.delay.set")
                }
            }
        }
        .presentationDetents([.height(320)])
        .presentationBackground(Color.surface)
    }

    private func wheel(_ value: Binding<Int>, range: ClosedRange<Int>, unit: LocalizedStringKey) -> some View {
        HStack(spacing: 2) {
            Picker(selection: value) {
                ForEach(range, id: \.self) { Text(verbatim: "\($0)").tag($0) }
            } label: { EmptyView() }
                .pickerStyle(.wheel)
            Text(unit).font(BarkingFont.sans(.footnote, size: 13)).foregroundStyle(Color.fgMuted)
        }
        .frame(maxWidth: .infinity)
    }
}
