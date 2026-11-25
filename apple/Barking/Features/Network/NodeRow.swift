import BarkingKit
import SwiftUI

/// Where a row of the Network screen leads (one `navigationDestination`
/// at the stack's root, so rows inside "Other known nodes" push too).
enum NetworkRoute: Hashable {
    case node(String)
    case others
    case blocked
}

/// One node of the "Internet relays" list (spec §7.1): country code, host,
/// reliability and latency; short id and address; verdict · wakes ·
/// subscriptions. No percentage. Opens the node (44 pt minimum, chevron),
/// reads as one VoiceOver element, keeps the share / QR menu.
struct NodeRow: View {
    let node: NodeInfo
    var showCode: (AppRouter.RelayLink) -> Void
    @Environment(\.locale) private var locale
    @Environment(\.dynamicTypeSize) private var typeSize
    @ScaledMetric(relativeTo: .footnote) private var countryWidth: CGFloat = 24

    var body: some View {
        let row = NodeLabels.Row(node, lang: .of(locale))
        NavigationLink(value: NetworkRoute.node(node.id)) {
            HStack(alignment: .center, spacing: Space.s3) {
                HStack(alignment: .firstTextBaseline, spacing: Space.s3) {
                    if !typeSize.isAccessibilitySize {
                        country(row).frame(width: countryWidth, alignment: .leading)
                    }
                    VStack(alignment: .leading, spacing: Space.s1) {
                        top(row)
                        if !row.idLine.isEmpty {
                            Text(verbatim: row.idLine).font(BarkingFont.mono(.caption2, size: 11))
                                .foregroundStyle(Color.fgSoft)
                        }
                        if row.verdict != nil || row.extras != nil { meta(row) }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                RowGlyph()
            }
            .padding(.vertical, Space.s3)
            .frame(minHeight: 44)
            .contentShape(.rect)
            // The link's one element reads this sentence, not the parts.
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text(verbatim: row.accessibilityLabel))
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("node.\(node.id)")
        .contextMenu {
            if !node.addr.isEmpty, let link = NetworkModel.relayLink(id: node.id, addr: node.addr) {
                ShareLink(item: link) { Label("Share this relay", systemImage: "square.and.arrow.up") }
                Button { showCode(AppRouter.RelayLink(id: node.id, addr: node.addr)) } label: {
                    Label("Show its QR code", systemImage: "qrcode")
                }
            }
        }
    }

    private func country(_ row: NodeLabels.Row) -> some View {
        Text(verbatim: row.country).font(BarkingFont.mono(.footnote, size: 13, weight: .semibold))
            .foregroundStyle(Color.fgMuted)
    }

    /// Host and state side by side when they fit, else one under the other
    /// (large text): nothing is cut.
    private func top(_ row: NodeLabels.Row) -> some View {
        let name = Text(verbatim: row.name).font(BarkingFont.mono(.subheadline, size: 14, weight: .semibold))
            .foregroundStyle(Color.fg)
        let status = StatusDot(row.status.state, verbatim: row.status.text)
        return ViewThatFits(in: .horizontal) {
            HStack(alignment: .firstTextBaseline, spacing: Space.s2) {
                if typeSize.isAccessibilitySize { country(row) }
                name.lineLimit(1)
                Spacer(minLength: Space.s2)
                status.fixedSize()
            }
            VStack(alignment: .leading, spacing: Space.s1) {
                if typeSize.isAccessibilitySize { country(row) }
                name.fixedSize(horizontal: false, vertical: true)
                status.fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// "✓ verified · wakes · 3 subscriptions": the verdict in its tone,
    /// the rest muted, as one wrapping text.
    private func meta(_ row: NodeLabels.Row) -> some View {
        var text = Text(verbatim: "")
        if let v = row.verdict {
            let tone = Color(v.state.token)
            text = text + Text(verbatim: "\(Self.verdictGlyph(v.state)) ")
                .font(.bSymbol(11, relativeTo: .caption, weight: .bold)).foregroundStyle(tone)
                + Text(verbatim: v.text).foregroundStyle(tone)
        }
        if let extras = row.extras {
            text = text + Text(verbatim: row.verdict == nil ? extras : " · \(extras)").foregroundStyle(Color.fgSoft)
        }
        return text.font(.bMeta).fixedSize(horizontal: false, vertical: true)
    }

    /// ✓ checked, ⚠ off (text presentation, never the emoji), ○ unknown.
    static func verdictGlyph(_ state: StatusDot.State) -> String {
        switch state {
        case .ok: "✓"
        case .waiting, .down: "\u{26A0}\u{FE0E}"
        case .checking: "○"
        }
    }
}

/// A row that opens a list: "Other known nodes (214)", "Blocked nodes (1)".
struct NodeListLink: View {
    let route: NetworkRoute
    let title: String
    let identifier: String

    var body: some View {
        NavigationLink(value: route) {
            HStack(spacing: Space.s2) {
                Text(verbatim: title).font(BarkingFont.mono(.subheadline, size: 14, weight: .semibold))
                    .foregroundStyle(Color.fg)
                    .multilineTextAlignment(.leading)
                    .frame(maxWidth: .infinity, alignment: .leading)
                RowGlyph()
            }
            .padding(.vertical, Space.s1)
            .frame(minHeight: 44)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier(identifier)
    }
}

/// The rest of the view (up to 2048 nodes), with the same rows.
struct OtherNodesView: View {
    let model: NetworkModel
    @State private var sharing: AppRouter.RelayLink?

    var body: some View {
        ScrollView {
            Card {
                LazyVStack(alignment: .leading, spacing: 0) {
                    if model.others.isEmpty {
                        Text("No other node known yet.").font(.bBody).foregroundStyle(Color.fgMuted)
                    }
                    ForEach(Array(model.others.enumerated()), id: \.element.id) { i, node in
                        if i > 0 { Rectangle().fill(Color.border).frame(height: 1) }
                        NodeRow(node: node) { sharing = $0 }
                    }
                }
            }
            .padding(.horizontal, Space.gutter)
            .padding(.vertical, Space.s4)
        }
        .contentMargins(.bottom, 96, for: .scrollContent)
        .background(Color.surface)
        .navigationTitle(Text("Other known nodes"))
        .navigationBarTitleDisplayMode(.inline)
        .sheet(item: $sharing) { r in RelayCodeSheet(relay: r) { sharing = nil } }
    }
}

/// A relay's link as a QR code (white ground in both themes).
struct RelayCodeSheet: View {
    let relay: AppRouter.RelayLink
    var close: () -> Void

    var body: some View {
        NavigationStack {
            VStack(spacing: Space.s4) {
                if let link = NetworkModel.relayLink(id: relay.id, addr: relay.addr),
                   let img = QRPayload.image(for: Data(link.absoluteString.utf8), scale: 6) {
                    Image(uiImage: img).interpolation(.none).resizable().scaledToFit()
                        .padding(12).background(Color.white, in: .rect(cornerRadius: Radius.card))
                        .frame(maxWidth: 320)
                        .accessibilityLabel(Text("Relay QR code. Another phone scans it to add this relay."))
                    Text(verbatim: relay.addr).font(BarkingFont.mono(.footnote, size: 13)).foregroundStyle(Color.fgMuted)
                    ShareLink(item: link) { Text("Share this relay") }.buttonStyle(.barkingPrimary)
                }
            }
            .padding(Space.gutter)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color.surface)
            .navigationTitle(Text("Relay"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close", action: close) } }
        }
        .presentationBackground(Color.surface)
    }
}
