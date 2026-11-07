import BarkingKit
import SwiftUI

/// Message path screen (screen 5 of the mockup, spec block 2b §4.2).
struct PathView: View {
    @State private var model: PathModel

    init(core: CoreService, messageId: Int64, contact: String, contactName: String) {
        _model = State(initialValue: PathModel(core: core, messageId: messageId, contact: contact,
                                               contactName: contactName))
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Space.s2) {
                quoteCard
                // 24 pt above a section label, 8 below (U-14).
                SectionLabel("How it got here").padding(.top, Space.section - Space.s2)
                PathStops(rows: model.rows, notRecorded: model.notRecorded)
                PrivacyBlock(contactName: model.contactName).padding(.top, Space.s3)
            }
            .padding(.horizontal, Space.gutter)
            .padding(.vertical, Space.s4)
        }
        .background(Color.surface)
        .navigationTitle(Text("Message path"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar(.hidden, for: .tabBar)
        .task { await model.load() }
    }

    private var quoteCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("“\(model.quote)”").font(BarkingFont.sans(.body, size: 15)).foregroundStyle(Color.fg)
                .lineSpacing(3).fixedSize(horizontal: false, vertical: true)
            // One tag per fact (U-18): a tag moves to the next row whole
            // instead of wrapping inside itself.
            FlowLayout {
                if let route = model.routeBadge { Tag(verbatim: route, style: .accent) }
                ForEach(model.times, id: \.self) { Tag(verbatim: $0) }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.surfaceCard, in: RoundedRectangle(cornerRadius: Radius.card))
        .overlay(RoundedRectangle(cornerRadius: Radius.card).stroke(Color.border, lineWidth: 1))
    }
}

/// The recorded stops of a message's way, or "Path not recorded". Shared
/// by the path screen and the message sheet of a received message.
struct PathStops: View {
    let rows: [PathRow]
    let notRecorded: Bool

    var body: some View {
        if notRecorded {
            Text("Path not recorded")
                .font(BarkingFont.sans(.body, size: 15)).foregroundStyle(Color.fgMuted)
                .accessibilityIdentifier("path.notRecorded")
        } else {
            VStack(spacing: 0) {
                ForEach(Array(rows.enumerated()), id: \.element.id) { i, row in
                    PathStop(row: row, more: i < rows.count - 1)
                }
            }
        }
    }
}

/// The terminal block (U-38): "// only you and Alice can read it" and the
/// protocols, `terminalBg` in both themes, with an `accent` edge on Ink so
/// it stays a block of its own.
struct PrivacyBlock: View {
    let contactName: String
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("// only you and \(contactName) can read it")
                .font(BarkingFont.mono(.caption, size: 12)).foregroundStyle(Color.terminalFg)
            FlowLayout {
                ForEach(["PQXDH", "Double Ratchet"], id: \.self) { chip(Text(verbatim: $0)) }
                chip(Text("hidden sender"))
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.terminalBg, in: RoundedRectangle(cornerRadius: Radius.card))
        .overlay {
            RoundedRectangle(cornerRadius: Radius.card)
                .strokeBorder(scheme == .dark ? Color.accent.opacity(0.3) : Color.border, lineWidth: 1)
        }
        .accessibilityElement(children: .combine)
    }

    private func chip(_ text: Text) -> some View {
        text.font(.bTag).foregroundStyle(Color.terminalFg)
            .padding(.horizontal, 8).padding(.vertical, 4)
            .overlay(RoundedRectangle(cornerRadius: Radius.tag).strokeBorder(Color.terminalFg.opacity(0.35), lineWidth: 1))
    }
}

/// One stop: a 32 pt circle, a dashed line to the next stop, its name, its
/// time line and what it could see.
private struct PathStop: View {
    /// The node disc grows with the text, up to 48 pt.
    @ScaledMetric(relativeTo: .subheadline) private var disc: CGFloat = 32
    let row: PathRow
    let more: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(spacing: 4) {
                Text(verbatim: glyph).font(.bSymbol(14, relativeTo: .subheadline, maximum: 21)).foregroundStyle(.white)
                    .frame(width: min(disc, 48), height: min(disc, 48)).background(color, in: .circle)
                    .accessibilityHidden(true)
                if more {
                    Line().stroke(Color.borderStrong, style: StrokeStyle(lineWidth: 2, dash: [4, 3]))
                        .frame(width: 2).frame(maxHeight: .infinity)
                        .accessibilityHidden(true)
                }
            }
            // The column follows the disc, so a 48 pt disc never overhangs it.
            .frame(width: min(disc, 48))
            VStack(alignment: .leading, spacing: 3) {
                Text(verbatim: row.title).font(BarkingFont.sans(.subheadline, size: 15, weight: .semibold))
                    .foregroundStyle(Color.fg)
                Text(verbatim: row.subtitle).font(BarkingFont.mono(.caption2, size: 11.5))
                    .foregroundStyle(Color.fgSoft)
                Text(seen)
                    .font(BarkingFont.sans(.footnote, size: 12.5)).foregroundStyle(Color.fgMuted)
                    .lineSpacing(2).fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 10).padding(.vertical, 8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.surfaceCard, in: RoundedRectangle(cornerRadius: Radius.tile))
                    .overlay(RoundedRectangle(cornerRadius: Radius.tile).stroke(Color.border, lineWidth: 1))
                    .padding(.top, 6)
            }
            .padding(.top, 4)
        }
        .padding(.bottom, 12)
        // One sentence (U-36): "iPhone, wrote and encrypted, 11:58. Could see: …".
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: row.spoken))
        .accessibilityAddTraits(.isStaticText)
    }

    /// "Could see:" in the accent color, then what this stop saw.
    private var seen: AttributedString {
        var label = AttributedString(String(localized: "Could see:"))
        label.font = BarkingFont.sans(.footnote, size: 12.5, weight: .semibold)
        label.foregroundColor = Color.accent
        return label + AttributedString(" " + row.saw)
    }

    private var glyph: String {
        switch row.glyph {
        case .sender: "✎"
        case .relay: "≋"
        case .recipient: "✓"
        case .ownDevices: "⇄"
        }
    }

    /// Named colorsets: white glyphs read on them in both themes.
    private var color: Color { Color(PathStopColor.name(for: row.glyph)) }
}

/// Asset names of the path discs.
enum PathStopColor {
    static let sender = "pathSender"
    /// The internet transport color (the amber is gone).
    static let relay = "transportNet"
    static let recipient = "pathRecipient"
    static let ownDevices = "pathOwnDevices"

    static func name(for glyph: PathRow.Glyph) -> String {
        switch glyph {
        case .sender: sender
        case .relay: relay
        case .recipient: recipient
        case .ownDevices: ownDevices
        }
    }
}

/// A vertical line, for the dashed connector between stops.
private struct Line: Shape {
    func path(in rect: CGRect) -> Path {
        var p = Path()
        p.move(to: CGPoint(x: rect.midX, y: rect.minY))
        p.addLine(to: CGPoint(x: rect.midX, y: rect.maxY))
        return p
    }
}

/// Route badge under a bubble: opens that message's path.
struct RouteChip: View {
    let text: String
    let outgoing: Bool

    var body: some View {
        Text(verbatim: text).font(BarkingFont.mono(.caption2, size: 11))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(outgoing ? Color.white.opacity(0.18) : Color.wash, in: RoundedRectangle(cornerRadius: Radius.tag))
            .foregroundStyle(outgoing ? Color.white : Color.accent)
    }
}
