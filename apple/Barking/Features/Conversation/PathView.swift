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
            VStack(alignment: .leading, spacing: 12) {
                quoteCard
                SectionLabel("How it got here")
                if model.notRecorded {
                    Text("Path not recorded")
                        .font(BarkingFont.sans(.body, size: 15)).foregroundStyle(Color.fgMuted)
                        .accessibilityIdentifier("path.notRecorded")
                } else {
                    VStack(spacing: 0) {
                        ForEach(Array(model.rows.enumerated()), id: \.element.id) { i, row in
                            PathStop(row: row, more: i < model.rows.count - 1)
                        }
                    }
                }
                footer.padding(.top, 8)
            }
            .padding(16)
        }
        .background(Color.surface)
        .navigationTitle(Text("Message path"))
        .navigationBarTitleDisplayMode(.inline)
        .task { await model.load() }
    }

    private var quoteCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("“\(model.quote)”").font(BarkingFont.sans(.body, size: 15)).foregroundStyle(Color.fg)
                .lineSpacing(3).fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 6) {
                if let route = model.routeBadge {
                    Text(verbatim: route).padding(.horizontal, 7).padding(.vertical, 3)
                        .background(Color.wash, in: RoundedRectangle(cornerRadius: Radius.tag))
                        .foregroundStyle(Color.accent)
                }
                if !model.times.isEmpty {
                    Text(verbatim: model.times).padding(.horizontal, 7).padding(.vertical, 3)
                        .background(Color.field, in: RoundedRectangle(cornerRadius: Radius.tag))
                        .foregroundStyle(Color.fgMuted)
                }
            }
            .font(BarkingFont.mono(.caption2, size: 11))
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.surfaceCard, in: RoundedRectangle(cornerRadius: Radius.card))
        .overlay(RoundedRectangle(cornerRadius: Radius.card).stroke(Color.border, lineWidth: 1))
    }

    /// Dark in both themes, as in the mockup.
    private var footer: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("// only you and \(model.contactName) can read it")
                .font(BarkingFont.mono(.caption, size: 12)).foregroundStyle(Color(hex: 0xB9A6E0))
            HStack(spacing: 6) {
                ForEach(["PQXDH", "Double Ratchet"], id: \.self) { chip(Text(verbatim: $0)) }
                chip(Text("hidden sender"))
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(hex: 0x120E19), in: RoundedRectangle(cornerRadius: Radius.card))
        .overlay(RoundedRectangle(cornerRadius: Radius.card).stroke(Color.border, lineWidth: 1))
    }

    private func chip(_ text: Text) -> some View {
        text.font(BarkingFont.mono(.caption2, size: 11)).foregroundStyle(Color(hex: 0xF2EFF7))
            .padding(.horizontal, 8).padding(.vertical, 4)
            .background(Color(hex: 0x1B1524), in: RoundedRectangle(cornerRadius: 5))
            .overlay(RoundedRectangle(cornerRadius: 5).stroke(Color(hex: 0x33293F), lineWidth: 1))
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
        .accessibilityElement(children: .combine)
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

    /// The mockup's fixed colors: white glyphs read on them in both themes.
    private var color: Color {
        switch row.glyph {
        case .sender: Color(hex: 0x6640AF)
        case .relay: Color(hex: 0x8A6A0B)
        case .recipient: Color(hex: 0x1F7F55)
        case .ownDevices: Color(hex: 0x4E3189)
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

private extension Color {
    init(hex: UInt32) {
        self.init(red: Double((hex >> 16) & 0xFF) / 255, green: Double((hex >> 8) & 0xFF) / 255,
                  blue: Double(hex & 0xFF) / 255)
    }
}
