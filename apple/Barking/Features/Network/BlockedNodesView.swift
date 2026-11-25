import BarkingKit
import Observation
import SwiftUI

/// The blocked nodes (spec §7.4), newest first, each with "Unblock". A row
/// shows the identifier, the origin known when it was blocked and the date;
/// no verdict (Ruling H: there is no record to check any more).
@MainActor @Observable
final class BlockedNodesModel {
    private let core: CoreService
    private(set) var nodes: [BlockedNode] = []
    private(set) var loaded = false
    /// The last unblock was not recorded.
    private(set) var failed = false

    init(core: CoreService) { self.core = core }

    func load() async {
        nodes = ((try? await core.blockedNodes()) ?? []).sorted { ($0.at, $0.id) > ($1.at, $1.id) }
        loaded = true
    }

    /// Unblocked, the node comes back only by the usual ways (discovery,
    /// added by hand): it leaves this list, not into the relays (§6.4).
    func unblock(_ node: BlockedNode) async -> Bool {
        failed = (try? await core.unblockNode(id: node.id)) == nil
        await load()
        return !failed
    }

    /// "OVH SAS · FR · blocked on 24 Nov 2026", or the origin unknown.
    static func subtitle(_ node: BlockedNode, lang: NodeLabels.Lang = .current) -> String {
        let origin = node.origin.map { o -> String in
            let host = o.asName.trimmingCharacters(in: .whitespaces)
            return [host.isEmpty ? nil : host, o.country.count == 2 ? o.country.uppercased() : nil]
                .compactMap { $0 }.joined(separator: " · ")
        }
        let day = Date(timeIntervalSince1970: TimeInterval(node.at))
            .formatted(Date.FormatStyle(locale: lang.locale, timeZone: lang.timeZone).day().month().year())
        let blocked = String(localized: "blocked on \(day)", bundle: lang.bundle, locale: lang.locale)
        let shownOrigin = (origin?.isEmpty == false ? origin : nil)
            ?? String(localized: "origin unknown", bundle: lang.bundle, locale: lang.locale)
        return "\(shownOrigin) · \(blocked)"
    }
}

struct BlockedNodesView: View {
    @State private var model: BlockedNodesModel
    @Environment(\.locale) private var locale

    init(core: CoreService) { _model = State(initialValue: BlockedNodesModel(core: core)) }

    var body: some View {
        Group {
            Text("Barking no longer contacts a blocked node. Unblocking it doesn't bring it back: it returns only if the network finds it again or you add it by hand.")
                .font(.bBody).foregroundStyle(Color.fgMuted)
                .fixedSize(horizontal: false, vertical: true)
            if model.failed { Banner(kind: .danger, title: "Not saved. Try again.") }
            if model.loaded && model.nodes.isEmpty {
                Text("No blocked node.").font(.bBody).foregroundStyle(Color.fgSoft)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityIdentifier("blockedNodes.empty")
            } else if !model.nodes.isEmpty {
                FormCard {
                    ForEach(model.nodes, id: \.id) { node in row(node) }
                }
            }
        }
        .barkingScreen(tabRoot: true)
        .navigationTitle(Text("Blocked nodes"))
        .toolbarTitleDisplayMode(.inline)
        .task { await model.load() }
    }

    private func row(_ node: BlockedNode) -> some View {
        let short = NodeLabels.shortId(node.id)
        let subtitle = BlockedNodesModel.subtitle(node, lang: .of(locale))
        return FormRow(title: Text(verbatim: short).font(BarkingFont.mono(.subheadline, size: 14, weight: .semibold)),
                       subtitle: Text(verbatim: subtitle)) {
            Button("Unblock") {
                Task { if await model.unblock(node) { Haptic.success.play() } else { Haptic.error.play() } }
            }
            .font(.bBody.weight(.semibold))
            .foregroundStyle(Color.accent)
            .frame(minHeight: 44)
            .accessibilityLabel(Text("Unblock \(short)"))
            .accessibilityIdentifier("blockedNode.unblock.\(node.id)")
        }
        .accessibilityElement(children: .contain)
    }
}
