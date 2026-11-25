import BarkingKit
import Observation
import os
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
    /// The list could not be read (a sync holding the database, a storage
    /// error): not the same as an empty list.
    private(set) var loadFailed = false

    private static let log = Logger(subsystem: "barking", category: "blocked-nodes")

    init(core: CoreService) { self.core = core }

    /// Reads the list; a failure keeps what was shown and says so.
    func load() async {
        do {
            nodes = try await core.blockedNodes().sorted { ($0.at, $0.id) > ($1.at, $1.id) }
            loadFailed = false
        } catch {
            Self.log.error("blocked nodes: read failed (\(NodeDetailModel.kind(error), privacy: .public))")
            loadFailed = true
        }
        loaded = true
    }

    /// Unblocked, the node comes back only by the usual ways (discovery,
    /// added by hand): it leaves this list, not into the relays (§6.4).
    func unblock(_ node: BlockedNode) async -> Bool {
        do {
            try await core.unblockNode(id: node.id)
            failed = false
        } catch {
            let kind = NodeDetailModel.kind(error), short = NodeLabels.shortId(node.id)
            Self.log.error("blocked nodes: unblock failed (\(kind, privacy: .public)) for \(short, privacy: .public)")
            failed = true
        }
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
    let core: CoreService
    @State private var model: BlockedNodesModel
    @Environment(\.locale) private var locale

    init(core: CoreService) {
        self.core = core
        _model = State(initialValue: BlockedNodesModel(core: core))
    }

    var body: some View {
        Group {
            Text("Barking no longer contacts a blocked node. Unblocking it doesn't bring it back: it returns only if the network finds it again or you add it by hand.")
                .font(.bBody).foregroundStyle(Color.fgMuted)
                .fixedSize(horizontal: false, vertical: true)
            if model.failed { Banner(kind: .danger, title: "Not saved. Try again.") }
            if model.loadFailed {
                Banner(kind: .danger, title: "Couldn't load the list. Try again.",
                       action: Banner.Action(label: "Try again", hint: "Reads the list again") {
                           Task { await model.load() }
                       })
                    .accessibilityIdentifier("blockedNodes.loadFailed")
            }
            if !model.loaded {
                HStack(spacing: Space.s2) {
                    ProgressView()
                    Text("Loading the list…").font(.bBody).foregroundStyle(Color.fgMuted)
                }
                .accessibilityElement(children: .combine)
                .accessibilityIdentifier("blockedNodes.loading")
            } else if !model.loadFailed && model.nodes.isEmpty {
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
        .task {
            await model.load()
            // A block that lands after this screen opened (it waits for a
            // sync in progress) shows here at once.
            for await change in await core.changes where change == .network { await model.load() }
        }
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
