import BarkingKit
import Foundation
import Observation

/// What an ⓘ of the node's detail screen explains (spec §7.3).
enum ExplainTopic: String, Identifiable {
    case reliability, latency, origin, fill, subscriptions, pushLink, mySubscriptions

    var id: String { rawValue }
}

/// A node's detail screen (node transparency spec §7.2): the cached detail
/// at once, then the node's own answer; "Remove" and "Block" (§6.4, §7.4).
@MainActor @Observable
final class NodeDetailModel {
    /// "Ce qu'il fait": the node's report, or why there is none.
    enum Activity: Equatable {
        case report(NodeReportView)
        /// Never reported yet and not answered yet: asked right now.
        case asking
        /// No report: an old node (protocol under 5), or one that said nothing.
        case notShared(olderThan05: Bool)
    }

    /// One row of the declared / observed table.
    struct OriginRow: Equatable {
        enum Kind: Equatable { case asn, country }
        enum Mark: Equatable {
            case same, differs, unknown

            /// ✓ alike, ≠ different, ○ not checked: never the colour alone.
            var glyph: String {
                switch self {
                case .same: "✓"
                case .differs: "≠"
                case .unknown: "○"
                }
            }
        }

        let kind: Kind
        let declared: String
        let observed: String
        let mark: Mark
    }

    let id: String
    private let core: CoreService
    private(set) var detail: NodeDetail?
    /// The node is gone from the view (blocked elsewhere, never known).
    private(set) var missing = false
    /// The node has answered (or failed to) since the screen opened.
    private(set) var refreshed = false
    /// The last request did not reach the node: the cached detail stays.
    private(set) var unreachable = false
    private(set) var refreshing = false
    /// Instant notifications are on: only then is the push link shown.
    private(set) var instant = false
    /// "Blocking…": the block waits for a sync in progress (§6.4).
    private(set) var blocking = false
    /// Usable nodes left if this one were blocked, when under 3 (§6.4).
    private(set) var blockWarning: Int?
    /// The last block or removal was not recorded.
    private(set) var actionFailed = false

    /// Under this many usable nodes, the block confirmation warns
    /// (`CLIENT_COPIES`, the copies a message is left as).
    static let copies = 3

    init(core: CoreService, id: String) {
        self.core = core
        self.id = id
    }

    var node: NodeInfo? { detail?.node }

    /// Only a node added by hand or a default node can be removed (§6.4);
    /// one found on the network or on a card would come back by itself.
    var canRemove: Bool {
        switch node?.kind {
        case .manual?, .bootstrap?: true
        default: false
        }
    }

    var showsPushLink: Bool { instant && detail?.report?.pushLink != nil }

    var activity: Activity {
        if let report = detail?.report { return .report(report) }
        if let v = detail?.peerVersion, v < 5 { return .notShared(olderThan05: true) }
        return refreshed ? .notShared(olderThan05: false) : .asking
    }

    /// No origin declared reads as "doesn't share its origin".
    var verdict: OriginVerdictView { node?.origin?.verdict ?? .notReported }

    var isMismatch: Bool {
        if case .mismatch = verdict { true } else { false }
    }

    func verdictLine(lang: NodeLabels.Lang = .current) -> NodeLabels.Line {
        NodeLabels.verdictLine(verdict, lang: lang)
    }

    /// AS and country, declared then observed; empty without an origin.
    var originRows: [OriginRow] {
        guard let o = node?.origin else { return [] }
        let asn = String(o.asn)
        let country = o.country.uppercased()
        switch o.verdict {
        case .matches:
            return [OriginRow(kind: .asn, declared: asn, observed: asn, mark: .same),
                    OriginRow(kind: .country, declared: country, observed: country, mark: .same)]
        case .mismatch(let dc, let oc, let da, let oa):
            return [OriginRow(kind: .asn, declared: String(da), observed: String(oa), mark: da == oa ? .same : .differs),
                    OriginRow(kind: .country, declared: dc.uppercased(), observed: oc.uppercased(),
                              mark: dc.uppercased() == oc.uppercased() ? .same : .differs)]
        case .notReported, .notInBase, .noRecord:
            return [OriginRow(kind: .asn, declared: asn, observed: NodeLabels.noCountry, mark: .unknown),
                    OriginRow(kind: .country, declared: country, observed: NodeLabels.noCountry, mark: .unknown)]
        }
    }

    /// The cached detail, then the node's own answer (§6.1).
    func load() async {
        await loadCached()
        await refresh()
    }

    /// The cache alone: the screen shows it while the node is asked.
    func loadCached() async {
        instant = (try? await core.notificationPrefs().instant) ?? false
        do {
            detail = try await core.nodeDetail(id: id)
            missing = false
        } catch {
            missing = detail == nil
        }
        await checkBlock()
    }

    /// Asks the node (pull to refresh too). It may wait for a running sync;
    /// an unreachable node keeps the cached detail on screen.
    func refresh() async {
        refreshing = true
        defer { refreshing = false }
        do {
            detail = try await core.refreshNodeInfo(id: id)
            unreachable = false
            missing = false
        } catch {
            unreachable = true
        }
        refreshed = true
    }

    /// Reads how many usable nodes blocking this one would leave.
    func checkBlock() async {
        guard let usable = try? await core.usableNodesIfBlocked(id: id) else { blockWarning = nil; return }
        blockWarning = usable < Self.copies ? usable : nil
    }

    /// Blocks the node: immediate and total once written (§6.4). True once
    /// the core holds it.
    func block() async -> Bool {
        blocking = true
        defer { blocking = false }
        do {
            try await core.blockNode(id: id)
            actionFailed = false
            return true
        } catch {
            actionFailed = true
            return false
        }
    }

    func remove() async -> Bool {
        do {
            try await core.removeNode(id: id)
            actionFailed = false
            return true
        } catch {
            actionFailed = true
            return false
        }
    }
}
