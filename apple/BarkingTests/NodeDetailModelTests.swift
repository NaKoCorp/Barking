import XCTest
@testable import Barking
@testable import BarkingKit

/// A node's detail screen (node transparency spec §7.2 to §7.4): the
/// declared / observed table and its verdict, an old node, the push link,
/// "Remove" and "Block" with the guard-rail, and the explanations.
@MainActor
final class NodeDetailModelTests: XCTestCase {
    private static let id = String(repeating: "A", count: 49) + "X4Q"
    private let utc = TimeZone(identifier: "UTC")!

    // MARK: Fixtures

    /// `lastSeen` 0: never confirmed by this device (the core says 0 until
    /// the node answered as itself).
    private func node(kind: NodeOriginKind = .discovered, origin: OriginView? = nil,
                      lastSeen: UInt64 = 1_800_000_000) -> NodeInfo {
        NodeInfo(id: Self.id, addr: "51.38.12.4:7700", reliability: .good, score: 0.7,
                 manual: kind == .manual || kind == .bootstrap, fromCard: kind == .fromCard, lastSeen: lastSeen,
                 latencyMs: 38, inUse: true, origin: origin, mySubscriptions: 3, kind: kind)
    }

    private func report(push: PushLinkView? = .ok) -> NodeReportView {
        NodeReportView(software: "0.5.0", protocol: 5, uptimeSecs: 3 * 86_400, storage: .medium, wake: .low,
                       pushLink: push)
    }

    private func detail(kind: NodeOriginKind = .discovered, origin: OriginView? = nil, report: NodeReportView? = nil,
                        peer: UInt16? = 5, lastSeen: UInt64 = 1_800_000_000) -> NodeDetail {
        NodeDetail(node: node(kind: kind, origin: origin, lastSeen: lastSeen), v4: "51.38.12.4:7700", v6: nil, report: report,
                   fetchedAt: report == nil ? nil : 1_800_000_000, peerVersion: peer)
    }

    private func ovh(_ verdict: OriginVerdictView) -> OriginView {
        OriginView(asn: 16276, asName: "OVH SAS", country: "FR", verdict: verdict)
    }

    private func lang(_ code: String) throws -> NodeLabels.Lang {
        let path = try XCTUnwrap(Bundle.main.path(forResource: code, ofType: "lproj"))
        return NodeLabels.Lang(bundle: try XCTUnwrap(Bundle(path: path)), locale: Locale(identifier: code),
                               timeZone: utc)
    }

    private func flat(_ s: String) -> String {
        s.replacingOccurrences(of: "\u{00A0}", with: " ").replacingOccurrences(of: "\u{202F}", with: " ")
            .replacingOccurrences(of: "\u{2019}", with: "'")
    }

    private func make(_ d: FakeDevice) -> NodeDetailModel {
        NodeDetailModel(core: CoreService(device: d, runner: DirectRunner()), id: Self.id)
    }

    // MARK: Where it runs (§7.2)

    /// A mismatch on the country: an amber banner (attention, never red)
    /// that names both countries, and the advice under it.
    func testMismatchShowsWarnBanner() async throws {
        let d = FakeDevice()
        d.nodeDetailResult = detail(origin: ovh(.mismatch(declaredCountry: "FR", observedCountry: "NL",
                                                           declaredAsn: 16276, observedAsn: 16276)))
        let model = make(d)
        await model.load()
        let fr = try lang("fr")
        XCTAssertTrue(model.isMismatch)
        let line = model.verdictLine(lang: fr)
        XCTAssertEqual(line.state, .waiting)
        XCTAssertEqual(flat(line.text), "Déclaré France · constaté Pays-Bas")
        XCTAssertEqual(flat(NodeLabels.mismatchAdvice(lang: fr)),
                       "Les bases d'adresses ont parfois du retard. Si l'écart persiste, vous pouvez bloquer ce nœud.")
        // The table marks the country row, not the AS row.
        let rows = model.originRows
        XCTAssertEqual(rows.map(\.kind), [.asn, .country])
        XCTAssertEqual(rows[0].declared, "16276")
        XCTAssertEqual(rows[0].observed, "16276")
        XCTAssertEqual(rows[0].mark, .same)
        XCTAssertEqual(rows[1].declared, "FR")
        XCTAssertEqual(rows[1].observed, "NL")
        XCTAssertEqual(rows[1].mark, .differs)
    }

    /// A match: both columns alike, a green line; unverifiable: a dash
    /// under "observed"; no origin at all: no table, "doesn't share".
    func testOriginTableForEachVerdict() async throws {
        let fr = try lang("fr")
        let d = FakeDevice()
        d.nodeDetailResult = detail(origin: ovh(.matches))
        var model = make(d)
        await model.load()
        XCTAssertFalse(model.isMismatch)
        XCTAssertEqual(model.originRows.map(\.observed), ["16276", "FR"])
        XCTAssertEqual(model.originRows.map(\.mark), [.same, .same])
        XCTAssertEqual(model.verdictLine(lang: fr).state, .ok)

        d.nodeDetailResult = detail(origin: ovh(.notInBase))
        model = make(d)
        await model.load()
        XCTAssertEqual(model.originRows.map(\.observed), [NodeLabels.noCountry, NodeLabels.noCountry])
        XCTAssertEqual(model.originRows.map(\.mark), [.unknown, .unknown])
        XCTAssertEqual(flat(model.verdictLine(lang: fr).text), "Non vérifiable · adresse absente de la base")

        d.nodeDetailResult = detail(origin: nil)
        model = make(d)
        await model.load()
        XCTAssertTrue(model.originRows.isEmpty)
        XCTAssertEqual(flat(model.verdictLine(lang: fr).text),
                       "Non vérifiable · ce nœud ne communique pas son origine")
    }

    // MARK: What it does

    /// No report and a node that speaks protocol 4: "not shared · older
    /// than 0.5"; no report from a recent node once asked: "not shared".
    func testOldNodeShowsNotReported() async throws {
        let fr = try lang("fr")
        let d = FakeDevice()
        d.nodeDetailResult = detail(report: nil, peer: 4)
        var model = make(d)
        await model.load()
        XCTAssertEqual(model.activity, .notShared(olderThan05: true))
        XCTAssertEqual(flat(NodeLabels.notShared(olderThan05: true, lang: fr)),
                       "non communiqué · version du nœud antérieure à 0.5")

        d.nodeDetailResult = detail(report: nil, peer: 5)
        model = make(d)
        await model.load()
        XCTAssertEqual(model.activity, .notShared(olderThan05: false))
        XCTAssertEqual(flat(NodeLabels.notShared(olderThan05: false, lang: fr)), "non communiqué")
    }

    /// Before the node answered, nothing is called "not shared" yet.
    func testNoReportBeforeTheFirstAnswerIsAsking() async {
        let d = FakeDevice()
        d.nodeDetailResult = detail(report: nil, peer: nil)
        let model = make(d)
        await model.loadCached()
        XCTAssertEqual(model.activity, .asking)
        XCTAssertEqual(d.nodeCalls, [], "the cache alone, no request yet")
    }

    /// Opening asks the node (§6.1); a node that doesn't answer keeps the
    /// cached detail on screen and says it is unreachable.
    func testRefreshFailureKeepsCachedDetail() async {
        let d = FakeDevice()
        d.nodeDetailResult = detail(report: report())
        d.refreshError = BarkingError.Network(detail: "timeout")
        let model = make(d)
        await model.load()
        XCTAssertEqual(d.nodeCalls, ["refresh:\(Self.id)"])
        XCTAssertTrue(model.unreachable)
        XCTAssertEqual(model.activity, .report(report()))
        XCTAssertNotNil(model.detail)

        // A later answer clears the line and shows the new report.
        d.refreshError = nil
        d.refreshedDetail = detail(report: report(push: .failing))
        await model.refresh()
        XCTAssertFalse(model.unreachable)
        XCTAssertEqual(model.activity, .report(report(push: .failing)))
    }

    /// A node this device never reached (found on the network, on a card,
    /// added by hand) is not dialled when its screen opens: only a pull to
    /// refresh asks it. Until then nothing spins: "not asked yet".
    func testUnconfirmedNodeIsAskedOnlyOnPull() async throws {
        let d = FakeDevice()
        d.nodeDetailResult = detail(report: nil, peer: nil, lastSeen: 0)
        let model = make(d)
        await model.load()
        XCTAssertFalse(model.confirmed)
        XCTAssertEqual(d.nodeCalls, [], "opening dials nothing")
        XCTAssertEqual(model.activity, .notAsked)
        XCTAssertFalse(model.refreshing)
        let fr = try lang("fr")
        XCTAssertEqual(flat(NodeLabels.notAsked(lang: fr)),
                       "pas encore demandé · tirez vers le bas pour interroger le nœud")

        // The explicit pull asks it.
        d.refreshedDetail = detail(report: report(), lastSeen: 1_800_000_000)
        await model.refresh()
        XCTAssertEqual(d.nodeCalls, ["refresh:\(Self.id)"])
        XCTAssertEqual(model.activity, .report(report()))
        XCTAssertTrue(model.confirmed)
    }

    /// A confirmed node is asked as soon as the screen opens.
    func testConfirmedNodeIsAskedOnOpening() async {
        let d = FakeDevice()
        d.nodeDetailResult = detail(report: report())
        let model = make(d)
        await model.load()
        XCTAssertTrue(model.confirmed)
        XCTAssertEqual(d.nodeCalls, ["refresh:\(Self.id)"])
    }

    // MARK: Errors (lock, gone, network)

    /// A sync holding the database (`Locked`) never reads as "gone" nor
    /// "unreachable": the last content stays, with "try again shortly".
    func testLockedKeepsContentAndSaysSyncInProgress() async throws {
        let d = FakeDevice()
        d.nodeDetailResult = detail(report: report())
        let model = make(d)
        await model.load()
        XCTAssertFalse(model.syncBusy)

        d.nodeDetailError = BarkingError.Locked
        d.refreshError = BarkingError.Locked
        await model.loadCached()
        XCTAssertTrue(model.syncBusy)
        XCTAssertFalse(model.missing)
        XCTAssertNotNil(model.detail, "last content kept")
        await model.refresh()
        XCTAssertTrue(model.syncBusy)
        XCTAssertFalse(model.missing)
        XCTAssertFalse(model.unreachable)
        XCTAssertEqual(model.activity, .report(report()))

        // Locked on the very first read: still not "missing".
        let fresh = make(d)
        await fresh.load()
        XCTAssertFalse(fresh.missing)
        XCTAssertTrue(fresh.syncBusy)

        // The next answer clears the line.
        d.nodeDetailError = nil
        d.refreshError = nil
        await model.refresh()
        XCTAssertFalse(model.syncBusy)

        let fr = try lang("fr")
        XCTAssertEqual(String(localized: "Sync in progress, try again in a moment", bundle: fr.bundle, locale: fr.locale),
                       "Synchronisation en cours, réessayez dans un instant")
    }

    /// Only `NotFound` (and, on refresh, a block from elsewhere) says the
    /// node left the list; the network failing says "unreachable".
    func testErrorKindsMapToTheirStatement() async {
        let d = FakeDevice()
        d.nodeDetailError = BarkingError.NotFound
        d.refreshError = BarkingError.NotFound
        var model = make(d)
        await model.load()
        XCTAssertTrue(model.missing)
        XCTAssertNil(model.detail)
        XCTAssertFalse(model.unreachable)

        let cases: [(Error, missing: Bool, unreachable: Bool, busy: Bool)] = [
            (BarkingError.NotFound, true, false, false),
            (BarkingError.InvalidInput(detail: "node is blocked"), true, false, false),
            (BarkingError.Network(detail: "timeout"), false, true, false),
            (BarkingError.Locked, false, false, true),
        ]
        for (error, missing, unreachable, busy) in cases {
            d.nodeDetailError = nil
            d.refreshError = nil
            d.nodeDetailResult = detail(report: report())
            model = make(d)
            await model.load()
            d.refreshError = error
            await model.refresh()
            XCTAssertEqual(model.missing, missing, "\(error)")
            XCTAssertEqual(model.unreachable, unreachable, "\(error)")
            XCTAssertEqual(model.syncBusy, busy, "\(error)")
            XCTAssertEqual(model.detail == nil, missing, "gone: no stale detail; else kept (\(error))")
        }
    }

    /// The guard-rail fails closed: a count that cannot be read keeps the
    /// warning, without a number.
    func testBlockGuardRailFailsClosed() async throws {
        let d = FakeDevice()
        d.nodeDetailResult = detail()
        d.usableError = BarkingError.Locked
        let model = make(d)
        await model.load()
        XCTAssertTrue(model.blockCountUnknown)
        XCTAssertNil(model.blockWarning)
        let fr = try lang("fr")
        let text = flat(NodeLabels.blockMessage(usableLeft: model.blockWarning, countUnknown: model.blockCountUnknown,
                                                lang: fr))
        XCTAssertTrue(text.hasPrefix("Barking cesse immédiatement"), text)
        XCTAssertTrue(text.contains("n'a pas pu compter les nœuds utilisables"), text)
        XCTAssertTrue(NodeLabels.blockMessage(usableLeft: nil, countUnknown: true, lang: try lang("en"))
            .contains("could not count the usable nodes"))

        d.usableError = nil
        d.usableIfBlocked = 5
        await model.checkBlock()
        XCTAssertFalse(model.blockCountUnknown)
        XCTAssertNil(model.blockWarning)
    }

    /// A second tap while the count runs does nothing.
    func testSecondTapDuringTheCountIsIgnored() async {
        let d = FakeDevice()
        d.nodeDetailResult = detail()
        let model = make(d)
        async let first = model.checkBlock()
        async let second = model.checkBlock()
        let results = await [first, second]
        XCTAssertEqual(results.filter { $0 }.count, 1, "one count only")
        XCTAssertFalse(model.checkingBlock)
    }

    /// A block during a sync stays "Blocking…" and tries again until the
    /// lock is free; past the deadline it says it failed.
    func testBlockRetriesWhileLocked() async {
        let d = FakeDevice()
        d.nodeDetailResult = detail()
        let model = make(d)
        model.lockRetry = .milliseconds(1)
        d.blockLockedTimes = 3
        let ok = await model.block()
        XCTAssertTrue(ok)
        XCTAssertEqual(d.blockAttempts, 4)
        XCTAssertFalse(model.actionFailed)
        XCTAssertFalse(model.blocking)
        XCTAssertEqual(d.nodeCalls.last, "block:\(Self.id)")

        model.lockDeadline = .milliseconds(20)
        model.lockRetry = .milliseconds(5)
        d.blockLockedTimes = 1_000
        let late = await model.block()
        XCTAssertFalse(late)
        XCTAssertTrue(model.actionFailed)
        XCTAssertFalse(model.blocking)
    }

    /// The blocked list: a failed read is an error, not "no blocked node";
    /// a failed unblock is told.
    func testBlockedListErrorIsNotEmpty() async {
        let d = FakeDevice()
        d.blockedNodesError = BarkingError.Locked
        let model = BlockedNodesModel(core: CoreService(device: d, runner: DirectRunner()))
        await model.load()
        XCTAssertTrue(model.loaded)
        XCTAssertTrue(model.loadFailed)
        XCTAssertTrue(model.nodes.isEmpty)

        d.blockedNodesError = nil
        d.blockedNodeList = [BlockedNode(id: Self.id, at: 1_800_000_000, origin: nil)]
        await model.load()
        XCTAssertFalse(model.loadFailed)
        XCTAssertEqual(model.nodes.count, 1)

        d.unblockError = BarkingError.Locked
        let unblocked = await model.unblock(model.nodes[0])
        XCTAssertFalse(unblocked)
        XCTAssertTrue(model.failed)
    }

    /// The push link only with instant notifications on, and when the
    /// node said something about it.
    func testPushLinkOnlyWithInstantNotifications() async {
        let d = FakeDevice()
        d.nodeDetailResult = detail(report: report(push: .ok))
        var model = make(d)
        await model.load()
        XCTAssertTrue(model.showsPushLink)

        d.prefs.instant = false
        model = make(d)
        await model.load()
        XCTAssertFalse(model.showsPushLink)

        d.prefs.instant = true
        d.nodeDetailResult = detail(report: report(push: nil))
        model = make(d)
        await model.load()
        XCTAssertFalse(model.showsPushLink)
    }

    /// "Version 0.5.0 · protocol 5 · online for 3 d", from the node's
    /// own report, never a percentage.
    func testVersionLine() throws {
        let fr = try lang("fr")
        XCTAssertEqual(flat(NodeLabels.version(report(), lang: fr)), "0.5.0 · protocole 5 · en ligne depuis 3 j")
        let en = try lang("en")
        var r = report()
        r.uptimeSecs = 5 * 3_600
        XCTAssertEqual(NodeLabels.version(r, lang: en), "0.5.0 · protocol 5 · online for 5 h")
        r.uptimeSecs = 600
        XCTAssertEqual(NodeLabels.version(r, lang: en), "0.5.0 · protocol 5 · online for less than an hour")
    }

    // MARK: Remove (§6.4)

    func testRemoveHiddenForDiscovered() async {
        for kind in [NodeOriginKind.discovered, .fromCard] {
            let d = FakeDevice()
            d.nodeDetailResult = detail(kind: kind)
            let model = make(d)
            await model.load()
            XCTAssertFalse(model.canRemove, "\(kind)")
        }
    }

    func testRemoveShownForDefaultAndManual() async {
        for kind in [NodeOriginKind.bootstrap, .manual] {
            let d = FakeDevice()
            d.nodeDetailResult = detail(kind: kind)
            let model = make(d)
            await model.load()
            XCTAssertTrue(model.canRemove, "\(kind)")
            let removed = await model.remove()
            XCTAssertTrue(removed)
            XCTAssertEqual(d.nodeCalls.last, "remove:\(Self.id)")
        }
    }

    // MARK: Block (§6.4, §7.4)

    /// Fewer than 3 usable nodes left: the confirmation says how many.
    func testBlockWarningBelowThreeUsable() async throws {
        let d = FakeDevice()
        d.nodeDetailResult = detail()
        let model = make(d)
        await model.load()
        for (usable, warning) in [(UInt32(4), Int?.none), (3, nil), (2, 2), (1, 1), (0, 0)] {
            d.usableIfBlocked = usable
            await model.checkBlock()
            XCTAssertEqual(model.blockWarning, warning, "\(usable) usable")
        }
        let fr = try lang("fr")
        let en = try lang("en")
        XCTAssertEqual(flat(NodeLabels.blockMessage(usableLeft: nil, lang: fr)),
                       "Barking cesse immédiatement de lui parler. Ce qu'il garde pour vous ne sera récupéré que via les autres copies. Les réveils posés chez lui s'arrêtent.")
        for n in 0...2 {
            let text = flat(NodeLabels.blockMessage(usableLeft: n, lang: fr))
            XCTAssertTrue(text.hasPrefix("Barking cesse immédiatement"), text)
            XCTAssertTrue(text.contains(n == 0 ? "Aucun nœud utilisable" : "\(n) nœud"), text)
            XCTAssertTrue(NodeLabels.blockMessage(usableLeft: n, lang: en).contains(n == 0 ? "No usable node" : "\(n) usable node"))
        }
    }

    /// Blocking says "Blocking…" while it waits for a running sync, then
    /// gives the screen back; a failure is told, never silent.
    func testBlockRunsAndReportsFailure() async {
        let d = FakeDevice()
        d.nodeDetailResult = detail()
        let model = make(d)
        await model.load()
        XCTAssertFalse(model.blocking)
        let ok = await model.block()
        XCTAssertTrue(ok)
        XCTAssertFalse(model.blocking)
        XCTAssertEqual(d.nodeCalls.last, "block:\(Self.id)")

        d.nodeActionError = NSError(domain: "core", code: 1)
        let again = await model.block()
        XCTAssertFalse(again)
        XCTAssertTrue(model.actionFailed)
        XCTAssertFalse(model.blocking)
    }

    // MARK: Explanations (§7.3)

    /// Every explanation has a title and at least one sentence, says
    /// « vous » in French (Ruling K), and none of the forbidden words.
    func testExplanationsInPlainWords() throws {
        let fr = try lang("fr")
        let en = try lang("en")
        let topics: [ExplainTopic] = [.reliability, .latency, .origin, .fill, .subscriptions, .pushLink,
                                      .mySubscriptions]
        for topic in topics {
            for l in [fr, en] {
                XCTAssertFalse(NodeLabels.explainTitle(topic, lang: l).isEmpty)
                let text = NodeLabels.explainText(topic, lang: l)
                XCTAssertFalse(text.isEmpty, "\(topic)")
                for p in text {
                    XCTAssertTrue(p.hasSuffix(".") || p.hasSuffix("»"), "a sentence ends with a full stop: \(p)")
                    for word in ["score", " AS ", "paquet", "packet", "DHT", "%"] {
                        XCTAssertFalse(p.contains(word), "\(word) in \(p)")
                    }
                }
            }
            for p in NodeLabels.explainText(topic, lang: fr).map(flat) {
                for tu in [" tu ", " ton ", " ta ", " tes ", " te ", " t'"] {
                    XCTAssertFalse(" \(p.lowercased())".contains(tu), "« tu » in \(p)")
                }
            }
        }
        XCTAssertEqual(flat(NodeLabels.explainText(.latency, lang: fr).first ?? ""),
                       "Le temps que met ce relais à répondre à votre iPhone. Plus c'est bas, plus vos messages partent vite.")
        XCTAssertEqual(NodeLabels.explainTitle(.reliability, lang: fr), "Comment Barking juge un relais")
        // "Unknown" adds why the node doesn't say.
        XCTAssertEqual(NodeLabels.explainText(.pushLink, unknownPushLink: true, lang: fr).count,
                       NodeLabels.explainText(.pushLink, lang: fr).count + 1)
    }
}
