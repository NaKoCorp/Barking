import XCTest
@testable import Barking
@testable import BarkingKit

/// The "Internet relays" list (node transparency spec §7.1, §7.3): the
/// words and sentences of `NodeLabels`, the split between nodes in use and
/// the others, and "Restore the default nodes".
@MainActor
final class NodeListTests: XCTestCase {
    private let t0: UInt64 = 1_800_000_000
    private var now: Date { Date(timeIntervalSince1970: TimeInterval(t0)) }
    private let utc = TimeZone(identifier: "UTC")!
    private static let idA = String(repeating: "A", count: 50) + "XQ"
    private static let idB = String(repeating: "B", count: 50) + "YQ"

    // MARK: Fixtures

    private func node(_ id: String, inUse: Bool = true, reliability: Reliability = .good, latency: UInt32? = 38,
                      origin: OriginView? = nil, subs: UInt32 = 0, lastSeen: UInt64 = 0,
                      kind: NodeOriginKind = .discovered) -> NodeInfo {
        NodeInfo(id: id, addr: "51.38.12.4:7700", reliability: reliability, score: 0.73, manual: kind == .manual,
                 fromCard: kind == .fromCard, lastSeen: lastSeen, latencyMs: latency, inUse: inUse, origin: origin,
                 mySubscriptions: subs, kind: kind)
    }

    private func ovh(_ verdict: OriginVerdictView = .matches) -> OriginView {
        OriginView(asn: 16276, asName: "OVH SAS", country: "FR", verdict: verdict)
    }

    private func lang(_ code: String) throws -> NodeLabels.Lang {
        let path = try XCTUnwrap(Bundle.main.path(forResource: code, ofType: "lproj"))
        return NodeLabels.Lang(bundle: try XCTUnwrap(Bundle(path: path)), locale: Locale(identifier: code),
                               timeZone: utc)
    }

    /// Spaces of every kind as plain ones, typographic apostrophes as straight ones.
    private func flat(_ s: String) -> String {
        s.replacingOccurrences(of: "\u{00A0}", with: " ").replacingOccurrences(of: "\u{202F}", with: " ")
            .replacingOccurrences(of: "\u{2019}", with: "'")
    }

    private func make(_ d: FakeDevice) -> NetworkModel {
        NetworkModel(core: CoreService(device: d, runner: DirectRunner()))
    }

    // MARK: The row

    /// No percentage anywhere on the row (§7.1), whatever the state, the
    /// origin or the language: neither on screen nor for VoiceOver.
    func testRowTextHasNoPercentage() throws {
        let states: [Reliability] = [.new, .good, .fair, .weak, .avoided(until: t0 + 3_600, reason: .messageLost),
                                     .avoided(until: t0 + 7 * 86_400, reason: .unreachable)]
        let origins: [OriginView?] = [nil, ovh(), ovh(.mismatch(declaredCountry: "FR", observedCountry: "NL",
                                                                 declaredAsn: 16276, observedAsn: 24940)),
                                      ovh(.notReported), ovh(.notInBase), ovh(.noRecord)]
        for code in ["en", "fr"] {
            let l = try lang(code)
            for r in states {
                for o in origins {
                    for latency in [nil, UInt32(38)] {
                        let row = NodeLabels.Row(node(Self.idA, reliability: r, latency: latency, origin: o, subs: 3),
                                                 now: now, lang: l)
                        let texts = [row.country, row.name, row.status.text, row.idLine, row.verdict?.text ?? "",
                                     row.extras ?? "", row.accessibilityLabel]
                        for t in texts {
                            XCTAssertFalse(t.contains("%"), "\(code) \(r) \(String(describing: o)): \(t)")
                            XCTAssertFalse(t.isEmpty && t == row.name, "\(code): empty name")
                        }
                    }
                }
            }
        }
    }

    /// The sketch of §7.1: country in ISO code, host, status and latency,
    /// short id and address, verdict · wakes · subscriptions.
    func testRowFollowsTheSketch() throws {
        let fr = try lang("fr")
        let row = NodeLabels.Row(node(Self.idA, origin: ovh(), subs: 3), now: now, lang: fr)
        XCTAssertEqual(row.country, "FR")
        XCTAssertEqual(row.name, "OVH SAS")
        XCTAssertEqual(row.status.state, .ok)
        XCTAssertEqual(flat(row.status.text), "bonne · 38 ms")
        XCTAssertEqual(row.idLine, "AAAAAA…AXQ · 51.38.12.4:7700")
        XCTAssertEqual(row.verdict?.state, .ok)
        XCTAssertEqual(row.verdict?.text, "vérifié")
        XCTAssertEqual(row.extras, "réveils · 3 abonnements")
        let label = flat(row.accessibilityLabel)
        for part in ["France", "OVH SAS", "fiabilité bonne", "38 ms", "vérifié", "3 abonnements"] {
            XCTAssertTrue(label.contains(part), "\(part) in \(label)")
        }
    }

    /// Without an origin: the short id as the name, `—` as the country,
    /// no verdict; no subscription, no "wakes".
    func testRowWithoutOrigin() throws {
        let en = try lang("en")
        let row = NodeLabels.Row(node(Self.idA, reliability: .new, latency: nil), now: now, lang: en)
        XCTAssertEqual(row.country, NodeLabels.noCountry)
        XCTAssertEqual(row.name, "AAAAAA…AXQ")
        XCTAssertEqual(row.idLine, "51.38.12.4:7700", "the short id once")
        XCTAssertEqual(row.status.state, .checking)
        XCTAssertEqual(row.status.text, "new")
        XCTAssertNil(row.verdict)
        XCTAssertNil(row.extras)
    }

    /// A mismatch is amber (attention), never red.
    func testMismatchIsAWarningInTheList() throws {
        let fr = try lang("fr")
        let o = ovh(.mismatch(declaredCountry: "FR", observedCountry: "NL", declaredAsn: 16276, observedAsn: 24940))
        let row = NodeLabels.Row(node(Self.idA, origin: o), now: now, lang: fr)
        XCTAssertEqual(row.verdict?.state, .waiting)
        XCTAssertEqual(row.verdict?.text, "ne concorde pas")
    }

    // MARK: Words and sentences (§7.3)

    func testReliabilitySentencesMatchSpec() throws {
        let fr = try lang("fr")
        let expected: [(Reliability, String)] = [
            (.new, "Cet iPhone n'a pas encore assez échangé avec ce relais pour le juger."),
            (.good, "Ce relais répond bien à ton iPhone ces derniers temps."),
            (.fair, "Ce relais ne répond pas toujours. Tes messages restent en sécurité : ils sont aussi gardés ailleurs."),
            (.weak, "Ce relais a souvent échoué. Barking s'en sert moins et confie tes messages à d'autres."),
            (.avoided(until: t0 + 3_600, reason: .messageLost),
             "Un message confié à ce relais a disparu. Barking l'évite pour l'instant et réessaiera plus tard."),
            (.avoided(until: t0 + 3_600, reason: .unreachable),
             "Ce relais ne répondait plus. Barking l'évite pour l'instant et réessaiera plus tard."),
        ]
        for (r, sentence) in expected {
            XCTAssertEqual(flat(NodeLabels.reliabilitySentence(r, lang: fr)), sentence)
        }
        let en = try lang("en")
        for (r, _) in expected {
            let s = NodeLabels.reliabilitySentence(r, lang: en)
            XCTAssertTrue(s.hasSuffix("."), s)
            XCTAssertFalse(s.contains("score"), s)
        }
    }

    func testReliabilityWords() throws {
        let fr = try lang("fr")
        XCTAssertEqual(NodeLabels.reliabilityWord(.new, now: now, lang: fr), "nouveau")
        XCTAssertEqual(NodeLabels.reliabilityWord(.good, now: now, lang: fr), "bonne")
        XCTAssertEqual(NodeLabels.reliabilityWord(.fair, now: now, lang: fr), "moyenne")
        XCTAssertEqual(NodeLabels.reliabilityWord(.weak, now: now, lang: fr), "fragile")
        let en = try lang("en")
        XCTAssertEqual(NodeLabels.reliabilityWord(.fair, now: now, lang: en), "fair")
        XCTAssertEqual(NodeLabels.reliabilityWord(.weak, now: now, lang: en), "weak")
        // t0 is 08:00 UTC: 14:00 the same day reads as an hour.
        let today = t0 - 8 * 3_600 + 14 * 3_600
        XCTAssertEqual(flat(NodeLabels.reliabilityWord(.avoided(until: today, reason: .unreachable), now: now,
                                                       lang: fr)), "évité jusqu'à 14:00")
        // Avoided for 7 days: the date, not an hour that reads as today.
        let later = NodeLabels.reliabilityWord(.avoided(until: t0 + 7 * 86_400, reason: .messageLost), now: now,
                                               lang: fr)
        XCTAssertTrue(flat(later).hasPrefix("évité jusqu'au "), later)
        XCTAssertFalse(later.contains(":"), later)
    }

    func testLatencyWords() throws {
        let fr = try lang("fr")
        XCTAssertEqual(NodeLabels.latencyWord(ms: 99, lang: fr), "rapide")
        XCTAssertEqual(NodeLabels.latencyWord(ms: 100, lang: fr), "correct")
        XCTAssertEqual(NodeLabels.latencyWord(ms: 299, lang: fr), "correct")
        XCTAssertEqual(NodeLabels.latencyWord(ms: 300, lang: fr), "lent")
        let en = try lang("en")
        XCTAssertEqual(NodeLabels.latencyWord(ms: 38, lang: en), "fast")
        XCTAssertEqual(NodeLabels.latencyWord(ms: 300, lang: en), "slow")
        XCTAssertEqual(flat(NodeLabels.latency(ms: 38, lang: fr)), "38 ms · rapide")
    }

    func testFillWords() throws {
        let fr = try lang("fr")
        XCTAssertEqual([FillTierView.low, .medium, .high, .full].map { NodeLabels.fillWord($0, lang: fr) },
                       ["bas", "moyen", "élevé", "plein"])
        XCTAssertEqual(NodeLabels.fillSegments(.low), 1)
        XCTAssertEqual(NodeLabels.fillSegments(.full), 4)
    }

    /// The verdict line of the detail sheet (§7.2), with country names.
    func testVerdictLines() throws {
        let fr = try lang("fr")
        let match = NodeLabels.verdictLine(.matches, lang: fr)
        XCTAssertEqual(match.state, .ok)
        XCTAssertEqual(match.text, "Concorde avec ce que voit cet iPhone")
        let off = NodeLabels.verdictLine(.mismatch(declaredCountry: "FR", observedCountry: "NL", declaredAsn: 16276,
                                                   observedAsn: 24940), lang: fr)
        XCTAssertEqual(off.state, .waiting)
        XCTAssertEqual(flat(off.text), "Déclaré France · constaté Pays-Bas")
        let asOnly = NodeLabels.verdictLine(.mismatch(declaredCountry: "FR", observedCountry: "FR", declaredAsn: 16276,
                                                      observedAsn: 24940), lang: fr)
        XCTAssertEqual(flat(asOnly.text), "Déclaré AS16276 · constaté AS24940")
        let silent = NodeLabels.verdictLine(.notReported, lang: fr)
        XCTAssertEqual(silent.state, .checking)
        XCTAssertEqual(flat(silent.text), "Non vérifiable · ce nœud ne communique pas son origine")
        XCTAssertEqual(flat(NodeLabels.verdictLine(.notInBase, lang: fr).text),
                       "Non vérifiable · adresse absente de la base")
        XCTAssertEqual(NodeLabels.verdictLine(.noRecord, lang: fr).state, .checking)
    }

    func testPushLinkLines() throws {
        let fr = try lang("fr")
        XCTAssertEqual(NodeLabels.pushLinkLine(.ok, lang: fr).state, .ok)
        XCTAssertEqual(NodeLabels.pushLinkLine(.ok, lang: fr).text, "joint")
        XCTAssertEqual(NodeLabels.pushLinkLine(.failing, lang: fr).state, .down)
        XCTAssertEqual(NodeLabels.pushLinkLine(.failing, lang: fr).text, "injoignable")
        XCTAssertEqual(NodeLabels.pushLinkLine(.unknown, lang: fr).state, .checking)
        XCTAssertEqual(NodeLabels.pushLinkLine(.unknown, lang: fr).text, "non communiqué")
    }

    /// `last_seen` is rounded to the hour: never a minute (§7.2).
    func testLastSeen() throws {
        let fr = try lang("fr")
        XCTAssertEqual(flat(NodeLabels.lastSeen(t0 - 600, now: now, lang: fr)), "il y a moins d'une heure")
        XCTAssertEqual(flat(NodeLabels.lastSeen(t0 + 600, now: now, lang: fr)), "il y a moins d'une heure")
        XCTAssertEqual(flat(NodeLabels.lastSeen(t0 - 3 * 3_600, now: now, lang: fr)), "il y a 3 h")
        // 08:00 now: 20 h ago was yesterday.
        XCTAssertEqual(NodeLabels.lastSeen(t0 - 20 * 3_600, now: now, lang: fr), "hier")
        let older = NodeLabels.lastSeen(t0 - 5 * 86_400, now: now, lang: fr)
        XCTAssertFalse(older.contains("il y a"), older)
        XCTAssertFalse(older.contains(":"), older)
        XCTAssertEqual(NodeLabels.lastSeen(0, now: now, lang: fr), "jamais")
    }

    func testOriginKindWords() throws {
        let fr = try lang("fr")
        XCTAssertEqual(NodeLabels.originKind(.discovered, lang: fr), "découvert sur le réseau")
        XCTAssertEqual(NodeLabels.originKind(.manual, lang: fr), "ajouté à la main")
    }

    // MARK: The model

    func testSplitInUseAndOthers() async {
        let d = FakeDevice()
        let slowGood = node("G1", latency: 200), fastGood = node("G2", latency: 20)
        let noLatency = node("G3", latency: nil)
        let fair = node("F1", reliability: .fair, latency: 10)
        let avoided = node("V1", reliability: .avoided(until: t0, reason: .unreachable), latency: 5)
        let fresh = node("N1", reliability: .new, latency: nil)
        d.nodeList = [avoided, node("O1", inUse: false), slowGood, fair, fresh, node("O2", inUse: false, latency: 5),
                      noLatency, fastGood]
        let m = make(d)
        await m.load()
        XCTAssertEqual(m.inUse.map(\.id), ["G2", "G1", "G3", "F1", "N1", "V1"],
                       "by reliability, then latency (unknown last)")
        XCTAssertEqual(m.others.map(\.id), ["O2", "O1"])
    }

    func testResetLinkHiddenWithoutDismissed() async {
        let d = FakeDevice()
        d.dismissedCount = 0
        let m = make(d)
        await m.load()
        XCTAssertEqual(m.dismissedDefaults, 0)
        XCTAssertFalse(m.showsReset)
        d.dismissedCount = 2
        await m.load()
        XCTAssertEqual(m.dismissedDefaults, 2)
        XCTAssertTrue(m.showsReset)
    }

    func testBlockedCount() async {
        let d = FakeDevice()
        d.blockedNodeList = [BlockedNode(id: Self.idB, at: t0, origin: nil)]
        let m = make(d)
        await m.load()
        XCTAssertEqual(m.blockedCount, 1)
    }

    /// Ruling J: the bootstrap entries go to the core as they are, and a
    /// failure is said, not taken for "nothing to restore".
    func testResetDefaultsSendsTheBootstrapEntries() async {
        let d = FakeDevice()
        d.resetDefaultsResult = 2
        let m = make(d)
        let n = await m.resetDefaults(info: ["BarkingBootstrapNodes": "\(Self.idA)@1.2.3.4:7700, \(Self.idB)@5.6.7.8:7700"])
        XCTAssertEqual(n, 2)
        XCTAssertEqual(d.resetCalls, [["\(Self.idA)@1.2.3.4:7700", "\(Self.idB)@5.6.7.8:7700"]])
        XCTAssertNil(m.resetError)
    }

    func testResetDefaultsFailureIsShown() async {
        let d = FakeDevice()
        d.resetDefaultsError = NSError(domain: "test", code: 1)
        let m = make(d)
        let n = await m.resetDefaults(info: ["BarkingBootstrapNodes": "\(Self.idA)@1.2.3.4:7700"])
        XCTAssertEqual(n, 0)
        XCTAssertNotNil(m.resetError)
    }

    func testResetConfirmationCountsTheNodes() throws {
        let fr = try lang("fr")
        XCTAssertEqual(flat(NodeLabels.resetMessage(3, lang: fr)),
                       "Les 3 nœuds fournis avec Barking que tu as retirés reviennent dans la liste. Les nœuds bloqués restent bloqués.")
        XCTAssertEqual(flat(NodeLabels.resetMessage(1, lang: fr)),
                       "Le nœud fourni avec Barking que tu as retiré revient dans la liste. Les nœuds bloqués restent bloqués.")
    }
}
