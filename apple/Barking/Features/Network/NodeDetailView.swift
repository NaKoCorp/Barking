import BarkingKit
import SwiftUI

/// A node's detail (node transparency spec §7.2): where it runs (declared
/// against observed), what it does, how it behaves with this iPhone, its
/// addresses, then "Remove" and "Block" in a danger zone. Every value has
/// its plain sentence, under it or behind an ⓘ (§7.3); pull to refresh asks
/// the node again.
struct NodeDetailView: View {
    let core: CoreService
    @State private var model: NodeDetailModel
    @State private var explaining: ExplainTopic?
    @State private var confirmingBlock = false
    @State private var confirmingRemove = false
    @State private var sharing: AppRouter.RelayLink?
    @State private var copied = false
    @Environment(\.dismiss) private var dismiss
    @Environment(\.locale) private var locale
    @Environment(\.colorScheme) private var scheme

    init(core: CoreService, id: String) {
        self.core = core
        _model = State(initialValue: NodeDetailModel(core: core, id: id))
    }

    private var lang: NodeLabels.Lang { .of(locale) }

    private func s(_ key: String.LocalizationValue) -> String {
        String(localized: key, bundle: .strings(for: locale), locale: locale)
    }

    var body: some View {
        Group {
            header
            if let node = model.node {
                whereItRuns(node)
                whatItDoes
                withThisIPhone(node)
                addresses(node)
                dangerZone(node)
            } else if model.missing {
                Text("This node is no longer in the list.").font(.bBody).foregroundStyle(Color.fgMuted)
            }
        }
        // The tab bar stays visible over this pushed screen: room for it.
        .barkingScreen(tabRoot: true)
        .refreshable { await model.refresh() }
        // The host is the screen's title already: the bar says what it is.
        .navigationTitle(Text("Node"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if let node = model.node, !node.addr.isEmpty {
                ToolbarItem(placement: .primaryAction) {
                    Button { sharing = AppRouter.RelayLink(id: node.id, addr: node.addr) } label: {
                        Label("Share this relay", systemImage: "square.and.arrow.up")
                    }
                    .accessibilityIdentifier("node.share")
                }
            }
        }
        .task { await model.load() }
        .sheet(item: $explaining) { topic in
            NodeExplainSheet(topic: topic, mismatch: model.isMismatch,
                             unknownPushLink: model.detail?.report?.pushLink == .unknown)
        }
        .sheet(item: $sharing) { r in RelayCodeSheet(relay: r) { sharing = nil } }
        .confirmationDialog(Text("Block this node?"), isPresented: $confirmingBlock, titleVisibility: .visible) {
            Button("Block", role: .destructive) { Task { await block() } }
                .accessibilityIdentifier("node.block.confirm")
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(verbatim: NodeLabels.blockMessage(usableLeft: model.blockWarning, lang: lang))
        }
        .confirmationDialog(Text("Remove this node?"), isPresented: $confirmingRemove, titleVisibility: .visible) {
            Button("Remove", role: .destructive) { Task { await remove() } }
                .accessibilityIdentifier("node.remove.confirm")
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(verbatim: NodeLabels.removeMessage(model.node?.kind ?? .manual, lang: lang))
        }
    }

    // MARK: Header

    /// The host (or short id) and the whole identifier in groups of four,
    /// with a copy button; "unreachable" when the node didn't answer.
    private var header: some View {
        VStack(alignment: .leading, spacing: Space.s2) {
            ScreenTitle(verbatim: model.node.map(NodeLabels.name) ?? NodeLabels.shortId(model.id), size: 22)
            HStack(alignment: .firstTextBaseline, spacing: Space.s2) {
                Text(verbatim: Self.grouped(model.id))
                    .font(BarkingFont.mono(.caption, size: 12)).foregroundStyle(Color.fgMuted)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityLabel(Text("Identifier \(NodeLabels.shortId(model.id))"))
                Button {
                    UIPasteboard.general.string = model.id
                    copied = true
                    Haptic.success.play()
                } label: {
                    Image(systemName: copied ? "checkmark" : "doc.on.doc")
                        .font(.bSymbol(13, relativeTo: .footnote, maximum: 22))
                        .foregroundStyle(Color.accent)
                        .frame(minWidth: 44, minHeight: 44)
                        .contentShape(.rect)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(Text(copied ? "Identifier copied" : "Copy the identifier"))
                .accessibilityIdentifier("node.copy")
            }
            if model.unreachable {
                StatusDot(.waiting, label: "Unreachable right now · last known details")
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("node.unreachable")
            }
        }
    }

    /// "A7KQ 2M9F …" in groups of four, so it can be read out.
    static func grouped(_ id: String) -> String {
        stride(from: 0, to: id.count, by: 4).map { i -> String in
            let start = id.index(id.startIndex, offsetBy: i)
            let end = id.index(start, offsetBy: 4, limitedBy: id.endIndex) ?? id.endIndex
            return String(id[start..<end])
        }
        .joined(separator: " ")
    }

    // MARK: Where it runs

    /// The declared / observed table in the terminal block, then the
    /// verdict: a line, or an amber banner when they differ.
    private func whereItRuns(_ node: NodeInfo) -> some View {
        VStack(alignment: .leading, spacing: Space.s2) {
            // On the label alone: on the card it would name every row in it.
            SectionLabel("Where it runs").accessibilityIdentifier("node.origin")
            Card {
                VStack(alignment: .leading, spacing: Space.s3) {
                    if !model.originRows.isEmpty { originTable }
                    verdict
                }
            }
            TextLink("What does it mean?", glyph: "ⓘ") { explaining = .origin }
                .accessibilityIdentifier("node.explain.origin")
        }
    }

    private func rowLabel(_ kind: NodeDetailModel.OriginRow.Kind) -> String {
        kind == .asn ? "AS" : s("country")
    }

    private func markWord(_ mark: NodeDetailModel.OriginRow.Mark) -> String {
        switch mark {
        case .same: s("same")
        case .differs: s("different")
        case .unknown: s("not checked")
        }
    }

    /// Three columns while they fit, else one block per row (large text).
    private var originTable: some View {
        let rows = model.originRows
        let header = (s("declared"), s("observed"))
        return ViewThatFits(in: .horizontal) {
            Grid(alignment: .leading, horizontalSpacing: Space.s4, verticalSpacing: Space.s2) {
                GridRow {
                    Text(verbatim: "")
                    Text(verbatim: header.0).foregroundStyle(Color.terminalFg.opacity(0.75))
                    Text(verbatim: header.1).foregroundStyle(Color.terminalFg.opacity(0.75))
                    Text(verbatim: "")
                }
                .accessibilityHidden(true)
                ForEach(rows, id: \.kind) { row in
                    GridRow {
                        Text(verbatim: rowLabel(row.kind)).foregroundStyle(Color.terminalFg.opacity(0.75))
                        Text(verbatim: row.declared)
                        Text(verbatim: row.observed)
                        Text(verbatim: row.mark.glyph).font(.bSymbol(12, relativeTo: .caption, weight: .bold))
                    }
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel(Text(verbatim: originAccessibility(row, header)))
                }
            }
            .fixedSize()
            VStack(alignment: .leading, spacing: Space.s3) {
                ForEach(rows, id: \.kind) { row in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(verbatim: "\(rowLabel(row.kind)) \(row.mark.glyph)")
                            .foregroundStyle(Color.terminalFg.opacity(0.75))
                        Text(verbatim: "\(header.0) \(row.declared)")
                        Text(verbatim: "\(header.1) \(row.observed)")
                    }
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel(Text(verbatim: originAccessibility(row, header)))
                }
            }
        }
        .font(BarkingFont.mono(.footnote, size: 13))
        .foregroundStyle(Color.terminalFg)
        .padding(12).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.terminalBg, in: .rect(cornerRadius: Radius.card))
        .overlay {
            // On Ink the block keeps an edge of its own (as the sync card's).
            if scheme == .dark {
                RoundedRectangle(cornerRadius: Radius.card).strokeBorder(Color.accent.opacity(0.3), lineWidth: 1)
            }
        }
    }

    private func originAccessibility(_ row: NodeDetailModel.OriginRow, _ header: (String, String)) -> String {
        [rowLabel(row.kind), "\(header.0) \(row.declared)", "\(header.1) \(row.observed)", markWord(row.mark)]
            .joined(separator: ", ")
    }

    @ViewBuilder private var verdict: some View {
        let line = model.verdictLine(lang: lang)
        if model.isMismatch {
            // Attention, not danger: the bases lag, nothing is punished (§6.3).
            HStack(alignment: .top, spacing: 10) {
                Text(verbatim: NodeRow.verdictGlyph(.waiting)).font(.bSymbol(13, relativeTo: .footnote, weight: .bold))
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(verbatim: line.text).fontWeight(.semibold)
                    Text(verbatim: NodeLabels.mismatchAdvice(lang: lang))
                }
                .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
            }
            .font(.bBodySmall)
            .foregroundStyle(Color.warnFg)
            .padding(12)
            .background(Color.warnBg, in: .rect(cornerRadius: Radius.chip))
            .overlay(RoundedRectangle(cornerRadius: Radius.chip).stroke(Color.warnBorder, lineWidth: 1))
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("node.mismatch")
        } else {
            StatusDot(line.state, verbatim: line.text)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("node.verdict")
        }
    }

    // MARK: What it does

    private var whatItDoes: some View {
        VStack(alignment: .leading, spacing: Space.s2) {
            SectionLabel("What it does")
            FormCard {
                switch model.activity {
                case .report(let r):
                    InfoRow(label: s("Fill"), value: NodeLabels.fillWord(r.storage, lang: lang),
                            explain: { explaining = .fill }, identifier: "node.fill") {
                        TierValue(tier: r.storage, word: NodeLabels.fillWord(r.storage, lang: lang))
                    }
                    if let wake = r.wake {
                        InfoRow(label: s("Subscriptions"), value: NodeLabels.fillWord(wake, lang: lang),
                                explain: { explaining = .subscriptions }, identifier: "node.subscriptions") {
                            TierValue(tier: wake, word: NodeLabels.fillWord(wake, lang: lang))
                        }
                    }
                    if model.showsPushLink, let link = r.pushLink {
                        let line = NodeLabels.pushLinkLine(link, lang: lang)
                        InfoRow(label: s("Push relay"), value: line.text, explain: { explaining = .pushLink },
                                identifier: "node.pushLink") {
                            StatusDot(line.state, verbatim: line.text)
                        }
                    }
                    InfoRow(label: s("Version"), value: NodeLabels.version(r, lang: lang), identifier: "node.version") {
                        MonoValue(text: NodeLabels.version(r, lang: lang))
                    }
                case .asking:
                    InfoRow(label: s("Asking the node…"), value: "", identifier: "node.asking") {
                        ProgressView().controlSize(.small)
                    }
                case .notShared(let old):
                    // A plain muted line, not a row title: there is no value.
                    StatusDot(.checking, verbatim: NodeLabels.notShared(olderThan05: old, lang: lang))
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                        .padding(.horizontal, FormRowMetrics.inset)
                        .padding(.vertical, Space.s2)
                        .accessibilityIdentifier("node.notShared")
                }
            }
        }
    }

    // MARK: With this iPhone

    private func withThisIPhone(_ node: NodeInfo) -> some View {
        let word = NodeLabels.reliabilityWord(node.reliability, lang: lang)
        let sentence = NodeLabels.reliabilitySentence(node.reliability, lang: lang)
        let latency = node.latencyMs.map { NodeLabels.latency(ms: $0, lang: lang) } ?? s("not measured yet")
        let lastSeen = NodeLabels.lastSeen(node.lastSeen, now: .now, lang: lang)
        let origin = NodeLabels.originKind(node.kind, lang: lang)
        let subs = String(node.mySubscriptions)
        return VStack(alignment: .leading, spacing: Space.s2) {
            SectionLabel("With this iPhone")
            FormCard {
                InfoRow(label: s("Reliability"), value: word, sentence: sentence,
                        explain: { explaining = .reliability }, identifier: "node.reliability") {
                    StatusDot(NodeLabels.reliabilityState(node.reliability), verbatim: word)
                }
                InfoRow(label: s("Latency"), value: latency, explain: { explaining = .latency },
                        identifier: "node.latency") { MonoValue(text: latency) }
                InfoRow(label: s("Origin"), value: origin, identifier: "node.kind") { MonoValue(text: origin) }
                InfoRow(label: s("Last answer"), value: lastSeen, identifier: "node.lastSeen") {
                    MonoValue(text: lastSeen)
                }
                InfoRow(label: s("My subscriptions"), value: subs, explain: { explaining = .mySubscriptions },
                        identifier: "node.mySubscriptions") { MonoValue(text: subs) }
            }
        }
    }

    // MARK: Addresses

    private func addresses(_ node: NodeInfo) -> some View {
        let rows: [(String, String)] = [("IPv4", model.detail?.v4), ("IPv6", model.detail?.v6)]
            .compactMap { label, addr in addr.map { (label, $0) } }
        let shown = rows.isEmpty && !node.addr.isEmpty ? [(s("Address"), node.addr)] : rows
        return Group {
            if !shown.isEmpty {
                VStack(alignment: .leading, spacing: Space.s2) {
                    SectionLabel("Addresses")
                    FormCard {
                        ForEach(Array(shown.enumerated()), id: \.offset) { _, row in
                            InfoRow(label: row.0, value: row.1, identifier: "node.addr.\(row.0)") {
                                MonoValue(text: row.1)
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: Danger zone

    private func dangerZone(_ node: NodeInfo) -> some View {
        DangerZone {
            if model.canRemove {
                DangerButton("Remove", identifier: "node.remove", enabled: !model.blocking) { confirmingRemove = true }
            }
            DangerButton("Block this node", identifier: "node.block", enabled: !model.blocking) {
                Task {
                    // The guard-rail is read at the tap, then the question (§6.4).
                    await model.checkBlock()
                    confirmingBlock = true
                }
            }
            if model.blocking {
                StatusDot(.checking, label: "Blocking…").accessibilityIdentifier("node.blocking")
            }
            if model.actionFailed { Banner(kind: .danger, title: "Not saved. Try again.") }
        }
    }

    /// Haptic, then back to the list: the node has left it.
    private func block() async {
        if await model.block() {
            Haptic.success.play()
            AccessibilityNotification.Announcement(s("Node blocked")).post()
            dismiss()
        } else {
            Haptic.error.play()
        }
    }

    private func remove() async {
        if await model.remove() {
            Haptic.success.play()
            dismiss()
        } else {
            Haptic.error.play()
        }
    }
}

/// One row of the detail: a label, its value (a word, segments, a dot),
/// the plain sentence under it when there is one, and an ⓘ when it can be
/// explained. One VoiceOver element: label and value, then the sentence;
/// with an ⓘ the whole row is the button that opens it (44 pt).
private struct InfoRow<Value: View>: View {
    let label: String
    let value: String
    var sentence: String?
    var explain: (() -> Void)?
    let identifier: String
    @ViewBuilder let content: Value

    init(label: String, value: String, sentence: String? = nil, explain: (() -> Void)? = nil, identifier: String,
         @ViewBuilder content: () -> Value) {
        self.label = label
        self.value = value
        self.sentence = sentence
        self.explain = explain
        self.identifier = identifier
        self.content = content()
    }

    private var spoken: String {
        [label, value.isEmpty ? nil : value, sentence].compactMap { $0 }.joined(separator: ", ")
    }

    var body: some View {
        if let explain {
            Button(action: explain) { row }
                .buttonStyle(.plain)
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(Text(verbatim: spoken))
                .accessibilityHint(Text("Explains this"))
                .accessibilityAddTraits(.isButton)
                .accessibilityIdentifier(identifier)
        } else {
            row
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(Text(verbatim: spoken))
                .accessibilityIdentifier(identifier)
        }
    }

    private var row: some View {
        HStack(alignment: .firstTextBaseline, spacing: Space.s2) {
            VStack(alignment: .leading, spacing: Space.s1) {
                ViewThatFits(in: .horizontal) {
                    HStack(alignment: .firstTextBaseline, spacing: Space.s3) {
                        title.lineLimit(1)
                        Spacer(minLength: Space.s2)
                        content.fixedSize()
                    }
                    VStack(alignment: .leading, spacing: Space.s1) {
                        title.fixedSize(horizontal: false, vertical: true)
                        content.fixedSize(horizontal: false, vertical: true)
                    }
                }
                if let sentence {
                    Text(verbatim: sentence).font(.bBodySmall).foregroundStyle(Color.fgMuted)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            if explain != nil {
                Image(systemName: "info.circle")
                    .font(.bSymbol(15, relativeTo: .subheadline, maximum: 24))
                    .foregroundStyle(Color.accent)
            }
        }
        .padding(.horizontal, FormRowMetrics.inset)
        .padding(.vertical, Space.s3)
        .frame(minHeight: 44)
        .contentShape(.rect)
    }

    private var title: some View {
        Text(verbatim: label).font(.bBody.weight(.semibold)).foregroundStyle(Color.fg)
    }
}

/// A value in Fira Code, wrapping when long (an IPv6 address).
private struct MonoValue: View {
    let text: String

    var body: some View {
        Text(verbatim: text).font(BarkingFont.mono(.footnote, size: 13)).foregroundStyle(Color.fg)
            .multilineTextAlignment(.leading)
    }
}

/// A tier as 4 segments and its word: never a percentage (§7.2). The
/// segments are drawing only; the word carries the value.
private struct TierValue: View {
    let tier: FillTierView
    let word: String
    @ScaledMetric(relativeTo: .footnote) private var height: CGFloat = 10
    @ScaledMetric(relativeTo: .footnote) private var width: CGFloat = 7

    var body: some View {
        HStack(alignment: .center, spacing: Space.s2) {
            HStack(spacing: 2) {
                ForEach(0..<4, id: \.self) { i in
                    RoundedRectangle(cornerRadius: 1.5)
                        .fill(i < NodeLabels.fillSegments(tier) ? Color.fg : Color.border)
                        .frame(width: min(width, 14), height: min(height, 20))
                }
            }
            .accessibilityHidden(true)
            Text(verbatim: word).font(BarkingFont.mono(.footnote, size: 13)).foregroundStyle(Color.fg)
        }
    }
}
