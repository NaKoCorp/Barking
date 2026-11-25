import SwiftUI

/// The small sheet an ⓘ of the node's detail opens (spec §7.3): a title
/// and one or two sentences in plain words, at medium height. It scrolls,
/// so the longest text is never cut at the largest sizes.
struct NodeExplainSheet: View {
    let topic: ExplainTopic
    var mismatch = false
    var unknownPushLink = false
    @Environment(\.dismiss) private var dismiss
    @Environment(\.locale) private var locale

    var body: some View {
        let lang = NodeLabels.Lang.of(locale)
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: Space.s3) {
                    // In the content, not the bar: a bar title is cut at large sizes.
                    Text(verbatim: NodeLabels.explainTitle(topic, lang: lang))
                        .font(BarkingFont.mono(.headline, size: 17, weight: .semibold)).foregroundStyle(Color.fg)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityAddTraits(.isHeader)
                    ForEach(NodeLabels.explainText(topic, mismatch: mismatch, unknownPushLink: unknownPushLink,
                                                   lang: lang), id: \.self) { paragraph in
                        Text(verbatim: paragraph).font(.bBody).foregroundStyle(Color.fg)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, Space.gutter)
                .padding(.vertical, Space.s4)
            }
            .background(Color.surface)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }.accessibilityIdentifier("explain.close")
                }
            }
        }
        .presentationDetents([.medium])
        .presentationBackground(Color.surface)
        .accessibilityIdentifier("explain.\(topic.rawValue)")
    }
}
