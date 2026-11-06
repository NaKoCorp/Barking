#if DEBUG
import SwiftUI

/// Shows a component in the four review conditions: Paper, Ink, French and
/// the AX3 text size (UI review §4).
struct PreviewMatrix<Content: View>: View {
    @ViewBuilder let content: () -> Content

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                pane("Paper") { content() }.environment(\.colorScheme, .light)
                pane("Ink") { content() }.environment(\.colorScheme, .dark)
                pane("FR") { content() }.environment(\.locale, Locale(identifier: "fr"))
                pane("AX3") { content() }.environment(\.dynamicTypeSize, .accessibility3)
            }
        }
    }

    private func pane(_ name: String, @ViewBuilder _ body: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(verbatim: name).font(.bMeta).foregroundStyle(Color.fgSoft)
            body()
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.surface)
    }
}
#endif
