import BarkingKit
import SwiftUI

// Placeholders the "Internet relays" list navigates to (Task 9); Task 10
// replaces them with the node's detail screen (spec §7.2) and the blocked
// nodes list (§7.4).

struct NodeDetailView: View {
    let core: CoreService
    let id: String

    var body: some View {
        Text(verbatim: NodeLabels.shortId(id)).font(.bBody)
            .navigationTitle(Text("Node"))
    }
}

struct BlockedNodesView: View {
    let core: CoreService

    var body: some View {
        Text("Blocked nodes").font(.bBody)
    }
}
