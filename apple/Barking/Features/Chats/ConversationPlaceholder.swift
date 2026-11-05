import BarkingKit
import SwiftUI

/// Replaced by the conversation screen (Task 9).
struct ConversationView: View {
    let core: CoreService
    let contact: String
    var body: some View { Text(verbatim: contact) }
}
