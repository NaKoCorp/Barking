import SwiftUI

/// Settings › Licences: the attributions the bundled data and font ask for
/// (the IP base of node transparency spec §6.3, CC BY 4.0; Fira Code, OFL).
struct LicensesView: View {
    var body: some View {
        Group {
            FormCard {
                FormRow(title: Text("IP address base"),
                        subtitle: Text("IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0 license")) { EmptyView() }
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("licenses.ipdb")
                FormRow(title: Text("Fira Code font"), subtitle: Text(verbatim: "SIL Open Font License 1.1")) { EmptyView() }
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("licenses.font")
            }
        }
        .barkingScreen()
        .navigationTitle(Text("Licenses"))
        .toolbarTitleDisplayMode(.inline)
    }
}
