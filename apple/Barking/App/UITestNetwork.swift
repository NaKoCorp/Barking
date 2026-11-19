#if BARKING_DEV
import Foundation

/// A UI test launch (`BARKING_UI_TEST=1` in its environment, relaunches
/// included) stays off the network the build was configured with: no
/// bootstrap node, no push relay, whatever the developer's `Local.xcconfig`
/// holds. CI builds have none, so local runs then behave like CI.
enum UITestNetwork {
    static let environmentKey = "BARKING_UI_TEST"
    static var isolated: Bool { ProcessInfo.processInfo.environment[environmentKey] == "1" }
}
#endif
