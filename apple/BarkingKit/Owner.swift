import Foundation
import LocalAuthentication

/// Checks that the owner holds the phone before a sensitive step (phrase
/// export, removing a device, leaving the account).
public enum Owner {
    /// Face ID, Touch ID or the passcode. A phone with no passcode has
    /// nothing to check. `reason` is shown by Touch ID and the passcode screen.
    public static func check(reason: String = String(localized: "Confirm it is you")) async -> Bool {
        #if BARKING_DEV
        if ProcessInfo.processInfo.arguments.contains("-BarkingUITestReset") { return true }
        #endif
        let ctx = LAContext()
        var error: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            return (error as? LAError)?.code == .passcodeNotSet
        }
        return (try? await ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)) ?? false
    }
}
