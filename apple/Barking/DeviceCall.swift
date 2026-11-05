import BarkingKit
import UIKit

/// Every device call of the app goes through here: off the main thread,
/// inside a background task, so that a call started before suspension ends
/// and releases the database lock before iOS suspends the app (spec iOS
/// foundations §3.3: otherwise iOS kills the app, `0xdead10cc`). Calls fit
/// the background time (`Budget`).
enum DeviceCall {
    static func run<T: Sendable>(_ name: String, _ body: @escaping @Sendable () throws -> T) async throws -> T {
        let task = await BackgroundTask(name: name)
        defer { Task { @MainActor in task.end() } }
        return try await Task.detached(priority: .userInitiated) { try body() }.value
    }
}

/// A background task ended once: by the call, or by iOS's expiration
/// handler if it cuts the time shorter.
@MainActor
private final class BackgroundTask {
    private var id: UIBackgroundTaskIdentifier = .invalid

    init(name: String) {
        id = UIApplication.shared.beginBackgroundTask(withName: name) { [weak self] in
            MainActor.assumeIsolated { self?.end() }
        }
    }

    func end() {
        guard id != .invalid else { return }
        UIApplication.shared.endBackgroundTask(id)
        id = .invalid
    }
}

/// The app's runner for `CoreService`: every call through `DeviceCall`.
struct AppCallRunner: CallRunner {
    func run<T: Sendable>(_ name: String, _ body: @escaping @Sendable () throws -> T) async throws -> T {
        try await DeviceCall.run(name, body)
    }
}
