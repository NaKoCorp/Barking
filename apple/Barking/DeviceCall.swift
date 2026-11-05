import UIKit

/// Every device call of the app goes through here: off the main thread,
/// inside a background task, so that a call started before suspension ends
/// and releases the database lock before iOS suspends the app (spec iOS
/// foundations §3.3: otherwise iOS kills the app, `0xdead10cc`).
enum DeviceCall {
    static func run<T: Sendable>(_ name: String, _ body: @escaping @Sendable () throws -> T) async throws -> T {
        let task = await UIApplication.shared.beginBackgroundTask(withName: name)
        defer { Task { @MainActor in UIApplication.shared.endBackgroundTask(task) } }
        return try await Task.detached(priority: .userInitiated) { try body() }.value
    }
}
