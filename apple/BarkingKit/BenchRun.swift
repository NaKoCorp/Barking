import Foundation

/// The extension's work, measured step by step (spec iOS foundations §6):
/// key and database, quick sync. The app's bench button runs the same code.
public enum BenchRun {
    /// `record.outcome` is empty when the sync reached the network: the
    /// caller sets it from what the notification shows.
    /// The extension's budget (`Budget`): one lock wait, the quick sync
    /// gets what is left of the work time.
    public static func run(source: String) -> (BenchRecord, SyncSummary?) {
        let start = DispatchTime.now()
        let startedAt = Date()
        let sampler = FootprintSampler()
        sampler.start()
        var steps: [BenchRecord.Step] = []
        func mark(_ name: String) {
            steps.append(.init(name: name, atMs: elapsedMs(since: start), footprintBytes: Footprint.current()))
        }
        mark("start")
        var outcome = ""
        var summary: SyncSummary?
        do {
            if let device = try DeviceFactory.existing(lockTimeoutMs: Budget.extensionLockMs) {
                mark("opened")
                let left = Budget.quickSyncDeadline(elapsedMs: elapsedMs(since: start) + Budget.extensionLockMs)
                let s = try device.quickSync(deadlineMs: left)
                mark("fetched")
                summary = s
                if !s.networkUp { outcome = "network-down" }
            } else {
                outcome = "no-key"
            }
        } catch BarkingError.Locked {
            outcome = "locked"
        } catch {
            outcome = "error"
        }
        mark("ready")
        let record = BenchRecord(
            source: source, device: model(), startedAt: startedAt, steps: steps,
            peakBytes: sampler.stop(), totalMs: elapsedMs(since: start), outcome: outcome)
        return (record, summary)
    }

    static func elapsedMs(since start: DispatchTime) -> UInt64 {
        (DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000
    }

    static func model() -> String {
        var u = utsname()
        uname(&u)
        return withUnsafeBytes(of: u.machine) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
    }
}
