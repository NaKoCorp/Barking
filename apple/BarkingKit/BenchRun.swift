import Foundation

/// The extension's work, measured step by step (spec iOS foundations §6):
/// key and database, quick sync. The app's bench button runs the same code.
public enum BenchRun {
    /// `record.outcome` is empty when the sync reached the network: the
    /// caller sets it from what the notification shows.
    /// The extension's budget (`Budget`): one lock wait, the quick sync
    /// gets what is left of the work time. `sync: false` stops once the
    /// device is opened (outcome `opened`): key and open timings only.
    public static func run(source: String, paths: WipePaths = .live, sync: Bool = true) -> (BenchRecord, SyncSummary?) {
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
        var unwrapMs: UInt64?
        do {
            if Wipe.isPending(paths: paths) {
                // A wipe is under way: the push goes out as it came.
                outcome = wipePending
            } else {
                let before = elapsedMs(since: start)
                let device = try DeviceFactory.existing(lockTimeoutMs: Budget.extensionLockMs, paths: paths) {
                    unwrapMs = elapsedMs(since: start) - before
                    mark("key")
                }
                if let device {
                    mark("opened")
                    if sync {
                        let left = Budget.quickSyncDeadline(elapsedMs: elapsedMs(since: start) + Budget.extensionLockMs)
                        let s = try device.quickSync(deadlineMs: left)
                        mark("fetched")
                        summary = s
                        if !s.networkUp { outcome = "network-down" }
                    } else {
                        outcome = "opened"
                    }
                } else {
                    outcome = "no-key"
                }
            }
        } catch BarkingError.Locked {
            outcome = "locked"
        } catch {
            outcome = "error"
        }
        mark("ready")
        let record = BenchRecord(
            source: source, device: model(), startedAt: startedAt, steps: steps,
            peakBytes: sampler.stop(), totalMs: elapsedMs(since: start), outcome: outcome,
            unwrapMs: unwrapMs)
        return (record, summary)
    }

    /// `outcome` of a run skipped because a wipe is under way: nothing is
    /// recorded either (no new file in a container being erased).
    public static let wipePending = "wipe-pending"

    static func elapsedMs(since start: DispatchTime) -> UInt64 {
        (DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000
    }

    static func model() -> String {
        var u = utsname()
        uname(&u)
        return withUnsafeBytes(of: u.machine) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
    }
}
