import Darwin
import Foundation

/// Memory the system charges to this process (`phys_footprint`): what the
/// extension limit is measured against (spec iOS foundations §6.1).
public enum Footprint {
    public static func current() -> UInt64 {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        return kr == KERN_SUCCESS ? info.phys_footprint : 0
    }
}

/// Highest footprint seen while running, sampled on a timer.
public final class FootprintSampler: @unchecked Sendable {
    private let interval: DispatchTimeInterval
    private let queue = DispatchQueue(label: "barking.footprint")
    private var timer: DispatchSourceTimer?
    private var peak: UInt64 = 0

    public init(interval: Duration = .milliseconds(50)) {
        let ms = interval.components.seconds * 1000 + interval.components.attoseconds / 1_000_000_000_000_000
        self.interval = .milliseconds(Int(max(ms, 1)))
    }

    public func start() {
        queue.sync {
            peak = Footprint.current()
            let t = DispatchSource.makeTimerSource(queue: queue)
            t.schedule(deadline: .now(), repeating: interval)
            t.setEventHandler { [unowned self] in peak = max(peak, Footprint.current()) }
            t.resume()
            timer = t
        }
    }

    /// Stops sampling; returns the peak, current value included.
    public func stop() -> UInt64 {
        queue.sync {
            timer?.cancel()
            timer = nil
            peak = max(peak, Footprint.current())
            return peak
        }
    }
}
