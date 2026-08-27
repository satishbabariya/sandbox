import Foundation

/// A one-way flag set from a signal handler and read from the main flow.
///
/// A signal arrives on another thread, so the two sides need to agree without
/// tearing. It only ever goes from false to true, which is why nothing here
/// needs to be more elaborate than a lock.
public final class InterruptFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false

    public init() {}

    public func set() {
        lock.lock()
        value = true
        lock.unlock()
    }

    public var isSet: Bool {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}
