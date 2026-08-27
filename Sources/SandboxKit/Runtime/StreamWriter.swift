import Containerization
import Foundation

/// Forwards a guest stream to a host file handle.
///
/// Writes are serialised because the guest's stdout and stderr arrive on
/// separate tasks and would otherwise interleave mid-line.
public final class StreamWriter: Writer, @unchecked Sendable {
    private let handle: FileHandle
    private let lock = NSLock()

    public init(_ handle: FileHandle) {
        self.handle = handle
    }

    public static var standardOutput: StreamWriter { StreamWriter(.standardOutput) }
    public static var standardError: StreamWriter { StreamWriter(.standardError) }

    public func write(_ data: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        try handle.write(contentsOf: data)
    }

    public func close() throws {
        // stdout and stderr belong to the process, not to us; closing them
        // would silence everything printed after the sandbox exits.
    }
}

/// Collects a guest stream in memory. Used by tests that assert on output.
public final class BufferWriter: Writer, @unchecked Sendable {
    private var storage = Data()
    private let lock = NSLock()

    public init() {}

    public var data: Data {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    public var text: String {
        String(decoding: data, as: UTF8.self)
    }

    public func write(_ data: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        storage.append(data)
    }

    public func close() throws {}
}
