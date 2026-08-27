import Containerization
import Foundation

/// A file writer that will not grow without limit.
///
/// A detached sandbox has no terminal, so everything the guest prints goes to a
/// file on the host. The guest decides how much that is: measured at 635 MB/s
/// from a shell loop, which fills a disk in minutes and does not need a
/// compromised agent to happen -- a program stuck printing in a retry loop will
/// do it by accident.
///
/// One generation back is kept, so the file the user reads holds recent output
/// and the total is bounded at twice the limit. Rotating rather than refusing
/// to write: console output is read to find out what an agent did, and stopping
/// at a limit would freeze it at the moment the flood started and hide
/// everything after it.
public final class RotatingFileWriter: Writer, @unchecked Sendable {
    /// The size one file may reach before it is rotated.
    public static let defaultLimit: Int64 = 32 << 20

    private let path: URL
    private let limit: Int64
    private let lock = NSLock()
    private var handle: FileHandle?
    private var written: Int64 = 0

    public init(path: URL, limit: Int64 = RotatingFileWriter.defaultLimit) throws {
        self.path = path
        self.limit = limit
        FileManager.default.createFile(atPath: path.path, contents: nil)
        self.handle = try FileHandle(forWritingTo: path)
        self.written =
            (try? FileManager.default.attributesOfItem(atPath: path.path)[.size] as? Int64)
            .flatMap { $0 } ?? 0
    }

    /// Where the previous generation is kept.
    public var rotatedPath: URL { path.appendingPathExtension("prev") }

    public func write(_ data: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        guard let handle else { return }
        try handle.write(contentsOf: data)
        written += Int64(data.count)
        if written >= limit { rotateLocked() }
    }

    /// Callers must hold the lock.
    private func rotateLocked() {
        try? handle?.close()
        handle = nil
        try? FileManager.default.removeItem(at: rotatedPath)
        try? FileManager.default.moveItem(at: path, to: rotatedPath)

        FileManager.default.createFile(atPath: path.path, contents: nil)
        // If the file cannot be reopened there is nothing useful to do: losing
        // the log is bad, and stopping the sandbox because of it is worse.
        handle = try? FileHandle(forWritingTo: path)
        written = 0
    }

    public func close() throws {
        lock.lock()
        defer { lock.unlock() }
        try? handle?.close()
        handle = nil
    }
}
