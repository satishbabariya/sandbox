import Containerization
import Foundation

/// Feeds a guest process's stdin from data arriving elsewhere.
///
/// An interactive `exec` reads the caller's keystrokes off the control socket
/// in the supervisor, then has to hand them to a process that expects a
/// `ReaderStream`. This bridges the two.
public final class PipedInput: ReaderStream, @unchecked Sendable {
    private let continuation: AsyncStream<Data>.Continuation
    private let underlying: AsyncStream<Data>

    public init() {
        // Buffer rather than drop: a paste is a burst of input, and losing part
        // of it would silently corrupt what the user typed.
        var capturedContinuation: AsyncStream<Data>.Continuation?
        underlying = AsyncStream(bufferingPolicy: .unbounded) { continuation in
            capturedContinuation = continuation
        }
        guard let capturedContinuation else {
            fatalError("AsyncStream did not provide a continuation")
        }
        continuation = capturedContinuation
    }

    public func stream() -> AsyncStream<Data> { underlying }

    public func send(_ data: Data) {
        continuation.yield(data)
    }

    /// Signal end of input, which lets the guest process see EOF on stdin.
    public func finish() {
        continuation.finish()
    }
}
