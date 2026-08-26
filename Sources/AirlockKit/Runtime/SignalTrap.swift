import Darwin
import Dispatch
import Foundation

/// Catches the signals a user actually sends and lets the caller shut down.
///
/// Without this, Ctrl-C kills the CLI and leaves the gateway and the VM it was
/// holding running. That is a leak the user has no obvious way to notice, and
/// they will do it constantly.
public final class SignalTrap: @unchecked Sendable {
    private var sources: [DispatchSourceSignal] = []
    private let handler: @Sendable () -> Void

    public init(handler: @escaping @Sendable () -> Void) {
        self.handler = handler
    }

    /// Begin catching SIGINT and SIGTERM.
    ///
    /// The default disposition is ignored first, because a DispatchSource does
    /// not replace it — without this the process would still die on the
    /// default action before the handler ran.
    public func arm() {
        for number in [SIGINT, SIGTERM] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .global())
            source.setEventHandler { [handler] in handler() }
            source.resume()
            sources.append(source)
        }
    }

    public func disarm() {
        for source in sources {
            source.cancel()
        }
        sources.removeAll()
        // Restore the default so a second signal during a slow shutdown still
        // kills the process rather than being swallowed.
        for number in [SIGINT, SIGTERM] {
            signal(number, SIG_DFL)
        }
    }
}
