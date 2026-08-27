import Foundation

/// A published port: a host address the gateway listens on, forwarded to a
/// port inside the sandbox.
///
/// Publishing does not widen egress. It opens a way *in* from the host, which
/// is the opposite direction from the policy the sandbox is under, and is what
/// lets you reach a dev server the agent started.
public struct PortForward: Codable, Sendable, Equatable, CustomStringConvertible {
    /// Host interface to bind. Loopback by default: a sandbox port should not
    /// become reachable from the local network by accident.
    public var hostAddress: String
    public var hostPort: UInt16
    public var guestPort: UInt16

    public init(hostAddress: String = "127.0.0.1", hostPort: UInt16, guestPort: UInt16) {
        self.hostAddress = hostAddress
        self.hostPort = hostPort
        self.guestPort = guestPort
    }

    public var description: String {
        "\(hostAddress):\(hostPort) -> \(guestPort)"
    }

    /// Parse `[[HOST:]HOSTPORT:]GUESTPORT`.
    ///
    /// `8080` publishes guest 8080 on host 8080; `3000:8080` maps host 3000 to
    /// guest 8080; `0.0.0.0:3000:8080` binds all interfaces, which the caller
    /// has to ask for explicitly.
    public static func parse(_ raw: String) throws -> PortForward {
        let parts = raw.split(separator: ":").map(String.init)

        func port(_ text: String) throws -> UInt16 {
            guard let value = UInt16(text), value > 0 else {
                throw PortForwardError.invalid(raw, reason: "port must be 1...65535")
            }
            return value
        }

        func hostPort(_ text: String) throws -> UInt16 {
            let value = try port(text)
            // Binding below 1024 needs root, and sandbox deliberately does not
            // run as root. Saying so here beats the gateway failing to bind.
            guard value >= 1024 else {
                throw PortForwardError.invalid(
                    raw,
                    reason:
                        "host port \(value) is privileged; ports below 1024 need root, pick 1024 or above"
                )
            }
            return value
        }

        switch parts.count {
        case 1:
            // A single port publishes the guest port on the same host port, so
            // it has to satisfy the host-side restriction too.
            let both = try hostPort(parts[0])
            return PortForward(hostPort: both, guestPort: both)
        case 2:
            return PortForward(hostPort: try hostPort(parts[0]), guestPort: try port(parts[1]))
        case 3:
            return PortForward(
                hostAddress: parts[0],
                hostPort: try hostPort(parts[1]),
                guestPort: try port(parts[2]))
        default:
            throw PortForwardError.invalid(
                raw, reason: "expected [[HOST:]HOSTPORT:]GUESTPORT")
        }
    }
}

public enum PortForwardError: Error, CustomStringConvertible {
    case invalid(String, reason: String)

    public var description: String {
        switch self {
        case .invalid(let raw, let reason):
            return "invalid port spec '\(raw)': \(reason)"
        }
    }
}
