import Foundation

/// Line-delimited JSON over a unix socket, spoken between the CLI and the
/// supervisor process holding a sandbox's VM.
///
/// Deliberately small. The supervisor is a trust boundary of sorts — it holds a
/// VM with a policy attached — so the surface it exposes is a handful of
/// message types rather than anything general.
public enum ControlRequest: Codable, Sendable, Equatable {
    /// Run a command inside the running sandbox.
    case exec(command: [String], environment: [String: String], workingDirectory: String?)
    /// Run a command with a PTY attached, so an interactive shell works.
    case execTTY(
        command: [String], environment: [String: String], workingDirectory: String?,
        rows: UInt16, columns: UInt16)
    /// A chunk of the caller's stdin, base64 encoded, for an interactive exec.
    case input(base64: String)
    /// The caller's terminal changed size.
    case resize(rows: UInt16, columns: UInt16)
    /// The caller closed stdin.
    case closeInput
    /// Report what the supervisor is holding.
    case info
    /// Shut the sandbox down.
    case stop
    /// Read back policy decisions recorded so far.
    case policyLog
    /// Copy a host path into the sandbox. Both paths are resolved by the
    /// supervisor, which runs on the host, so no file bytes cross this socket.
    case copyIn(hostPath: String, guestPath: String)
    /// Copy a sandbox path out to the host.
    case copyOut(guestPath: String, hostPath: String)
    /// Quiesce the filesystem and copy it to `destination` on the host.
    case snapshot(destination: String)
}

public enum ControlResponse: Codable, Sendable, Equatable {
    case started(pid: Int32)
    /// A chunk of the guest process's output. Base64 so arbitrary bytes cannot
    /// break the line framing.
    case output(stream: OutputStream, base64: String)
    case exited(status: Int32)
    case info(SandboxInfo)
    case policyLog([PolicyAuditRecord])
    case failure(String)
    case copied
    case snapshotted
}

public enum OutputStream: String, Codable, Sendable, Equatable {
    case stdout
    case stderr
}

public struct SandboxInfo: Codable, Sendable, Equatable {
    public var name: String
    public var image: String
    public var allow: [String]
    public var deny: [String]
    public var guestAddress: String
    public var gatewayAddress: String

    public init(
        name: String, image: String, allow: [String], deny: [String],
        guestAddress: String, gatewayAddress: String
    ) {
        self.name = name
        self.image = image
        self.allow = allow
        self.deny = deny
        self.guestAddress = guestAddress
        self.gatewayAddress = gatewayAddress
    }
}

/// Framing for the control socket: one JSON object per line.
public enum ControlCodec {
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        var data = try JSONEncoder().encode(value)
        data.append(UInt8(ascii: "\n"))
        return data
    }

    public static func decode<T: Decodable>(_ type: T.Type, from line: Data) throws -> T {
        try JSONDecoder().decode(type, from: line)
    }
}

/// Reads newline-delimited JSON from a file descriptor.
public struct LineReader {
    private let fd: Int32
    private var buffer = Data()

    public init(fd: Int32) {
        self.fd = fd
    }

    /// Returns the next line, or nil at end of stream.
    public mutating func next() -> Data? {
        while true {
            if let index = buffer.firstIndex(of: UInt8(ascii: "\n")) {
                let line = buffer[buffer.startIndex..<index]
                buffer = Data(buffer[buffer.index(after: index)...])
                return Data(line)
            }
            var chunk = [UInt8](repeating: 0, count: 8192)
            let n = read(fd, &chunk, chunk.count)
            guard n > 0 else {
                // Flush a trailing line with no terminator.
                if !buffer.isEmpty {
                    let line = buffer
                    buffer = Data()
                    return line
                }
                return nil
            }
            buffer.append(contentsOf: chunk[0..<n])
        }
    }
}
