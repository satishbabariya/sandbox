import ContainerizationOS
import Darwin
import Foundation
import Synchronization

public enum ControlSocketError: Error, CustomStringConvertible {
    case failed(String, errno: Int32)
    case pathTooLong(String)
    case notRunning(String)

    public var description: String {
        switch self {
        case .failed(let op, let err):
            return "\(op): \(String(cString: strerror(err)))"
        case .pathTooLong(let path):
            return "socket path too long: \(path)"
        case .notRunning(let name):
            return "sandbox '\(name)' is not running"
        }
    }
}

enum UnixSocket {
    static func address(for url: URL) throws -> sockaddr_un {
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(url.path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            throw ControlSocketError.pathTooLong(url.path)
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: bytes)
            raw[bytes.count] = 0
        }
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        return addr
    }
}

/// Accepts control connections for one sandbox.
///
/// The socket is mode 0600 and lives under a directory only this user can
/// reach: anyone who can talk to it can run commands inside the sandbox, so it
/// is exactly as privileged as the user who started it and no more.
public final class ControlServer: @unchecked Sendable {
    private let path: URL
    private var fd: Int32 = -1
    private let handler: @Sendable (ControlRequest, Int32) async -> Void

    public init(
        path: URL,
        handler: @escaping @Sendable (ControlRequest, Int32) async -> Void
    ) {
        self.path = path
        self.handler = handler
    }

    public func start() throws {
        try? FileManager.default.removeItem(at: path)
        try FileManager.default.createDirectory(
            at: path.deletingLastPathComponent(), withIntermediateDirectories: true)

        let sock = socket(AF_UNIX, SOCK_STREAM, 0)
        guard sock >= 0 else { throw ControlSocketError.failed("socket", errno: errno) }

        var addr = try UnixSocket.address(for: path)
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(sock, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0 else {
            close(sock)
            throw ControlSocketError.failed("bind", errno: errno)
        }
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: path.path)

        guard listen(sock, 8) == 0 else {
            close(sock)
            throw ControlSocketError.failed("listen", errno: errno)
        }
        self.fd = sock
    }

    /// Serve until the task is cancelled.
    public func serve() async {
        while !Task.isCancelled {
            let client = accept(fd, nil, nil)
            guard client >= 0 else {
                if errno == EINTR { continue }
                break
            }
            var reader = LineReader(fd: client)
            guard let line = reader.next(),
                let request = try? ControlCodec.decode(ControlRequest.self, from: line)
            else {
                close(client)
                continue
            }
            await handler(request, client)
        }
    }

    public func stop() {
        if fd >= 0 { close(fd) }
        fd = -1
        try? FileManager.default.removeItem(at: path)
    }

    public static func send(_ response: ControlResponse, to client: Int32) {
        guard let data = try? ControlCodec.encode(response) else { return }
        _ = data.withUnsafeBytes { write(client, $0.baseAddress, $0.count) }
    }
}

/// Talks to a sandbox's supervisor.
public struct ControlClient: Sendable {
    private let path: URL

    public init(path: URL) {
        self.path = path
    }

    public static func path(for name: String, paths: SandboxPaths = SandboxPaths()) -> URL {
        paths.socketDirectory(name).appending(path: "control.sock")
    }

    private func connect() throws -> Int32 {
        let sock = socket(AF_UNIX, SOCK_STREAM, 0)
        guard sock >= 0 else { throw ControlSocketError.failed("socket", errno: errno) }
        var addr = try UnixSocket.address(for: path)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(sock, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard rc == 0 else {
            close(sock)
            throw ControlSocketError.failed("connect(\(path.path))", errno: errno)
        }
        return sock
    }

    /// Send a request and stream every response until the peer closes.
    ///
    /// Streaming rather than a single reply because an exec reports twice:
    /// once when the process starts and once when it exits.
    public func send(
        _ request: ControlRequest,
        onResponse: (ControlResponse) -> Bool
    ) throws {
        let sock = try connect()
        defer { close(sock) }

        let payload = try ControlCodec.encode(request)
        _ = payload.withUnsafeBytes { write(sock, $0.baseAddress, $0.count) }

        var reader = LineReader(fd: sock)
        while let line = reader.next() {
            guard let response = try? ControlCodec.decode(ControlResponse.self, from: line) else {
                continue
            }
            if !onResponse(response) { return }
        }
    }

    /// Send an interactive request, then pump the caller's stdin and window
    /// size onto the same connection while streaming responses back.
    ///
    /// Input runs on a background thread because reading stdin blocks, and the
    /// response loop must keep draining output the whole time — otherwise a
    /// program that prints while waiting for input would deadlock.
    public func sendInteractive(
        _ request: ControlRequest,
        terminal: Terminal,
        onResponse: (ControlResponse) -> Bool
    ) throws {
        let sock = try connect()
        defer { close(sock) }

        let payload = try ControlCodec.encode(request)
        _ = payload.withUnsafeBytes { write(sock, $0.baseAddress, $0.count) }

        let running = Mutex(true)

        // Poll rather than block on read: when the remote process exits there
        // is nothing to unblock a plain read(), and the thread would keep the
        // whole command alive after the session is over.
        let inputThread = Thread {
            var buffer = [UInt8](repeating: 0, count: 4096)
            while running.withLock({ $0 }) {
                var readable = fd_set()
                fdZero(&readable)
                fdSet(STDIN_FILENO, &readable)
                var timeout = timeval(tv_sec: 0, tv_usec: 200_000)
                let ready = select(STDIN_FILENO + 1, &readable, nil, nil, &timeout)
                if ready <= 0 { continue }

                let count = read(STDIN_FILENO, &buffer, buffer.count)
                guard count > 0 else { break }
                let chunk = Data(buffer[0..<count])
                guard
                    let frame = try? ControlCodec.encode(
                        ControlRequest.input(base64: chunk.base64EncodedString()))
                else { continue }
                _ = frame.withUnsafeBytes { write(sock, $0.baseAddress, $0.count) }
            }
            if running.withLock({ $0 }),
                let frame = try? ControlCodec.encode(ControlRequest.closeInput)
            {
                _ = frame.withUnsafeBytes { write(sock, $0.baseAddress, $0.count) }
            }
        }
        inputThread.start()

        let resizeSource = DispatchSource.makeSignalSource(signal: SIGWINCH, queue: .global())
        resizeSource.setEventHandler {
            guard let size = try? terminal.size else { return }
            guard
                let frame = try? ControlCodec.encode(
                    ControlRequest.resize(
                        rows: UInt16(size.height), columns: UInt16(size.width)))
            else { return }
            _ = frame.withUnsafeBytes { write(sock, $0.baseAddress, $0.count) }
        }
        signal(SIGWINCH, SIG_IGN)
        resizeSource.resume()
        defer { resizeSource.cancel() }

        var reader = LineReader(fd: sock)
        while let line = reader.next() {
            guard let response = try? ControlCodec.decode(ControlResponse.self, from: line)
            else { continue }
            if !onResponse(response) { break }
        }
        running.withLock { $0 = false }
        // Let the poll loop observe the flag and finish, so the thread is not
        // still running as the process tears down.
        Thread.sleep(forTimeInterval: 0.25)
    }

    /// Convenience for requests with exactly one reply.
    public func request(_ request: ControlRequest) throws -> ControlResponse? {
        var result: ControlResponse?
        try send(request) { response in
            result = response
            return false
        }
        return result
    }
}

/// `FD_ZERO` and `FD_SET` are C macros, so they are unavailable from Swift.
/// `fd_set` is a fixed array of 32-bit words; these set the bit by hand.
private func fdZero(_ set: inout fd_set) {
    withUnsafeMutableBytes(of: &set.fds_bits) { raw in
        raw.initializeMemory(as: UInt8.self, repeating: 0)
    }
}

private func fdSet(_ fd: Int32, _ set: inout fd_set) {
    let index = Int(fd) / 32
    let bit = Int32(1) << (Int32(fd) % 32)
    withUnsafeMutableBytes(of: &set.fds_bits) { raw in
        let words = raw.bindMemory(to: Int32.self)
        guard index < words.count else { return }
        words[index] |= bit
    }
}
