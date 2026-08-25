import Foundation

#if canImport(Darwin)
import Darwin
#endif

public enum GuestLinkError: Error, CustomStringConvertible {
    case socketFailed(String, errno: Int32)
    case pathTooLong(String)
    case invalidMACAddress(String)

    public var description: String {
        switch self {
        case .socketFailed(let op, let err):
            return "\(op) failed: \(String(cString: strerror(err))) (errno \(err))"
        case .pathTooLong(let path):
            return "socket path exceeds sun_path capacity: \(path)"
        case .invalidMACAddress(let mac):
            return "invalid MAC address: \(mac)"
        }
    }
}

/// The guest's only wire to the outside world.
///
/// A connected `AF_UNIX`/`SOCK_DGRAM` socket carrying raw Ethernet frames
/// between the VM's single virtio-net device and the `gvairlock` gateway. One
/// datagram is one frame — the layer the Virtualization framework documents for
/// `VZFileHandleNetworkDeviceAttachment`.
///
/// This type exists so that the sandbox has *no other* network device. Root
/// inside the guest may flush its firewall, rewrite its routes, and unset every
/// proxy variable; the frames still arrive at the far end of this socket,
/// because there is nowhere else for them to go.
public final class GuestLink: @unchecked Sendable {
    /// Handed to `VZFileHandleNetworkDeviceAttachment`. Ownership of the
    /// descriptor stays here.
    public let fileHandle: FileHandle

    /// Our own bound address. The gateway learns it by peeking the first
    /// datagram and replies there.
    public let clientPath: URL

    /// Apple's header requires SO_RCVBUF to be at least twice SO_SNDBUF, and
    /// recommends four times. gvisor-tap-vsock picks 1 MiB / 4 MiB on its side;
    /// matching it keeps both directions symmetric.
    public static let sendBufferBytes: Int32 = 1 * 1024 * 1024
    public static let receiveBufferBytes: Int32 = 4 * 1024 * 1024

    private let fd: Int32

    /// Connect to a gateway already listening on `gatewayPath`.
    ///
    /// - Parameters:
    ///   - gatewayPath: the gateway's `unixgram` socket.
    ///   - clientPath: where to bind our end. Must not already exist.
    /// - Throws: ``GuestLinkError`` when the socket cannot be created, bound,
    ///   or connected, or when either path exceeds `sun_path`.
    public init(gatewayPath: URL, clientPath: URL) throws {
        let fd = socket(AF_UNIX, SOCK_DGRAM, 0)
        guard fd >= 0 else {
            throw GuestLinkError.socketFailed("socket", errno: errno)
        }

        var ok = false
        defer { if !ok { Darwin.close(fd) } }

        // A stale socket file would make bind fail with EADDRINUSE.
        try? FileManager.default.removeItem(at: clientPath)

        var local = try Self.makeSockaddr(for: clientPath)
        let bound = withUnsafePointer(to: &local) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0 else {
            throw GuestLinkError.socketFailed("bind(\(clientPath.path))", errno: errno)
        }
        // Only this user may inject frames into the sandbox's network.
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: clientPath.path)

        var remote = try Self.makeSockaddr(for: gatewayPath)
        let connected = withUnsafePointer(to: &remote) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else {
            throw GuestLinkError.socketFailed("connect(\(gatewayPath.path))", errno: errno)
        }

        try Self.setBuffer(fd, SO_SNDBUF, Self.sendBufferBytes)
        try Self.setBuffer(fd, SO_RCVBUF, Self.receiveBufferBytes)

        self.fd = fd
        self.clientPath = clientPath
        self.fileHandle = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        ok = true
    }

    /// Announce ourselves to the gateway.
    ///
    /// The gateway discovers where to send replies by peeking the source
    /// address of the first datagram it receives, so it cannot speak to us
    /// until we have spoken first. `VFKT` is the magic vfkit sends; the gateway
    /// recognises and consumes it rather than treating it as a frame.
    public func handshake() throws {
        let magic = Array("VFKT".utf8)
        let sent = magic.withUnsafeBytes { send(fd, $0.baseAddress, $0.count, 0) }
        guard sent == magic.count else {
            throw GuestLinkError.socketFailed("send(handshake)", errno: errno)
        }
    }

    public func close() {
        Darwin.close(fd)
        try? FileManager.default.removeItem(at: clientPath)
    }

    private static func setBuffer(_ fd: Int32, _ option: Int32, _ bytes: Int32) throws {
        var value = bytes
        let rc = setsockopt(
            fd, SOL_SOCKET, option, &value, socklen_t(MemoryLayout<Int32>.size))
        guard rc == 0 else {
            throw GuestLinkError.socketFailed("setsockopt(\(option))", errno: errno)
        }
    }

    private static func makeSockaddr(for url: URL) throws -> sockaddr_un {
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let path = url.path
        let bytes = Array(path.utf8)
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        // Leave room for the NUL terminator.
        guard bytes.count < capacity else {
            throw GuestLinkError.pathTooLong(path)
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: bytes)
            raw[bytes.count] = 0
        }
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        return addr
    }
}
