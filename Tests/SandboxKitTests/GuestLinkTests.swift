import Darwin
import Foundation
import Testing

@testable import SandboxKit

/// A stand-in for the gvsandbox gateway: a bound `unixgram` socket that learns
/// its peer by peeking the first datagram, exactly as the real gateway does.
final class FakeGateway {
    let path: URL
    private let fd: Int32
    private var peer: sockaddr_un?

    init(path: URL) throws {
        try? FileManager.default.removeItem(at: path)
        let sock = socket(AF_UNIX, SOCK_DGRAM, 0)
        #expect(sock >= 0)

        var addr = try Self.makeSockaddr(for: path)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(sock, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        #expect(rc == 0, "bind failed: errno \(errno)")

        // Keep tests from hanging forever if nothing arrives.
        var tv = timeval(tv_sec: 3, tv_usec: 0)
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        self.fd = sock
        self.path = path
    }

    /// Receive one datagram, recording the sender so we can reply.
    func receive(max: Int = 2048) -> Data? {
        var buf = [UInt8](repeating: 0, count: max)
        var from = sockaddr_un()
        var fromLen = socklen_t(MemoryLayout<sockaddr_un>.size)
        let n = withUnsafeMutablePointer(to: &from) { fromPtr in
            fromPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                recvfrom(fd, &buf, max, 0, sa, &fromLen)
            }
        }
        guard n > 0 else { return nil }
        peer = from
        return Data(buf[0..<n])
    }

    /// Send a datagram back to whoever last spoke to us.
    func reply(_ payload: Data) -> Bool {
        guard var peer else { return false }
        let n = payload.withUnsafeBytes { raw in
            withUnsafePointer(to: &peer) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(
                        fd, raw.baseAddress, raw.count, 0, $0,
                        socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
        }
        return n == payload.count
    }

    func close() {
        Darwin.close(fd)
        try? FileManager.default.removeItem(at: path)
    }

    static func makeSockaddr(for url: URL) throws -> sockaddr_un {
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(url.path.utf8)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: bytes)
            raw[bytes.count] = 0
        }
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        return addr
    }
}

/// `sun_path` is 104 bytes on Darwin and the default temp dir can be long
/// enough to overflow it, so tests use short, unique paths under /tmp.
private func shortSocketPath(_ tag: String) -> URL {
    URL(filePath: "/tmp/al-\(tag)-\(UInt32.random(in: 0..<0xFFFF_FFFF)).sock")
}

@Suite("GuestLink wire")
struct GuestLinkTests {
    @Test("handshake reaches the gateway and identifies our address")
    func handshakeArrives() throws {
        let gw = try FakeGateway(path: shortSocketPath("gw"))
        defer { gw.close() }

        let link = try GuestLink(gatewayPath: gw.path, clientPath: shortSocketPath("cl"))
        defer { link.close() }

        try link.handshake()

        let got = gw.receive()
        #expect(got == Data("VFKT".utf8))
    }

    @Test("a guest frame arrives at the gateway intact")
    func frameToGateway() throws {
        let gw = try FakeGateway(path: shortSocketPath("gw"))
        defer { gw.close() }
        let link = try GuestLink(gatewayPath: gw.path, clientPath: shortSocketPath("cl"))
        defer { link.close() }

        try link.handshake()
        _ = gw.receive()

        // Stand in for what the VM writes into the attachment: one datagram is
        // one Ethernet frame. Broadcast destination, arbitrary payload.
        var frame = Data([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        frame.append(contentsOf: [0x5A, 0x94, 0xEF, 0xE4, 0x0C, 0xDD])
        frame.append(contentsOf: [0x08, 0x00])
        frame.append(contentsOf: Array(repeating: UInt8(0xAB), count: 46))

        link.fileHandle.write(frame)

        let received = gw.receive()
        #expect(received == frame, "the gateway must see the frame byte-for-byte")
    }

    @Test("a gateway frame arrives back at the guest intact")
    func frameToGuest() throws {
        let gw = try FakeGateway(path: shortSocketPath("gw"))
        defer { gw.close() }
        let link = try GuestLink(gatewayPath: gw.path, clientPath: shortSocketPath("cl"))
        defer { link.close() }

        // The gateway cannot address us until we have spoken once.
        try link.handshake()
        _ = gw.receive()

        let payload = Data([0xDE, 0xAD, 0xBE, 0xEF] + Array(repeating: UInt8(0x11), count: 60))
        #expect(gw.reply(payload))

        let got = link.fileHandle.availableData
        #expect(got == payload)
    }

    @Test("socket buffers satisfy Apple's ratio requirement")
    func bufferRatio() throws {
        // The Virtualization header requires SO_RCVBUF to be at least twice
        // SO_SNDBUF and recommends four times. Getting this wrong degrades or
        // breaks the attachment under load, so pin it.
        #expect(GuestLink.receiveBufferBytes >= 2 * GuestLink.sendBufferBytes)
        #expect(GuestLink.receiveBufferBytes == 4 * GuestLink.sendBufferBytes)
    }

    @Test("an over-long socket path is rejected rather than truncated")
    func pathTooLong() throws {
        let gw = try FakeGateway(path: shortSocketPath("gw"))
        defer { gw.close() }

        // Silent truncation would bind the wrong path; it must throw instead.
        let long = URL(filePath: "/tmp/" + String(repeating: "x", count: 120) + ".sock")
        #expect(throws: GuestLinkError.self) {
            try GuestLink(gatewayPath: gw.path, clientPath: long)
        }
    }
}
