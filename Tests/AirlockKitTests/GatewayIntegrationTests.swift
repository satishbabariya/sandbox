import Darwin
import Foundation
import Testing

@testable import AirlockKit

/// End-to-end against the real `gvairlock` gateway, with no VM involved.
///
/// A VM is not required to prove the keystone: the gateway cannot tell whether
/// the frames on its socket came from Virtualization or from us, so speaking
/// DHCP to it exercises exactly the path a guest would take. If the gateway
/// leases us an address, then our socket setup, the frame framing, the
/// handshake, and the gateway's own configuration are all correct.
///
/// Skipped when the binary is absent; build it with `make -C netstack`.
private func gvairlockBinary() -> URL? {
    let root = URL(filePath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    let bin = root.appending(path: ".build/bin/gvairlock")
    return FileManager.default.isExecutableFile(atPath: bin.path) ? bin : nil
}

/// Minimal DHCP client frames, hand-built so the test depends on nothing.
enum DHCP {
    static func discover(mac: [UInt8], xid: UInt32) -> Data {
        var dhcp = Data()
        dhcp.append(contentsOf: [1, 1, 6, 0])  // BOOTREQUEST, ethernet, hlen 6
        dhcp.append(contentsOf: xid.bigEndianBytes)
        dhcp.append(contentsOf: [0, 0])  // secs
        dhcp.append(contentsOf: [0x80, 0x00])  // flags: broadcast
        dhcp.append(contentsOf: [UInt8](repeating: 0, count: 16))  // ci/yi/si/gi addr
        dhcp.append(contentsOf: mac)
        dhcp.append(contentsOf: [UInt8](repeating: 0, count: 10))  // chaddr padding
        dhcp.append(contentsOf: [UInt8](repeating: 0, count: 64))  // sname
        dhcp.append(contentsOf: [UInt8](repeating: 0, count: 128))  // file
        dhcp.append(contentsOf: [0x63, 0x82, 0x53, 0x63])  // magic cookie
        dhcp.append(contentsOf: [53, 1, 1])  // option 53: DHCPDISCOVER
        dhcp.append(contentsOf: [55, 3, 1, 3, 6])  // params: mask, router, dns
        dhcp.append(255)  // end
        return udpBroadcastFrame(payload: dhcp, mac: mac, srcPort: 68, dstPort: 67)
    }

    /// Wrap a payload in UDP/IPv4/Ethernet, broadcast, source 0.0.0.0.
    static func udpBroadcastFrame(
        payload: Data, mac: [UInt8], srcPort: UInt16, dstPort: UInt16
    ) -> Data {
        var udp = Data()
        udp.append(contentsOf: srcPort.bigEndianBytes)
        udp.append(contentsOf: dstPort.bigEndianBytes)
        udp.append(contentsOf: UInt16(8 + payload.count).bigEndianBytes)
        udp.append(contentsOf: [0, 0])  // checksum optional over IPv4
        udp.append(payload)

        var ip = Data()
        ip.append(contentsOf: [0x45, 0x00])
        ip.append(contentsOf: UInt16(20 + udp.count).bigEndianBytes)
        ip.append(contentsOf: [0, 0, 0, 0, 64, 17])  // id, flags, ttl, proto=UDP
        let checksumOffset = ip.count
        ip.append(contentsOf: [0, 0])  // checksum placeholder
        ip.append(contentsOf: [0, 0, 0, 0])  // src 0.0.0.0
        ip.append(contentsOf: [255, 255, 255, 255])  // dst broadcast
        let sum = internetChecksum(ip)
        ip[checksumOffset] = UInt8(sum >> 8)
        ip[checksumOffset + 1] = UInt8(sum & 0xFF)

        var frame = Data()
        frame.append(contentsOf: [UInt8](repeating: 0xFF, count: 6))
        frame.append(contentsOf: mac)
        frame.append(contentsOf: [0x08, 0x00])
        frame.append(ip)
        frame.append(udp)
        return frame
    }

    static func internetChecksum(_ data: Data) -> UInt16 {
        var sum: UInt32 = 0
        var i = data.startIndex
        while i < data.endIndex {
            let hi = UInt32(data[i]) << 8
            let lo = i + 1 < data.endIndex ? UInt32(data[i + 1]) : 0
            sum &+= hi | lo
            i += 2
        }
        while sum >> 16 != 0 { sum = (sum & 0xFFFF) &+ (sum >> 16) }
        return UInt16(~sum & 0xFFFF)
    }

    /// Pull the DHCP message type (option 53) out of a reply frame.
    static func messageType(inFrame frame: Data) -> UInt8? {
        // 14 ethernet + 20 IPv4 (no options) + 8 UDP
        let dhcpStart = 14 + 20 + 8
        guard frame.count > dhcpStart + 240 else { return nil }
        let dhcp = frame[frame.index(frame.startIndex, offsetBy: dhcpStart)...]
        var i = dhcp.index(dhcp.startIndex, offsetBy: 240)  // past the magic cookie
        while i < dhcp.endIndex {
            let code = dhcp[i]
            if code == 255 { return nil }
            if code == 0 {
                i = dhcp.index(after: i)
                continue
            }
            guard dhcp.index(after: i) < dhcp.endIndex else { return nil }
            let len = Int(dhcp[dhcp.index(after: i)])
            let valueStart = dhcp.index(i, offsetBy: 2)
            guard code != 53 else {
                return valueStart < dhcp.endIndex ? dhcp[valueStart] : nil
            }
            i = dhcp.index(valueStart, offsetBy: len)
        }
        return nil
    }

    /// yiaddr — the address the server is offering us.
    static func offeredAddress(inFrame frame: Data) -> String? {
        let yiaddr = 14 + 20 + 8 + 16
        guard frame.count >= yiaddr + 4 else { return nil }
        let b = Array(frame[frame.index(frame.startIndex, offsetBy: yiaddr)...].prefix(4))
        return "\(b[0]).\(b[1]).\(b[2]).\(b[3])"
    }
}

extension UInt16 {
    var bigEndianBytes: [UInt8] { [UInt8(self >> 8), UInt8(self & 0xFF)] }
}
extension UInt32 {
    var bigEndianBytes: [UInt8] {
        [UInt8(self >> 24), UInt8((self >> 16) & 0xFF), UInt8((self >> 8) & 0xFF), UInt8(self & 0xFF)]
    }
}

@Suite("gvairlock gateway", .serialized)
struct GatewayIntegrationTests {

    /// Boots the gateway with a policy and returns a live link to it.
    private func startGateway(
        allow: [String], deny: [String], auditLog: URL
    ) throws -> (Process, GuestLink, URL)? {
        guard let binary = gvairlockBinary() else { return nil }

        let tag = UInt32.random(in: 0..<0xFFFF_FFFF)
        let gwSock = URL(filePath: "/tmp/al-gw-\(tag).sock")
        let clSock = URL(filePath: "/tmp/al-cl-\(tag).sock")
        let configPath = URL(filePath: "/tmp/al-cfg-\(tag).yaml")

        let allowYAML = allow.map { "      - \"\($0)\"" }.joined(separator: "\n")
        let denyYAML = deny.map { "      - \"\($0)\"" }.joined(separator: "\n")
        let config = """
            stack:
              mtu: 1500
              subnet: 192.168.127.0/24
              gatewayIP: 192.168.127.1
              gatewayMacAddress: "5a:94:ef:e4:0c:dd"
              policy:
                allow:
            \(allowYAML.isEmpty ? "      []" : allowYAML)
                deny:
            \(denyYAML.isEmpty ? "      []" : denyYAML)
                auditLog: "\(auditLog.path)"
            """
        try config.write(to: configPath, atomically: true, encoding: .utf8)

        let proc = Process()
        proc.executableURL = binary
        proc.arguments = [
            "-config", configPath.path,
            "-listen-vfkit", "unixgram://\(gwSock.path)",
        ]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try proc.run()

        // Wait for the gateway to bind its socket.
        let deadline = Date().addingTimeInterval(10)
        while !FileManager.default.fileExists(atPath: gwSock.path) {
            guard Date() < deadline, proc.isRunning else {
                proc.terminate()
                Issue.record("gateway never bound \(gwSock.path)")
                return nil
            }
            usleep(50_000)
        }

        let link = try GuestLink(gatewayPath: gwSock, clientPath: clSock)
        // Don't let a missing reply hang the suite.
        var tv = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(
            link.fileHandle.fileDescriptor, SOL_SOCKET, SO_RCVTIMEO, &tv,
            socklen_t(MemoryLayout<timeval>.size))
        try link.handshake()
        return (proc, link, configPath)
    }

    private func readFrame(_ link: GuestLink) -> Data? {
        var buf = [UInt8](repeating: 0, count: 4096)
        let n = read(link.fileHandle.fileDescriptor, &buf, buf.count)
        guard n > 0 else { return nil }
        return Data(buf[0..<n])
    }

    /// The keystone proof. If the real gateway leases us an address over this
    /// socket, then the framing, buffers, handshake, and gateway config are all
    /// correct — and the same socket is what the VM's only NIC will be bound to.
    @Test("the real gateway answers DHCP over GuestLink")
    func dhcpRoundTrip() throws {
        let audit = URL(filePath: "/tmp/al-audit-\(UInt32.random(in: 0..<9999)).jsonl")
        guard
            let (proc, link, config) = try startGateway(
                allow: ["*.anthropic.com"], deny: [], auditLog: audit)
        else {
            Issue.record("gvairlock not built; run: make -C netstack")
            return
        }
        defer {
            proc.terminate()
            link.close()
            try? FileManager.default.removeItem(at: config)
            try? FileManager.default.removeItem(at: audit)
        }

        let mac: [UInt8] = [0x5A, 0x94, 0xEF, 0xE4, 0x0C, 0xDE]
        link.fileHandle.write(DHCP.discover(mac: mac, xid: 0x1234_5678))

        // The gateway also emits unrelated broadcast chatter; scan a few frames
        // for the OFFER rather than assuming it is first.
        var offer: Data?
        for _ in 0..<10 {
            guard let frame = readFrame(link) else { break }
            if DHCP.messageType(inFrame: frame) == 2 {  // DHCPOFFER
                offer = frame
                break
            }
        }

        guard let offer else {
            Issue.record("no DHCPOFFER received from the gateway")
            return
        }
        let address = DHCP.offeredAddress(inFrame: offer)
        print("GATEWAY LEASED: \(address ?? "nil")")
        #expect(
            address?.hasPrefix("192.168.127.") == true,
            "expected a lease inside the configured subnet, got \(address ?? "nil")")
    }
}
