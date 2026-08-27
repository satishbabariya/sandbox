import Containerization
import ContainerizationExtras
import Foundation

#if canImport(Virtualization)
import Virtualization
#endif

/// The sandbox's sole network interface.
///
/// Containerization ships `NATInterface`, which returns a
/// `VZNATNetworkDeviceAttachment` and gives the guest a working route to the
/// internet via macOS. That is exactly what a sandbox must not have: with a
/// real route, any egress control has to be enforced inside the guest, where a
/// compromised agent with root can remove it.
///
/// This conformer returns a `VZFileHandleNetworkDeviceAttachment` instead. The
/// guest still sees an ordinary virtio-net device, but its wire is a datagram
/// socket held by the host. Configure a VM with this and nothing else, and the
/// guest's only reachable peer is our gateway.
///
/// `VZInterface` is a public protocol in Containerization, so this needs no
/// fork — it is the extension point behaving as intended.
public struct SandboxInterface: Interface, @unchecked Sendable {
    public let ipv4Address: CIDRv4
    public let ipv4Gateway: IPv4Address?
    public let macAddress: MACAddress?
    public let mtu: UInt32

    /// Keeps the socket alive for as long as the interface is configured.
    public let link: GuestLink

    /// Defaults chosen to match the gateway's own defaults so the two agree
    /// without extra configuration.
    public struct Defaults {
        public static let subnet = "192.168.127.0/24"
        public static let gateway = "192.168.127.1"
        public static let guest = "192.168.127.2"
        /// The MAC the gateway expects for its own side.
        public static let gatewayMAC = "5a:94:ef:e4:0c:dd"
        /// Apple permits 1500...65535. Larger amortises the per-datagram cost
        /// of crossing the socket, but both ends must agree, so raising this
        /// means raising the gateway's `mtu` too.
        public static let mtu: UInt32 = 1500
    }

    public init(
        link: GuestLink,
        address: String = Defaults.guest,
        prefixLength: UInt8 = 24,
        gateway: String = Defaults.gateway,
        macAddress: String? = nil,
        mtu: UInt32 = Defaults.mtu
    ) throws {
        self.link = link
        guard let prefix = Prefix(length: prefixLength) else {
            throw GuestLinkError.pathTooLong("invalid prefix length \(prefixLength)")
        }
        self.ipv4Address = try CIDRv4(IPv4Address(address), prefix: prefix)
        self.ipv4Gateway = try IPv4Address(gateway)
        self.macAddress = try macAddress.map { try MACAddress($0) }
        self.mtu = mtu
    }
}

#if canImport(Virtualization)
extension SandboxInterface: VZInterface {
    public func device() throws -> VZVirtioNetworkDeviceConfiguration {
        let config = VZVirtioNetworkDeviceConfiguration()
        if let macAddress {
            guard let mac = VZMACAddress(string: macAddress.description) else {
                throw GuestLinkError.invalidMACAddress(macAddress.description)
            }
            config.macAddress = mac
        }
        let attachment = VZFileHandleNetworkDeviceAttachment(fileHandle: link.fileHandle)
        // Available from macOS 13. Both ends must agree on this value.
        attachment.maximumTransmissionUnit = Int(mtu)
        config.attachment = attachment
        return config
    }
}
#endif
