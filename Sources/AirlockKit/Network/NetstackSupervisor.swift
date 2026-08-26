import Foundation
import Logging

public enum NetstackError: Error, CustomStringConvertible {
    case binaryNotFound(URL)
    case didNotStart(String)
    case exitedEarly(Int32, detail: String?)

    public var description: String {
        switch self {
        case .binaryNotFound(let url):
            return "gvairlock not found at \(url.path); build it with: make -C netstack"
        case .didNotStart(let detail):
            return "gvairlock did not start: \(detail)"
        case .exitedEarly(let code, let detail):
            guard let detail, !detail.isEmpty else {
                return "gvairlock exited with status \(code) before it was ready"
            }
            return "gvairlock exited before it was ready: \(detail)"
        }
    }
}

/// Owns the `gvairlock` gateway process for exactly one sandbox.
///
/// One gateway per sandbox, rather than one shared gateway, so a sandbox's
/// policy, its DNS resolution ledger, and its audit log cannot be observed or
/// influenced by any other sandbox. The process is bound to the sandbox's
/// lifetime and dies with it.
public actor NetstackSupervisor {
    public struct Configuration: Sendable {
        public var policy: NetworkPolicy
        /// Directory for the gateway's sockets, config, and audit log.
        public var runtimeDirectory: URL
        public var subnet: String
        public var gatewayIP: String
        public var gatewayMAC: String
        public var mtu: UInt32
        /// Credential bindings to resolve and hand the gateway. Empty means no
        /// interception at all.
        public var credentials: [CredentialBinding]
        /// Ports published from the host into the sandbox.
        public var ports: [PortForward]

        public init(
            policy: NetworkPolicy,
            runtimeDirectory: URL,
            subnet: String = AirlockInterface.Defaults.subnet,
            gatewayIP: String = AirlockInterface.Defaults.gateway,
            gatewayMAC: String = AirlockInterface.Defaults.gatewayMAC,
            mtu: UInt32 = AirlockInterface.Defaults.mtu,
            credentials: [CredentialBinding] = [],
            ports: [PortForward] = []
        ) {
            self.policy = policy
            self.runtimeDirectory = runtimeDirectory
            self.subnet = subnet
            self.gatewayIP = gatewayIP
            self.gatewayMAC = gatewayMAC
            self.mtu = mtu
            self.credentials = credentials
            self.ports = ports
        }
    }

    private let binary: URL
    private let config: Configuration
    private let logger: Logger?
    private var process: Process?
    private var link: GuestLink?

    /// Where the gateway records every allow/deny decision.
    public nonisolated var auditLogPath: URL {
        config.runtimeDirectory.appending(path: "policy.jsonl")
    }

    /// Resolved secrets for the gateway. Mode 0600, on the host, in a directory
    /// that is never shared into the VM.
    public nonisolated var brokerConfigPath: URL {
        config.runtimeDirectory.appending(path: "credentials.json")
    }

    /// A directory holding ONLY the CA certificate, so it can be shared into
    /// the guest without exposing anything else in the runtime directory —
    /// which is also where the resolved secrets live.
    public nonisolated var guestShareDirectory: URL {
        config.runtimeDirectory.appending(path: "guest")
    }

    /// The CA certificate the guest must trust for interception to verify.
    public nonisolated var caCertificatePath: URL {
        guestShareDirectory.appending(path: "airlock-ca.crt")
    }

    /// Services named by a binding that had no secret stored.
    public private(set) var missingSecrets: [String] = []
    /// Services whose OAuth token has expired on the host.
    public private(set) var expiredSecrets: [String] = []

    public init(binary: URL, configuration: Configuration, logger: Logger? = nil) {
        self.binary = binary
        self.config = configuration
        self.logger = logger
    }

    /// Default location of the gateway binary relative to an install root.
    public static func defaultBinary(installRoot: URL) -> URL {
        installRoot.appending(path: "bin/gvairlock")
    }

    /// Start the gateway and return the wire to hand the VM.
    ///
    /// Sockets live under a short path in the runtime directory because
    /// `sun_path` is only 104 bytes on Darwin.
    public func start() async throws -> GuestLink {
        guard FileManager.default.isExecutableFile(atPath: binary.path) else {
            throw NetstackError.binaryNotFound(binary)
        }
        try FileManager.default.createDirectory(
            at: config.runtimeDirectory, withIntermediateDirectories: true)

        let gatewaySocket = config.runtimeDirectory.appending(path: "net.sock")
        let clientSocket = config.runtimeDirectory.appending(path: "guest.sock")
        let configFile = config.runtimeDirectory.appending(path: "gateway.yaml")
        try? FileManager.default.removeItem(at: gatewaySocket)

        try writeBrokerConfiguration()
        try renderConfiguration().write(to: configFile, atomically: true, encoding: .utf8)

        let proc = Process()
        proc.executableURL = binary
        proc.arguments = [
            "-config", configFile.path,
            "-listen-vfkit", "unixgram://\(gatewaySocket.path)",
        ]
        let logHandle = try openLog()
        proc.standardOutput = logHandle
        proc.standardError = logHandle
        try proc.run()
        self.process = proc

        try await waitForSocket(gatewaySocket, process: proc)

        let link = try GuestLink(gatewayPath: gatewaySocket, clientPath: clientSocket)
        try link.handshake()
        self.link = link
        logger?.info("gateway ready", metadata: ["socket": .string(gatewaySocket.path)])
        return link
    }

    public func stop() {
        link?.close()
        link = nil
        if let process, process.isRunning {
            process.terminate()
            process.waitUntilExit()
        }
        process = nil
    }

    /// Read back the decisions the gateway recorded.
    public nonisolated func auditRecords() throws -> [PolicyAuditRecord] {
        guard let data = try? Data(contentsOf: auditLogPath) else { return [] }
        let decoder = JSONDecoder()
        return data.split(separator: UInt8(ascii: "\n")).compactMap { line in
            try? decoder.decode(PolicyAuditRecord.self, from: Data(line))
        }
    }

    /// Resolve bindings against the keychain and write them where only this
    /// user, and the gateway running as this user, can read them.
    private func writeBrokerConfiguration() throws {
        guard !config.credentials.isEmpty else { return }
        let (resolved, missing, expired) = BrokerConfiguration.resolve(
            bindings: config.credentials)
        self.missingSecrets = missing
        self.expiredSecrets = expired
        guard !resolved.credentials.isEmpty else { return }

        // The CA lands in its own directory; the secrets stay in the parent,
        // which is never shared into the VM.
        try FileManager.default.createDirectory(
            at: guestShareDirectory, withIntermediateDirectories: true)

        let data = try JSONEncoder().encode(resolved)
        try data.write(to: brokerConfigPath, options: .atomic)
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: brokerConfigPath.path)
    }

    /// Pull the gateway's own error line out of its log, so a failure to bind
    /// a port or parse a rule reaches the user instead of an exit code.
    private func lastGatewayError() -> String? {
        let path = config.runtimeDirectory.appending(path: "gateway.log")
        guard let text = try? String(contentsOf: path, encoding: .utf8) else { return nil }
        let errors = text.split(separator: "\n").filter { $0.contains("level=error") }
        guard let last = errors.last else { return nil }
        // Strip logfmt noise; the message is what matters.
        if let range = last.range(of: "msg=") {
            return String(last[range.upperBound...]).trimmingCharacters(
                in: CharacterSet(charactersIn: "\""))
        }
        return String(last)
    }

    private func openLog() throws -> FileHandle {
        let path = config.runtimeDirectory.appending(path: "gateway.log")
        if !FileManager.default.fileExists(atPath: path.path) {
            FileManager.default.createFile(atPath: path.path, contents: nil)
        }
        let handle = try FileHandle(forWritingTo: path)
        try handle.seekToEnd()
        return handle
    }

    private func waitForSocket(_ socket: URL, process: Process) async throws {
        let deadline = Date().addingTimeInterval(15)
        while !FileManager.default.fileExists(atPath: socket.path) {
            guard process.isRunning else {
                throw NetstackError.exitedEarly(
                    process.terminationStatus, detail: lastGatewayError())
            }
            guard Date() < deadline else {
                process.terminate()
                throw NetstackError.didNotStart("timed out waiting for \(socket.path)")
            }
            try await Task.sleep(for: .milliseconds(25))
        }
    }

    /// Render the gateway's YAML. Quoting every pattern keeps a leading `*`
    /// from being read as a YAML alias.
    func renderConfiguration() -> String {
        func list(_ patterns: [HostPattern]) -> String {
            guard !patterns.isEmpty else { return " []" }
            return "\n" + patterns.map { "      - \"\($0.raw)\"" }.joined(separator: "\n")
        }
        return """
            stack:
              mtu: \(config.mtu)
              subnet: \(config.subnet)
              gatewayIP: \(config.gatewayIP)
              gatewayMacAddress: "\(config.gatewayMAC)"
              policy:
                allow:\(list(config.policy.allow))
                deny:\(list(config.policy.deny))
                auditLog: "\(auditLogPath.path)"
            \(brokerLines)
            \(forwardLines)
            """
    }

    /// Host address -> guest address, which is how the gateway expresses a
    /// published port.
    private var forwardLines: String {
        guard !config.ports.isEmpty else { return "" }
        let entries = config.ports.map { forward in
            "    \"\(forward.hostAddress):\(forward.hostPort)\": "
                + "\"\(AirlockInterface.Defaults.guest):\(forward.guestPort)\""
        }.joined(separator: "\n")
        return "  forwards:\n" + entries
    }

    /// Only emitted when a credential actually resolved, so a sandbox with no
    /// secrets is never intercepted.
    private var brokerLines: String {
        guard FileManager.default.fileExists(atPath: brokerConfigPath.path) else { return "" }
        return """
                brokerConfig: "\(brokerConfigPath.path)"
                brokerCACert: "\(caCertificatePath.path)"
            """
    }
}

/// One line of the gateway's audit log.
public struct PolicyAuditRecord: Codable, Sendable, Equatable {
    public let time: String
    public let proto: String
    public let address: String
    public let port: UInt16
    public let allowed: Bool
    public let rule: String?
    public let reason: String
    public let names: [String]?
}
