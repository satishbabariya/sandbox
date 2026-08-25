import Containerization
import ContainerizationOCI
import Foundation
import Logging

public enum SandboxError: Error, CustomStringConvertible {
    case kernelNotFound(URL)
    case notRunning

    public var description: String {
        switch self {
        case let .kernelNotFound(url):
            return """
                no Linux kernel at \(url.path)
                fetch one with: make kernel
                """
        case .notRunning:
            return "sandbox is not running"
        }
    }
}

/// Everything needed to bring one sandbox up.
public struct SandboxSpec: Sendable {
    public var id: String
    public var image: String
    /// The command the sandbox runs. Empty means the image's own entrypoint.
    public var command: [String]
    public var environment: [String: String]
    public var policy: NetworkPolicy
    public var cpus: Int
    public var memoryInBytes: UInt64
    public var workspace: URL?
    public var workspaceDestination: String
    public var terminal: Bool
    /// Grant the guest process every Linux capability.
    ///
    /// Needed by workloads that manage their own namespaces and networking,
    /// such as a dockerd running inside the sandbox. It deliberately does NOT
    /// weaken egress policy: the enforcement point is the host end of the
    /// guest's only network device, so CAP_NET_ADMIN buys the guest control
    /// over an interface that still has nowhere else to go.
    public var privileged: Bool
    /// Where the guest's stdout goes. Defaults to the host's stdout.
    public var stdout: (any Writer)?
    /// Where the guest's stderr goes. Defaults to the host's stderr.
    public var stderr: (any Writer)?

    public init(
        id: String,
        image: String,
        command: [String] = [],
        environment: [String: String] = [:],
        policy: NetworkPolicy = .denyAll,
        cpus: Int = 4,
        memoryInBytes: UInt64 = 4 * 1024 * 1024 * 1024,
        workspace: URL? = nil,
        workspaceDestination: String = "/workspace",
        terminal: Bool = false,
        privileged: Bool = false,
        stdout: (any Writer)? = nil,
        stderr: (any Writer)? = nil
    ) {
        self.id = id
        self.image = image
        self.command = command
        self.environment = environment
        self.policy = policy
        self.cpus = cpus
        self.memoryInBytes = memoryInBytes
        self.workspace = workspace
        self.workspaceDestination = workspaceDestination
        self.terminal = terminal
        self.privileged = privileged
        self.stdout = stdout ?? StreamWriter.standardOutput
        self.stderr = stderr ?? StreamWriter.standardError
    }
}

/// Where airlock keeps kernels, images, and per-sandbox runtime state.
public struct AirlockPaths: Sendable {
    public let root: URL

    public init(root: URL? = nil) {
        self.root =
            root
            ?? FileManager.default.homeDirectoryForCurrentUser
                .appending(path: ".airlock")
    }

    public var kernel: URL { root.appending(path: "vmlinux-arm64") }
    public var images: URL { root.appending(path: "images") }
    public func runtime(_ id: String) -> URL { root.appending(path: "run/\(id)") }

    /// `sun_path` is 104 bytes, and the gateway sockets live in the runtime
    /// directory, so keep that path short by placing sockets under /tmp.
    public func socketDirectory(_ id: String) -> URL {
        URL(filePath: "/tmp/airlock-\(id)")
    }
}

/// One sandbox: a Linux VM with exactly one network device, whose wire is held
/// by this process.
///
/// The ordering in `start()` is load-bearing. The gateway must be listening
/// before the VM is configured, because the interface handed to Virtualization
/// wraps a socket that has to be connected at configuration time.
public actor Sandbox {
    public let spec: SandboxSpec
    private let paths: AirlockPaths
    private let logger: Logger?

    private var netstack: NetstackSupervisor?
    private var container: LinuxContainer?
    private var manager: ContainerManager?

    public init(spec: SandboxSpec, paths: AirlockPaths = AirlockPaths(), logger: Logger? = nil) {
        self.spec = spec
        self.paths = paths
        self.logger = logger
    }

    public var auditLogPath: URL? {
        netstack?.auditLogPath
    }

    /// Bring the sandbox up and return once its process has been started.
    public func start(gatewayBinary: URL) async throws {
        // A kernel image is data, not a program — readable is the right test.
        guard FileManager.default.isReadableFile(atPath: paths.kernel.path) else {
            throw SandboxError.kernelNotFound(paths.kernel)
        }

        // 1. Gateway first: the VM's only NIC is a socket connected to it.
        let socketDir = paths.socketDirectory(spec.id)
        let runtimeDir = paths.runtime(spec.id)
        try FileManager.default.createDirectory(at: runtimeDir, withIntermediateDirectories: true)

        let supervisor = NetstackSupervisor(
            binary: gatewayBinary,
            configuration: .init(policy: spec.policy, runtimeDirectory: socketDir),
            logger: logger
        )
        let link = try await supervisor.start()
        self.netstack = supervisor

        // 2. The VM. One interface, no vmnet, no NAT, no host route.
        let interface = try AirlockInterface(link: link, macAddress: "5a:94:ef:e4:0c:de")

        let kernel = Kernel(path: paths.kernel, platform: .linuxArm)
        try FileManager.default.createDirectory(at: paths.images, withIntermediateDirectories: true)
        let contentStore = try LocalContentStore(path: paths.images.appending(path: "content"))
        let imageStore = try ImageStore(path: paths.images, contentStore: contentStore)

        var mgr = try await ContainerManager(
            kernel: kernel,
            initfsReference: Self.initfsReference,
            imageStore: imageStore
        )

        let spec = self.spec
        let container = try await mgr.create(
            spec.id,
            reference: spec.image,
            networking: false  // airlock supplies the interface itself
        ) { config in
            config.cpus = spec.cpus
            config.memoryInBytes = spec.memoryInBytes
            config.interfaces = [interface]
            // The gateway is the only resolver the sandbox can reach, which is
            // what lets policy gate name resolution as well as dialling.
            config.dns = DNS(nameservers: [AirlockInterface.Defaults.gateway])
            config.process.terminal = spec.terminal
            if spec.privileged {
                config.process.capabilities = .allCapabilities
            }
            config.process.stdout = spec.stdout
            config.process.stderr = spec.stderr

            if !spec.command.isEmpty {
                config.process.arguments = spec.command
            }
            for (key, value) in spec.environment {
                config.process.environmentVariables.append("\(key)=\(value)")
            }
            if let workspace = spec.workspace {
                config.mounts.append(
                    .share(
                        source: workspace.path(percentEncoded: false),
                        destination: spec.workspaceDestination
                    )
                )
                config.process.workingDirectory = spec.workspaceDestination
            }
        }
        self.manager = mgr
        self.container = container

        try await container.create()
        try await container.start()
        logger?.info("sandbox started", metadata: ["id": .string(spec.id)])
    }

    /// The vminit image carrying the guest agent. Pinned so a sandbox is
    /// reproducible rather than tracking whatever :latest happens to be.
    public static let initfsReference = "ghcr.io/apple/containerization/vminit:0.30.0"

    public func wait() async throws -> Int32 {
        guard let container else { throw SandboxError.notRunning }
        let status = try await container.wait()
        return status.exitCode
    }

    public func stop() async {
        if let container {
            try? await container.stop()
        }
        if let netstack {
            await netstack.stop()
        }
        container = nil
        netstack = nil
    }

    /// Decisions the gateway recorded for this sandbox.
    public func auditRecords() -> [PolicyAuditRecord] {
        guard let netstack else { return [] }
        return (try? netstack.auditRecords()) ?? []
    }
}
