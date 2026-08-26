import Containerization
import ContainerizationEXT4
import ContainerizationOCI
import ContainerizationOS
import Darwin
import Foundation
import Logging
import SystemPackage

public enum SandboxError: Error, CustomStringConvertible {
    case kernelNotFound(URL)
    case notRunning

    public var description: String {
        switch self {
        case .kernelNotFound(let url):
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
    /// Extra host directories to share, beyond the workspace.
    public var mounts: [MountSpec]
    /// Give the agent a private git clone instead of your working tree.
    public var cloneWorkspace: Bool
    /// MCP servers to declare to the agent, and where to write the file.
    public var mcp: [MCPServer]
    public var mcpConfigPath: String?
    /// Use this prepared ext4 image as the rootfs instead of unpacking the
    /// image fresh. Set by the agent cache.
    public var preparedRootfs: URL?
    public var terminal: Bool
    /// Grant the guest process every Linux capability.
    ///
    /// Needed by workloads that manage their own namespaces and networking,
    /// such as a dockerd running inside the sandbox. It deliberately does NOT
    /// weaken egress policy: the enforcement point is the host end of the
    /// guest's only network device, so CAP_NET_ADMIN buys the guest control
    /// over an interface that still has nowhere else to go.
    public var privileged: Bool
    /// Credentials to broker. The guest receives a sentinel, never the secret.
    public var credentials: [CredentialBinding]
    /// Ports published from the host into the sandbox.
    public var ports: [PortForward]
    /// Give the sandbox its own dockerd, backed by a dedicated block device.
    public var docker: Bool
    /// Size of that block device.
    public var dockerDiskBytes: UInt64
    /// The host terminal to attach when `terminal` is set. Supplying it makes
    /// the guest process interactive: it gets a PTY, and keystrokes and window
    /// size changes reach it.
    public var hostTerminal: Terminal?
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
        mounts: [MountSpec] = [],
        cloneWorkspace: Bool = false,
        mcp: [MCPServer] = [],
        mcpConfigPath: String? = nil,
        preparedRootfs: URL? = nil,
        terminal: Bool = false,
        hostTerminal: Terminal? = nil,
        privileged: Bool = false,
        credentials: [CredentialBinding] = [],
        ports: [PortForward] = [],
        docker: Bool = false,
        dockerDiskBytes: UInt64 = 20 * 1024 * 1024 * 1024,
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
        self.mounts = mounts
        self.cloneWorkspace = cloneWorkspace
        self.mcp = mcp
        self.mcpConfigPath = mcpConfigPath
        self.preparedRootfs = preparedRootfs
        self.terminal = terminal
        self.hostTerminal = hostTerminal
        self.privileged = privileged
        self.credentials = credentials
        self.ports = ports
        self.docker = docker
        self.dockerDiskBytes = dockerDiskBytes
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

    /// Where ContainerManager unpacks a sandbox's rootfs. Removing a sandbox
    /// has to clear this too, or the name cannot be reused.
    public func containerRoot(_ id: String) -> URL {
        images.appending(path: "containers/\(id)")
    }

    /// Everything a single sandbox owns on disk.
    public func allDirectories(_ id: String) -> [URL] {
        [runtime(id), socketDirectory(id), containerRoot(id)]
    }

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
            configuration: .init(
                policy: spec.policy,
                runtimeDirectory: socketDir,
                credentials: spec.credentials,
                ports: spec.ports
            ),
            logger: logger
        )
        let link = try await supervisor.start()
        self.netstack = supervisor

        // Silently starting without a credential the user asked for would
        // surface later as an opaque 401 from inside the sandbox.
        for service in await supervisor.missingSecrets {
            logger?.warning("no credential for '\(service)'")
            let message =
                "airlock: no credential for '\(service)'; "
                + "set one with 'airlock secret set \(service)'\n"
            FileHandle.standardError.write(Data(message.utf8))
        }
        for service in await supervisor.expiredSecrets {
            let message =
                "airlock: the sign-in for '\(service)' has expired; "
                + "sign in again on the host, or run 'airlock secret set \(service)'\n"
            FileHandle.standardError.write(Data(message.utf8))
        }

        // A dedicated block device for the image store. Layers are large and
        // churn, and keeping them off the rootfs means the sandbox's own disk
        // is not consumed by whatever the agent pulls.
        var dockerDisk: URL?
        if spec.docker {
            let disk = runtimeDir.appending(path: "docker.ext4")
            if !FileManager.default.fileExists(atPath: disk.path) {
                let formatter = try EXT4.Formatter(
                    FilePath(disk.path), minDiskSize: spec.dockerDiskBytes)
                try formatter.close()
            }
            dockerDisk = disk
        }

        let caCertificate = supervisor.caCertificatePath
        let caIsPresent = FileManager.default.fileExists(atPath: caCertificate.path)
        let guestShare = supervisor.guestShareDirectory

        // 2. The VM. One interface, no vmnet, no NAT, no host route.
        let interface = try AirlockInterface(link: link, macAddress: "5a:94:ef:e4:0c:de")

        let kernel = Kernel(path: paths.kernel, platform: .linuxArm)
        try FileManager.default.createDirectory(at: paths.images, withIntermediateDirectories: true)
        let contentStore = try LocalContentStore(path: paths.images.appending(path: "content"))
        let imageStore = try ImageStore(path: paths.images, contentStore: contentStore)

        // ContainerManager reuses an existing initfs.ext4 whatever reference it
        // is asked for, so bumping the vminit version would otherwise keep
        // booting the old guest agent. Track what produced the cached one and
        // discard it when the pin moves.
        try Self.invalidateStaleInitfs(in: paths.images)

        var mgr = try await ContainerManager(
            kernel: kernel,
            initfsReference: Self.initfsReference,
            imageStore: imageStore
        )

        // A crashed or killed run can leave the rootfs directory behind. The
        // store is the source of truth for whether a name is taken, so if we
        // got this far the leftovers are ours to clear.
        let containerRoot = paths.containerRoot(spec.id)
        if FileManager.default.fileExists(atPath: containerRoot.path) {
            try? FileManager.default.removeItem(at: containerRoot)
        }

        let spec = self.spec
        let configure: (inout LinuxContainer.Configuration) throws -> Void = { config in
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
            if spec.terminal, let host = spec.hostTerminal {
                // A PTY carries both streams, and the runtime rejects a
                // separately configured stderr when a terminal is attached.
                config.process.stdin = host
                config.process.stdout = host
                config.process.stderr = nil
            } else {
                config.process.stdout = spec.stdout
                config.process.stderr = spec.stderr
            }

            if !spec.command.isEmpty {
                config.process.arguments = spec.command
            }

            // Written at startup rather than baked into the cached rootfs, so
            // changing which servers an agent uses does not force a rebuild.
            if let mcpPath = spec.mcpConfigPath, !spec.mcp.isEmpty,
                let rendered = try? MCPConfiguration.render(spec.mcp)
            {
                config.process.arguments = Self.mcpBootstrap(
                    wrapping: config.process.arguments,
                    path: mcpPath,
                    contents: rendered)
            }

            if let dockerDisk {
                config.mounts.append(
                    .block(
                        format: "ext4",
                        source: dockerDisk.path(percentEncoded: false),
                        destination: "/var/lib/docker"
                    ))
                // dockerd manages its own namespaces, bridges, and iptables
                // rules, which needs the full capability set. It does not
                // weaken egress: containers it starts sit behind the same
                // single interface as everything else in the VM.
                config.process.capabilities = .allCapabilities
                config.process.arguments = Self.dockerBootstrap(
                    wrapping: config.process.arguments)
            }

            if caIsPresent {
                // Read-only, and only the directory holding the certificate —
                // the runtime directory beside it holds the real secrets.
                config.mounts.append(
                    .share(
                        source: guestShare.path(percentEncoded: false),
                        destination: Self.guestCertificateDirectory,
                        options: ["ro"]
                    ))
                config.process.arguments = Self.trustBootstrap(
                    wrapping: config.process.arguments)
                for (key, value) in Self.trustEnvironment {
                    config.process.environmentVariables.append("\(key)=\(value)")
                }
                for binding in spec.credentials {
                    guard let name = CredentialBinding.sentinelEnvironment[binding.service]
                    else { continue }
                    config.process.environmentVariables.append(
                        "\(name)=\(CredentialBinding.sentinel)")
                }
            }
            for (key, value) in spec.environment {
                config.process.environmentVariables.append("\(key)=\(value)")
            }
            if let workspace = spec.workspace {
                if spec.cloneWorkspace {
                    // Share the repository read-only somewhere else, and clone
                    // from it at startup. The agent gets a real working tree it
                    // can commit to, while the user's own tree is untouchable
                    // even if the agent runs `git reset --hard`.
                    config.mounts.append(
                        .share(
                            source: workspace.path(percentEncoded: false),
                            destination: Self.cloneSourceDirectory,
                            options: ["ro"]
                        ))
                    config.process.arguments = Self.cloneBootstrap(
                        wrapping: config.process.arguments,
                        destination: spec.workspaceDestination)
                } else {
                    config.mounts.append(
                        .share(
                            source: workspace.path(percentEncoded: false),
                            destination: spec.workspaceDestination
                        )
                    )
                }
                config.process.workingDirectory = spec.workspaceDestination
            }

            for mount in spec.mounts {
                config.mounts.append(
                    .share(
                        source: mount.source.path(percentEncoded: false),
                        destination: mount.destination,
                        options: mount.readOnly ? ["ro"] : []
                    ))
            }
        }

        let container: LinuxContainer
        if let prepared = spec.preparedRootfs {
            // A prepared rootfs already has the agent installed; unpacking the
            // base image again would throw that away.
            let image = try await imageStore.get(reference: spec.image, pull: true)
            let target = containerRoot.appending(path: "rootfs.ext4")
            try FileManager.default.createDirectory(
                at: containerRoot, withIntermediateDirectories: true)
            try? FileManager.default.removeItem(at: target)
            let cloned = clonefile(
                prepared.path(percentEncoded: false),
                target.path(percentEncoded: false), 0)
            if cloned != 0 {
                try FileManager.default.copyItem(at: prepared, to: target)
            }
            container = try await mgr.create(
                spec.id,
                image: image,
                rootfs: .block(
                    format: "ext4",
                    source: target.path(percentEncoded: false),
                    destination: "/",
                    runtimeOptions: ["vzDiskImageSynchronizationMode=fsync"]
                ),
                networking: false,
                configuration: configure
            )
        } else {
            container = try await mgr.create(
                spec.id,
                reference: spec.image,
                networking: false,  // airlock supplies the interface itself
                configuration: configure
            )
        }
        self.manager = mgr
        self.container = container

        try await container.create()
        try await container.start()
        logger?.info("sandbox started", metadata: ["id": .string(spec.id)])
    }

    /// Start dockerd in the background, wait for its socket, then exec the
    /// real command. Failing to start is reported rather than silently
    /// leaving the agent with a broken docker.
    static func dockerBootstrap(wrapping command: [String]) -> [String] {
        guard !command.isEmpty else { return command }
        // The stock guest kernel does not expose the nf_tables netlink API, so
        // the nft-backed iptables shim fails with "Could not fetch rule set
        // generation id" and dockerd cannot create its NAT chain. The legacy
        // backend works, so select it when nft is broken rather than requiring
        // a custom kernel.
        let script = """
            if ! iptables -t nat -L >/dev/null 2>&1; then
              for tool in iptables ip6tables; do
                if [ -x "/usr/sbin/$tool-legacy" ]; then
                  ln -sf "/usr/sbin/$tool-legacy" "/usr/sbin/$tool" 2>/dev/null
                  ln -sf "/usr/sbin/$tool-legacy" "/sbin/$tool" 2>/dev/null
                fi
              done
            fi
            if command -v dockerd >/dev/null 2>&1; then
              mkdir -p /var/log
              dockerd --host=unix:///var/run/docker.sock >/var/log/dockerd.log 2>&1 &
              for i in $(seq 1 60); do
                if docker info >/dev/null 2>&1; then break; fi
                sleep 0.5
              done
              if ! docker info >/dev/null 2>&1; then
                echo "airlock: dockerd did not start; see /var/log/dockerd.log" >&2
              fi
            else
              echo "airlock: --docker given but dockerd is not in this image" >&2
            fi
            exec "$@"
            """
        return ["/bin/sh", "-c", script, "airlock"] + command
    }

    /// Write the MCP configuration, then exec.
    ///
    /// The JSON goes through base64 so quoting in server arguments cannot break
    /// the shell that writes it.
    static func mcpBootstrap(
        wrapping command: [String], path: String, contents: String
    ) -> [String] {
        guard !command.isEmpty else { return command }
        let encoded = Data(contents.utf8).base64EncodedString()
        let script = """
            mkdir -p "$(dirname \(path))"
            printf %s '\(encoded)' | base64 -d > "\(path)" 2>/dev/null \
              || echo "airlock: could not write \(path)" >&2
            exec "$@"
            """
        return ["/bin/sh", "-c", script, "airlock"] + command
    }

    static let cloneSourceDirectory = "/airlock-source"

    /// Clone the read-only source into a writable workspace, then exec.
    ///
    /// `--local` would hardlink into the read-only share, so the clone is made
    /// with `file://` to force a real copy. A repository with no commits yet
    /// cannot be cloned, so that falls back to copying the tree.
    static func cloneBootstrap(wrapping command: [String], destination: String) -> [String] {
        guard !command.isEmpty else { return command }
        let script = """
            set -e
            if [ ! -d "\(destination)/.git" ]; then
              mkdir -p "\(destination)"
              if git -C \(cloneSourceDirectory) rev-parse HEAD >/dev/null 2>&1; then
                git clone --quiet "file://\(cloneSourceDirectory)" "\(destination)"
                git -C "\(destination)" remote set-url origin \
                  "$(git -C \(cloneSourceDirectory) remote get-url origin 2>/dev/null \
                     || echo file://\(cloneSourceDirectory))"
              else
                echo "airlock: no commits to clone; copying the tree instead" >&2
                cp -a \(cloneSourceDirectory)/. "\(destination)/" 2>/dev/null || true
              fi
            fi
            cd "\(destination)"
            exec "$@"
            """
        return ["/bin/sh", "-c", script, "airlock"] + command
    }

    static let guestCertificateDirectory = "/etc/airlock"
    static let guestCertificatePath = "/etc/airlock/airlock-ca.crt"

    /// Variables for runtimes that consult their own trust store rather than
    /// the system bundle. Node in particular ignores the bundle entirely.
    static let trustEnvironment: [String: String] = [
        "NODE_EXTRA_CA_CERTS": guestCertificatePath,
        "REQUESTS_CA_BUNDLE": "/etc/ssl/certs/ca-certificates.crt",
        "CURL_CA_BUNDLE": "/etc/ssl/certs/ca-certificates.crt",
        "GIT_SSL_CAINFO": "/etc/ssl/certs/ca-certificates.crt",
        "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
    ]

    /// Wrap the guest command so the CA is appended to the system bundle before
    /// it runs.
    ///
    /// Appending rather than replacing: pointing the bundle at our CA alone
    /// would stop every other certificate on the internet from verifying.
    static func trustBootstrap(wrapping command: [String]) -> [String] {
        guard !command.isEmpty else { return command }
        let script = """
            if [ -f \(guestCertificatePath) ]; then
              for bundle in /etc/ssl/certs/ca-certificates.crt \
                            /etc/pki/tls/certs/ca-bundle.crt; do
                [ -f "$bundle" ] && cat \(guestCertificatePath) >> "$bundle" 2>/dev/null
              done
            fi
            exec "$@"
            """
        return ["/bin/sh", "-c", script, "airlock"] + command
    }

    /// The vminit image carrying the guest agent. Pinned so a sandbox is
    /// reproducible rather than tracking whatever :latest happens to be.
    public static let initfsReference = "ghcr.io/apple/containerization/vminit:0.41.0"

    /// Remove a cached initfs built from a different vminit reference.
    static func invalidateStaleInitfs(in imagesDirectory: URL) throws {
        let initfs = imagesDirectory.appending(path: "initfs.ext4")
        let marker = imagesDirectory.appending(path: "initfs.reference")

        let recorded = try? String(contentsOf: marker, encoding: .utf8)
        if recorded?.trimmingCharacters(in: .whitespacesAndNewlines) == initfsReference {
            return
        }
        try? FileManager.default.removeItem(at: initfs)
        try FileManager.default.createDirectory(
            at: imagesDirectory, withIntermediateDirectories: true)
        try initfsReference.write(to: marker, atomically: true, encoding: .utf8)
    }

    /// Run an additional process inside the already-running sandbox.
    ///
    /// The process inherits the sandbox's network position exactly: it is in
    /// the same VM behind the same single interface, so policy applies to it
    /// without anything extra being wired up.
    public func exec(
        _ command: [String],
        environment: [String: String] = [:],
        workingDirectory: String? = nil,
        stdout: (any Writer)? = nil,
        stderr: (any Writer)? = nil,
        terminal: Bool = false
    ) async throws -> LinuxProcess {
        guard let container else { throw SandboxError.notRunning }
        var config = LinuxProcessConfiguration()
        config.arguments = command
        config.terminal = terminal
        config.stdout = stdout ?? StreamWriter.standardOutput
        config.stderr = stderr ?? StreamWriter.standardError
        config.workingDirectory = workingDirectory ?? spec.workspaceDestination
        for (key, value) in environment {
            config.environmentVariables.append("\(key)=\(value)")
        }
        if spec.privileged {
            config.capabilities = .allCapabilities
        }
        let id = "exec-\(UInt32.random(in: 0..<0xFFFF_FFFF))"
        let process = try await container.exec(id, configuration: config)
        try await process.start()
        return process
    }

    /// Copy a host path into the running sandbox.
    public func copyIn(from source: URL, to destination: String) async throws {
        guard let container else { throw SandboxError.notRunning }
        try await container.copyIn(from: source, to: URL(filePath: destination))
    }

    /// Copy a path out of the running sandbox.
    public func copyOut(from source: String, to destination: URL) async throws {
        guard let container else { throw SandboxError.notRunning }
        try await container.copyOut(from: URL(filePath: source), to: destination)
    }

    /// Run a process with a PTY attached, for an interactive exec.
    ///
    /// Returns the process so the caller can feed it input and resize it.
    public func execInteractive(
        _ command: [String],
        environment: [String: String] = [:],
        workingDirectory: String? = nil,
        input: PipedInput,
        output: any Writer,
        size: Terminal.Size
    ) async throws -> LinuxProcess {
        guard let container else { throw SandboxError.notRunning }
        var config = LinuxProcessConfiguration()
        config.arguments = command
        config.terminal = true
        config.stdin = input
        config.stdout = output
        // stderr stays nil: the PTY already carries it.
        config.workingDirectory = workingDirectory ?? spec.workspaceDestination
        config.environmentVariables.append(
            "TERM=\(environment["TERM"] ?? "xterm-256color")")
        // resize() is a separate RPC that lands shortly after the process
        // starts, so a program that reads its size immediately would see 0x0.
        // COLUMNS and LINES are set from the start for exactly that window.
        config.environmentVariables.append("COLUMNS=\(size.width)")
        config.environmentVariables.append("LINES=\(size.height)")
        for (key, value) in environment where key != "TERM" {
            config.environmentVariables.append("\(key)=\(value)")
        }
        if spec.privileged {
            config.capabilities = .allCapabilities
        }
        let process = try await container.exec(
            "exec-\(UInt32.random(in: 0..<0xFFFF_FFFF))", configuration: config)
        try await process.start()
        try? await process.resize(to: size)
        return process
    }

    /// Flush and hold the root filesystem still, run `body`, then release it.
    ///
    /// Copying a live filesystem can capture a half-written state. Freezing
    /// first makes the copy consistent; the thaw runs even if `body` throws,
    /// because leaving a sandbox frozen would wedge it.
    public func withFrozenFilesystem<T: Sendable>(
        _ body: @Sendable () async throws -> T
    ) async throws -> T {
        guard let container else { throw SandboxError.notRunning }
        try await container.filesystemOperation(operation: .freeze, path: "/")
        do {
            let result = try await body()
            try? await container.filesystemOperation(operation: .thaw, path: "/")
            return result
        } catch {
            try? await container.filesystemOperation(operation: .thaw, path: "/")
            throw error
        }
    }

    /// Tell the guest its terminal changed size.
    public func resize(to size: Terminal.Size) async throws {
        guard let container else { throw SandboxError.notRunning }
        try await container.resize(to: size)
    }

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
