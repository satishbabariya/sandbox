import Containerization
import ContainerizationEXT4
import ContainerizationOCI
import ContainerizationOS
import Darwin
import Foundation
import Logging
import SystemPackage

public actor Sandbox {
    public let spec: SandboxSpec
    private let paths: SandboxPaths
    private let logger: Logger?

    private var netstack: NetstackSupervisor?
    private var container: LinuxContainer?
    private var manager: ContainerManager?

    public init(spec: SandboxSpec, paths: SandboxPaths = SandboxPaths(), logger: Logger? = nil) {
        self.spec = spec
        self.paths = paths
        self.logger = logger
    }

    public var auditLogPath: URL? {
        netstack?.auditLogPath
    }

    /// Timing breakdown of start(), printed when SANDBOX_TRACE is set.
    ///
    /// Start latency is the number a user feels on every command, and guessing
    /// at which phase owns it wasted more time than measuring would have.
    private func trace(_ label: String, since: inout Date) {
        guard ProcessInfo.processInfo.environment["SANDBOX_TRACE"] != nil else { return }
        let elapsed = Date().timeIntervalSince(since)
        FileHandle.standardError.write(
            Data(
                (("  trace " + label.padding(toLength: 22, withPad: " ", startingAt: 0))
                    + String(format: " %6.2fs\n", elapsed)).utf8))
        since = Date()
    }

    /// Bring the sandbox up and return once its process has been started.
    ///
    /// Wrapped so a missing entitlement is reported with its remedy wherever it
    /// surfaces. Virtualization rejects the configuration rather than the
    /// start, and a plain `swift build` -- or a `swift test`, which rebuilds
    /// the executable -- produces exactly that. It is the first thing a
    /// contributor hits and the last thing they would guess.
    public func start(gatewayBinary: URL) async throws {
        do {
            try await bringUp(gatewayBinary: gatewayBinary)
        } catch {
            throw SandboxError.notEntitled(underlying: error)
        }
    }

    private func bringUp(gatewayBinary: URL) async throws {
        var mark = Date()
        // A kernel image is data, not a program — readable is the right test.
        guard FileManager.default.isReadableFile(atPath: paths.kernel.path) else {
            throw SandboxError.kernelNotFound(paths.kernel)
        }

        // 1. Gateway first: the VM's only NIC is a socket connected to it.
        let socketDir = paths.socketDirectory(spec.id)
        let runtimeDir = paths.runtime(spec.id)
        try createPrivateDirectory(at: runtimeDir)

        let supervisor = NetstackSupervisor(
            binary: gatewayBinary,
            configuration: .init(
                policy: spec.policy,
                runtimeDirectory: socketDir,
                credentials: spec.credentials,
                presetBroker: spec.presetBroker,
                ports: spec.ports
            ),
            logger: logger
        )
        let link = try await supervisor.start()
        self.netstack = supervisor
        trace("gateway", since: &mark)

        // Silently starting without a credential the user asked for would
        // surface later as an opaque 401 from inside the sandbox.
        for service in await supervisor.missingSecrets {
            logger?.warning("no credential for '\(service)'")
            let message =
                "sandbox: no credential for '\(service)'; "
                + "set one with 'sandbox secret set \(service)'\n"
            FileHandle.standardError.write(Data(message.utf8))
        }
        for service in await supervisor.expiredSecrets {
            let message =
                "sandbox: the sign-in for '\(service)' has expired; "
                + "sign in again on the host, or run 'sandbox secret set \(service)'\n"
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

        // Seed state mounts before configuring. A mount marked `state` is the
        // agent's own persistent copy of its configuration: created from the
        // host's the first time, shared read-write ever after, so what the
        // agent writes survives between runs and the host's original is never
        // touched. The copy is a host-side APFS clone -- the alternative,
        // copying inside the guest, cost 45 seconds of every start for a
        // 700 MB ~/.claude.
        var stateLinks: [(destination: String, target: String)] = []
        let stateMounts = spec.mounts.filter(\.state)
        if !stateMounts.isEmpty {
            guard let stateHome = spec.stateDirectory else {
                throw SandboxError.stateNeedsAgent(
                    destination: stateMounts[0].destination)
            }
            try createPrivateDirectory(at: stateHome)
            for mount in stateMounts {
                let item = URL(filePath: mount.destination).lastPathComponent
                let kept = stateHome.appending(path: item)
                if !FileManager.default.fileExists(atPath: kept.path),
                    FileManager.default.fileExists(atPath: mount.source.path)
                {
                    // Copy to a temporary name and rename: a seed interrupted
                    // halfway must not leave a partial copy that every later
                    // run trusts as the real thing. The rename is atomic; the
                    // orphaned temporary of a killed run is swept here too.
                    let staging = stateHome.appending(path: ".seeding-\(item)")
                    try? FileManager.default.removeItem(at: staging)
                    FileHandle.standardError.write(
                        Data("sandbox: keeping a copy of \(mount.source.path) for this agent (first run)\n".utf8))
                    do {
                        try FileManager.default.copyItem(at: mount.source, to: staging)
                        try FileManager.default.moveItem(at: staging, to: kept)
                    } catch {
                        try? FileManager.default.removeItem(at: staging)
                        logger?.warning(
                            "could not seed \(item) from \(mount.source.path): \(error)")
                    }
                }
                stateLinks.append((mount.destination, "\(Self.guestStateDirectory)/\(item)"))
            }
        }

        // Stage copies before configuring, so a mount marked `copy` shares a
        // duplicate the guest may rewrite without reaching the host's own.
        var stagedMounts: [String: URL] = [:]
        let stagingRoot = runtimeDir.appending(path: "mounts")
        for mount in spec.mounts where mount.copy {
            let staged = stagingRoot.appending(
                path: mount.destination
                    .replacingOccurrences(of: "/", with: "_")
                    .trimmingCharacters(in: CharacterSet(charactersIn: "_")))
            try? FileManager.default.removeItem(at: staged)
            try FileManager.default.createDirectory(
                at: stagingRoot, withIntermediateDirectories: true)
            do {
                try FileManager.default.copyItem(at: mount.source, to: staged)
                stagedMounts[mount.destination] = staged
            } catch {
                // A missing source is normal — the user may never have run the
                // agent on this host. Starting without it beats refusing.
                logger?.info("could not stage \(mount.source.path): \(error)")
            }
        }

        let caCertificate = supervisor.caCertificatePath
        let caIsPresent = FileManager.default.fileExists(atPath: caCertificate.path)
        let guestShare = supervisor.guestShareDirectory

        // 2. The VM. One interface, no vmnet, no NAT, no host route.
        let interface = try SandboxInterface(link: link, macAddress: "5a:94:ef:e4:0c:de")

        trace("interface", since: &mark)
        let kernel = Kernel(path: paths.kernel, platform: .linuxArm)
        try FileManager.default.createDirectory(at: paths.images, withIntermediateDirectories: true)
        let contentStore = try LocalContentStore(path: paths.images.appending(path: "content"))
        let imageStore = try ImageStore(path: paths.images, contentStore: contentStore)

        // ContainerManager reuses an existing initfs.ext4 whatever reference it
        // is asked for, so bumping the vminit version would otherwise keep
        // booting the old guest agent. Track what produced the cached one and
        // discard it when the pin moves.
        try Self.invalidateStaleInitfs(in: paths.images)

        trace("stores", since: &mark)
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

        trace("manager+initfs", since: &mark)
        let spec = self.spec
        let configure: (inout LinuxContainer.Configuration) throws -> Void = { config in
            // Guest boot is the dominant cost of a warm start, and without the
            // kernel's own log there is no way to see which phase owns it.
            if ProcessInfo.processInfo.environment["SANDBOX_TRACE"] != nil {
                config.bootLog = .file(
                    path: runtimeDir.appending(path: "boot.log"))
            }
            config.cpus = spec.cpus
            config.memoryInBytes = spec.memoryInBytes
            config.interfaces = [interface]
            // The gateway is the only resolver the sandbox can reach, which is
            // what lets policy gate name resolution as well as dialling.
            config.dns = DNS(nameservers: [SandboxInterface.Defaults.gateway])
            if spec.runAsRoot || spec.runAsUser != nil {
                // When the privilege drop is ours, the container must start
                // as root whatever USER the image bakes in. The kit images
                // from Docker's own templates ship USER agent, which silently
                // made every root-assuming bootstrap -- the CA trust, kit
                // startup commands, the /workspace compat link -- run
                // unprivileged and fail, some of them into 2>/dev/null.
                config.process.user = ContainerizationOCI.User(uid: 0, gid: 0)
            }
            config.process.terminal = spec.terminal
            if spec.privileged {
                config.process.capabilities = .allCapabilities
                // Docker's own --privileged clears these too. dockerd writes
                // sysctls to set up its bridge, and /proc/sys being read-only
                // makes it fail at "failed to set IP forwarding".
                config.maskedPaths = []
                config.readonlyPaths = []
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

            if let user = spec.runAsUser {
                config.process.arguments = Self.dropPrivilegeBootstrap(
                    wrapping: config.process.arguments,
                    user: user,
                    workspace: spec.workspaceDestination,
                    cloned: spec.workspace != nil && spec.cloneWorkspace)
            }

            // Applied after the privilege drop, so it runs before it, as root.
            // Every built-in agent that declares MCP servers also drops
            // privilege and names a path under /root, which an unprivileged
            // process cannot write -- the config never appeared. Writing it as
            // root also puts it where the drop's own copy step expects to find
            // it, which is why .mcp.json is in that list.
            //
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

            // Each wrapper is applied around the last, so the one applied last
            // is outermost and runs first. Startup is applied before files,
            // which puts files first at run time -- a startup command that
            // reads a file the kit declared must find it already there. Both
            // sit outside the privilege drop, so both run as root, which is
            // what kits assume when they write to /usr/local/bin or chown.
            config.process.arguments = Self.startupBootstrap(
                wrapping: config.process.arguments, startup: spec.startup)
            // Only into a clone. The default workspace is a live share of the
            // user's own tree, and a kit dropping a file into their repository
            // is not a thing a sandbox should do. The clone runs before this
            // point, so the tree exists to write into.
            var guestFiles = spec.files
            if let instructions = spec.agentInstructions,
                spec.workspace != nil, spec.cloneWorkspace
            {
                guestFiles.append(
                    GuestFile(
                        path: spec.workspaceDestination + "/" + instructions.filename,
                        content: instructions.content))
            }
            config.process.arguments = Self.filesBootstrap(
                wrapping: config.process.arguments, files: guestFiles)

            if let dockerDisk {
                // dockerd turns this on itself, but only if /proc/sys is
                // writable; setting it here means the daemon finds it already
                // correct rather than depending on that.
                config.sysctl["net.ipv4.ip_forward"] = "1"
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
                    guard let name = binding.environmentVariable else { continue }
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

            // Applied last, so it is the outermost wrapper and runs before
            // every other bootstrap. Anything they start -- dockerd, an MCP
            // server, a kit's startup daemon -- would otherwise pay the same
            // resolver timeout on its own hostname.
            config.process.arguments = Self.hostnameBootstrap(
                wrapping: config.process.arguments)

            // Agents get the workspace at its host path; /workspace stays as
            // a symlink for tools and documentation that learned the old
            // name. Only created where the image does not already have one --
            // replacing a directory an image ships would destroy its content.
            if spec.workspace != nil, spec.workspaceDestination != "/workspace" {
                config.process.arguments = Self.workspaceCompatBootstrap(
                    wrapping: config.process.arguments,
                    destination: spec.workspaceDestination)
            }

            for mount in spec.mounts where !mount.state {
                // A copy mount shares a staged duplicate, so the guest can
                // write freely and the host's originals are untouchable.
                let source =
                    mount.copy
                    ? (stagedMounts[mount.destination] ?? mount.source)
                    : mount.source
                config.mounts.append(
                    .share(
                        source: source.path(percentEncoded: false),
                        destination: mount.destination,
                        options: mount.readOnly ? ["ro"] : []
                    ))
            }

            // State mounts arrive as one share of the agent's state home, with
            // symlinks placed at each declared destination -- linking rather
            // than mounting item-by-item because a share must be a directory,
            // and .claude.json is a file.
            if let stateHome = spec.stateDirectory, !stateLinks.isEmpty {
                config.mounts.append(
                    .share(
                        source: stateHome.path(percentEncoded: false),
                        destination: Self.guestStateDirectory
                    ))
                config.process.arguments = Self.stateBootstrap(
                    wrapping: config.process.arguments, links: stateLinks)
            }
        }

        let container: LinuxContainer
        if let prepared = spec.preparedRootfs {
            // A prepared rootfs already has the agent installed; unpacking the
            // base image again would throw that away.
            // Only the image's config is needed here; the filesystem comes
            // from the prepared rootfs. Asking the store to pull makes every
            // start wait on a registry round trip for something already local.
            let image: Containerization.Image
            if let local = try? await imageStore.get(reference: spec.image, pull: false) {
                image = local
            } else {
                image = try await imageStore.get(reference: spec.image, pull: true)
            }
            let target = containerRoot.appending(path: "rootfs.ext4")
            try FileManager.default.createDirectory(
                at: containerRoot, withIntermediateDirectories: true)
            try? FileManager.default.removeItem(at: target)
            let cloned = clonefile(
                prepared.path(percentEncoded: false),
                target.path(percentEncoded: false), 0)
            if cloned != 0 {
                // A full copy of a multi-hundred-megabyte rootfs takes many
                // seconds and happens on every start, so it is worth knowing
                // when the clone did not take.
                logger?.warning(
                    "clonefile failed (errno \(errno)); copying the rootfs instead")
                if ProcessInfo.processInfo.environment["SANDBOX_TRACE"] != nil {
                    FileHandle.standardError.write(
                        Data("  trace clonefile failed, errno \(errno)\n".utf8))
                }
                try FileManager.default.copyItem(at: prepared, to: target)
            }
            trace("rootfs clone", since: &mark)
            container = try await mgr.create(
                spec.id,
                image: image,
                rootfs: .block(
                    format: "ext4",
                    source: target.path(percentEncoded: false),
                    destination: "/",
                    // A sandbox rootfs is a throwaway clone of a cached image.
                    // fsync durability costs seconds of boot time to protect
                    // data that is discarded when the sandbox exits, and
                    // "cached" lets the host page cache serve repeat starts.
                    runtimeOptions: [
                        "vzDiskImageSynchronizationMode=none",
                        "vzDiskImageCachingMode=cached",
                    ]
                ),
                networking: false,
                configuration: configure
            )
        } else {
            container = try await mgr.create(
                spec.id,
                reference: spec.image,
                networking: false,  // sandbox supplies the interface itself
                configuration: configure
            )
        }
        trace("create", since: &mark)
        self.manager = mgr
        self.container = container

        try await container.create()
        trace("container.create", since: &mark)
        try await container.start()
        trace("container.start", since: &mark)
        logger?.info("sandbox started", metadata: ["id": .string(spec.id)])
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
    /// What every process in this sandbox should inherit: the trust variables
    /// that make the gateway's CA acceptable to runtimes that keep their own
    /// stores, the credential sentinels, and the profile's environment.
    ///
    /// The main command gets all of this assembled at boot. An exec'd process
    /// used to get none of it, which meant Node inside an exec failed TLS
    /// against the gateway with SELF_SIGNED_CERT_IN_CHAIN -- the exact class
    /// of failure the boot-time wrapping exists to prevent.
    private var execBaseEnvironment: [String: String] {
        var env: [String: String] = [:]
        if netstack != nil {
            for (key, value) in Self.trustEnvironment { env[key] = value }
        }
        for binding in spec.credentials {
            guard let name = binding.environmentVariable else { continue }
            env[name] = CredentialBinding.sentinel
        }
        for (key, value) in spec.environment { env[key] = value }
        return env
    }

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
        for (key, value) in execBaseEnvironment.merging(environment) { _, caller in caller } {
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
        for (key, value) in execBaseEnvironment.merging(environment) { _, caller in caller }
        where key != "TERM" {
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
