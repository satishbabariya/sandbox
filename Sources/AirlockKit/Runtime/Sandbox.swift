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
                fetch one with: airlock kernel install
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
    /// Drop to this unprivileged user before running the command.
    public var runAsUser: String?
    /// Files written into the guest before the command runs.
    public var files: [GuestFile]
    /// Commands run as root at every start, after the files are written and
    /// before privilege is dropped.
    public var startup: [StartupCommand]
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
        runAsUser: String? = nil,
        files: [GuestFile] = [],
        startup: [StartupCommand] = [],
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
        self.runAsUser = runAsUser
        self.files = files
        self.startup = startup
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

    /// Timing breakdown of start(), printed when AIRLOCK_TRACE is set.
    ///
    /// Start latency is the number a user feels on every command, and guessing
    /// at which phase owns it wasted more time than measuring would have.
    private func trace(_ label: String, since: inout Date) {
        guard ProcessInfo.processInfo.environment["AIRLOCK_TRACE"] != nil else { return }
        let elapsed = Date().timeIntervalSince(since)
        FileHandle.standardError.write(
            Data(
                (("  trace " + label.padding(toLength: 22, withPad: " ", startingAt: 0))
                    + String(format: " %6.2fs\n", elapsed)).utf8))
        since = Date()
    }

    /// Bring the sandbox up and return once its process has been started.
    public func start(gatewayBinary: URL) async throws {
        var mark = Date()
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
        trace("gateway", since: &mark)

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
        let interface = try AirlockInterface(link: link, macAddress: "5a:94:ef:e4:0c:de")

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
            if ProcessInfo.processInfo.environment["AIRLOCK_TRACE"] != nil {
                config.bootLog = .file(
                    path: runtimeDir.appending(path: "boot.log"))
            }
            config.cpus = spec.cpus
            config.memoryInBytes = spec.memoryInBytes
            config.interfaces = [interface]
            // The gateway is the only resolver the sandbox can reach, which is
            // what lets policy gate name resolution as well as dialling.
            config.dns = DNS(nameservers: [AirlockInterface.Defaults.gateway])
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
            config.process.arguments = Self.filesBootstrap(
                wrapping: config.process.arguments, files: spec.files)

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

            // Applied last, so it is the outermost wrapper and runs before
            // every other bootstrap. Anything they start -- dockerd, an MCP
            // server, a kit's startup daemon -- would otherwise pay the same
            // resolver timeout on its own hostname.
            config.process.arguments = Self.hostnameBootstrap(
                wrapping: config.process.arguments)

            for mount in spec.mounts {
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
                if ProcessInfo.processInfo.environment["AIRLOCK_TRACE"] != nil {
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
                networking: false,  // airlock supplies the interface itself
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

    /// Create an unprivileged user if the image lacks one, hand it the
    /// workspace and a home, and exec the command as that user.
    ///
    /// Applied last so the CA install, MCP config, clone and dockerd bootstraps
    /// have all completed their root-only work first.
    static func dropPrivilegeBootstrap(
        wrapping command: [String], user: String, workspace: String, cloned: Bool
    ) -> [String] {
        guard !command.isEmpty else { return command }
        // A cloned workspace is a real tree in the rootfs, created moments ago
        // by the clone step running as root, so the agent cannot write it until
        // it is chowned. A shared workspace is virtiofs, which presents host
        // ownership whatever the guest asks for: recursing there changed
        // nothing and still walked every file, which cost 20s of startup on a
        // 45k-file repository.
        let workspaceOwnership =
            cloned ? "chown -R \"$TARGET_UID\" \"\(workspace)\" 2>/dev/null || true" : ":"
        let script = """
            RUN_AS=\(user)
            if ! id -u "$RUN_AS" >/dev/null 2>&1; then
              # Many agent images already ship an unprivileged user at 1000 —
              # node:22 has "node" — and creating another there fails as
              # non-unique. Reuse whoever is already there.
              EXISTING=$(getent passwd 1000 2>/dev/null | cut -d: -f1)
              if [ -n "$EXISTING" ]; then
                RUN_AS="$EXISTING"
              else
                # busybox/alpine and shadow/debian disagree on flags, so try
                # both and keep their usage output off the agent's stdout.
                adduser -D -u 1000 "$RUN_AS" >/dev/null 2>&1 \
                  || useradd -m -u 1000 -s /bin/sh "$RUN_AS" >/dev/null 2>&1 \
                  || true
              fi
            fi
            TARGET_UID=$(id -u "$RUN_AS" 2>/dev/null)
            if [ -z "$TARGET_UID" ]; then
              echo "airlock: no unprivileged user available; running as root" >&2
              exec "$@"
            fi
            TARGET_GID=$(id -g "$RUN_AS" 2>/dev/null || echo "$TARGET_UID")
            HOME_DIR=$(getent passwd "$RUN_AS" 2>/dev/null | cut -d: -f6)
            [ -n "$HOME_DIR" ] || HOME_DIR=/home/"$RUN_AS"
            mkdir -p "$HOME_DIR"
            # Earlier bootstraps staged the agent's config into root's home.
            for item in .claude .claude.json .codex .gemini .config .mcp.json; do
              [ -e "/root/$item" ] && cp -a "/root/$item" "$HOME_DIR/" 2>/dev/null
            done
            chown -R "$TARGET_UID" "$HOME_DIR" 2>/dev/null || true
            \(workspaceOwnership)
            # Installing packages is a normal thing for an agent to do, and it
            # cannot as an unprivileged user. This is still a VM whose egress is
            # enforced outside it, so root here buys the agent nothing beyond
            # its own sandbox.
            if command -v sudo >/dev/null 2>&1; then
              mkdir -p /etc/sudoers.d
              echo "$RUN_AS ALL=(ALL) NOPASSWD: ALL" >/etc/sudoers.d/airlock 2>/dev/null || true
              chmod 0440 /etc/sudoers.d/airlock 2>/dev/null || true
            fi
            export HOME="$HOME_DIR"
            export USER="$RUN_AS"
            # setpriv wants numeric ids, not names.
            if command -v setpriv >/dev/null 2>&1; then
              exec setpriv --reuid="$TARGET_UID" --regid="$TARGET_GID" \
                --init-groups --inh-caps=-all "$@"
            elif command -v su-exec >/dev/null 2>&1; then
              exec su-exec "$TARGET_UID" "$@"
            elif command -v runuser >/dev/null 2>&1; then
              exec runuser -u "$RUN_AS" -- "$@"
            else
              exec su -s /bin/sh -c 'exec "$0" "$@"' "$RUN_AS" -- "$@"
            fi
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

    /// Wrap the guest command so the sandbox's own hostname resolves locally.
    ///
    /// The guest is given a generated hostname that exists in no zone, and the
    /// gateway is its only resolver, so resolving it goes out to the gateway
    /// and is refused -- after the libc resolver has spent its full timeout
    /// retrying. Measured at 10s per lookup, and an unreasonable amount of
    /// ordinary software resolves its own hostname on startup: sudo does it on
    /// every invocation, and Python's HTTPServer does it between bind() and
    /// listen(), so `python3 -m http.server` sat there with a bound socket
    /// refusing connections until it completed.
    static func hostnameBootstrap(wrapping command: [String]) -> [String] {
        guard !command.isEmpty else { return command }
        let script = """
            HOST=$(hostname 2>/dev/null)
            if [ -n "$HOST" ] && ! grep -qw "$HOST" /etc/hosts 2>/dev/null; then
              echo "127.0.0.1 $HOST" >>/etc/hosts 2>/dev/null || true
            fi
            exec "$@"
            """
        return ["/bin/sh", "-c", script, "airlock"] + command
    }

    /// Quote a string so a POSIX shell reads it as one literal word.
    ///
    /// Kit content is arbitrary -- launcher scripts, JSON, shell one-liners --
    /// so anything interpolated into a generated script has to be quoted, or a
    /// quote in a kit becomes command injection into the guest's own bootstrap.
    static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// Wrap the guest command so declared files exist before it runs.
    ///
    /// Content travels base64-encoded. It is arbitrary text -- quotes,
    /// newlines, `$`, backticks -- and base64's alphabet cannot terminate the
    /// quoting or be re-read by the shell, which no amount of escaping the raw
    /// bytes would guarantee.
    static func filesBootstrap(wrapping command: [String], files: [GuestFile]) -> [String] {
        guard !command.isEmpty, !files.isEmpty else { return command }

        var lines: [String] = []
        for file in files {
            let path = shellQuote(file.path)
            let encoded = Data(file.content.utf8).base64EncodedString()
            lines.append("mkdir -p \"$(dirname \(path))\" 2>/dev/null || true")
            // Written to a temporary neighbour and moved into place, so a
            // consumer never sees a half-written file.
            lines.append("printf %s \(shellQuote(encoded)) | base64 -d > \(path).airlock-part")
            if let mode = file.mode, !mode.isEmpty {
                lines.append("chmod \(shellQuote(mode)) \(path).airlock-part 2>/dev/null || true")
            }
            lines.append("mv -f \(path).airlock-part \(path)")
        }
        lines.append("exec \"$@\"")
        return ["/bin/sh", "-c", lines.joined(separator: "\n"), "airlock"] + command
    }

    /// Wrap the guest command so startup commands run first, as root.
    ///
    /// A failing startup command does not stop the sandbox. These reconcile
    /// state and start helpers; refusing to launch the agent because a helper
    /// declined would make a sandbox less useful than one without the kit.
    /// The failure is reported so it is not silent.
    static func startupBootstrap(wrapping command: [String], startup: [StartupCommand])
        -> [String]
    {
        let runnable = startup.filter { !$0.argv.isEmpty }
        guard !command.isEmpty, !runnable.isEmpty else { return command }

        var lines: [String] = []
        for (index, step) in runnable.enumerated() {
            let quoted = step.argv.map(shellQuote).joined(separator: " ")
            if step.background {
                // A daemon's output would otherwise interleave with the
                // agent's, so it goes to a log the user can read afterwards.
                let log = "/tmp/airlock-startup-\(index).log"
                lines.append("\(quoted) >\(log) 2>&1 &")
            } else {
                lines.append(
                    "\(quoted) || echo \"airlock: startup command failed: "
                        + "\(step.argv[0])\" >&2")
            }
        }
        lines.append("exec \"$@\"")
        return ["/bin/sh", "-c", lines.joined(separator: "\n"), "airlock"] + command
    }

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
