import AirlockKit
import ArgumentParser
import Containerization
import ContainerizationOS
import Darwin
import Foundation
import Synchronization

struct RunCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "run",
        abstract: "Run a command in a sandbox whose egress it cannot bypass.",
        discussion: """
            The sandbox is a Linux VM with exactly one network device, whose wire is a \
            socket held by this process. Nothing reaches the network unless --allow \
            permits it, and that decision is made outside the guest, so a process \
            running as root inside the sandbox cannot route around it.

            With no --allow, the sandbox reaches nothing.
            """
    )

    @Argument(
        help: "Agent name (see 'airlock agents ls') or a container image. Defaults to the configured agent."
    )
    var target: String?

    @Argument(parsing: .postTerminator, help: "Command to run inside the sandbox, after --.")
    var command: [String] = []

    @Option(name: .customLong("allow"), help: "Permit egress to this host; repeatable.")
    var allow: [String] = []

    @Option(name: .customLong("deny"), help: "Refuse egress to this host; repeatable. Deny wins.")
    var deny: [String] = []

    @Option(name: .long, help: "Sandbox name. Defaults to a generated one.")
    var name: String?

    @Option(name: .long, help: "Number of CPUs. Default 4, or the configured value.")
    var cpus: Int?

    @Option(name: .long, help: "Memory, e.g. 4g or 512m. Default 4g, or the configured value.")
    var memory: String?

    @Option(name: .shortAndLong, help: "Host directory to mount at /workspace. Defaults to the current directory for agents.")
    var workspace: String?

    @Option(name: .shortAndLong, help: "Extra mount, host:guest[:ro]; repeatable.")
    var mount: [String] = []

    @Flag(name: .long, help: "Rebuild the agent's cached environment before running.")
    var rebuild: Bool = false

    @Option(
        name: .long,
        help: "Add an MCP server by name (filesystem, git, github, fetch); repeatable.")
    var mcp: [String] = []

    @Option(name: .long, help: "Start from a saved template instead of a fresh image.")
    var template: String?

    @Flag(
        name: .long,
        help: "Work on a private git clone of the workspace instead of your tree.")
    var clone: Bool = false

    @Flag(
        name: [.customShort("t"), .long],
        inversion: .prefixedNo,
        help: "Attach a terminal. Defaults to on when stdin is a terminal.")
    var tty: Bool = true

    @Option(
        name: [.customShort("p"), .long],
        help: "Publish a sandbox port to the host: [[HOST:]HOSTPORT:]GUESTPORT; repeatable.")
    var publish: [String] = []

    @Flag(name: .long, help: "Print every policy decision when the sandbox exits.")
    var showPolicyLog: Bool = false

    @Flag(
        name: [.short, .long],
        help: "Leave the sandbox running in the background and print its name.")
    var detach: Bool = false

    @Option(
        name: .long,
        help: "Inject a stored secret for this service; repeatable. The guest receives a sentinel, never the value.")
    var secret: [String] = []

    @Flag(
        name: .long,
        help: "Run a private dockerd inside the sandbox, on its own disk. Implies --privileged; the image must contain dockerd.")
    var docker: Bool = false

    @Flag(
        name: .long,
        help: "Grant every Linux capability inside the sandbox. Does not weaken egress policy.")
    var privileged: Bool = false

    /// Phase timings, printed when AIRLOCK_TRACE is set.
    static func trace(_ label: String, since: inout Date) {
        guard ProcessInfo.processInfo.environment["AIRLOCK_TRACE"] != nil else { return }
        FileHandle.standardError.write(
            Data(
                (("  trace " + label.padding(toLength: 22, withPad: " ", startingAt: 0))
                    + String(format: " %6.2fs\n", Date().timeIntervalSince(since))).utf8))
        since = Date()
    }

    func run() async throws {
        var mark = Date()
        var command = self.command
        if command.first == "--" { command.removeFirst() }

        let paths = AirlockPaths()
        let store = SandboxStore(paths: paths)
        let registry = AgentRegistry()
        // A profile that cannot be decoded is not an agent, so the name falls
        // through to being treated as an image and fails with a message about
        // image references. Say what actually happened.
        for (url, error) in registry.profiles().broken {
            FileHandle.standardError.write(
                Data(
                    "airlock: ignoring agent profile \(url.lastPathComponent): \(error)\n"
                        .utf8))
        }
        let gateway = InstallLayout.gatewayBinary()
        let config = try AirlockConfig.load(paths)

        // A bare `airlock run` uses the configured default agent, so the
        // common case is one word.
        guard let target = self.target ?? config.defaultAgent else {
            throw ValidationError(
                "no agent or image given, and no defaultAgent configured; "
                    + "try 'airlock run shell' or 'airlock config set defaultAgent claude'")
        }

        // `airlock run claude` and `airlock run alpine:3.20` are both valid.
        // The registry decides which this is, so a user-defined agent named
        // after an image still wins.
        let profile: AgentProfile? =
            registry.isAgentName(target) ? try registry.profile(named: target) : nil

        // Expanded here rather than at every use, so a bare `alpine:3.20` and
        // a kit's `docker/sandbox-templates:shell` both reach the image store
        // in the form it requires.
        let image = ImageReference.normalised(profile?.image ?? target)
        let id =
            name ?? profile.map { "\($0.name)-\(UInt32.random(in: 0..<0xFFFF))" }
            ?? "airlock-\(UInt32.random(in: 0..<0xFFFF_FFFF))"
        try SandboxStore.validate(name: id)

        // A profile's rules and any config rules are the floor; flags add to
        // them. deny is deliberately additive so a machine-wide block cannot be
        // flagged away.
        // MCP servers run inside the sandbox, so whatever they need to reach
        // becomes part of this sandbox's policy — a server can never reach
        // somewhere the agent could not.
        var servers = profile?.mcp ?? []
        for name in mcp {
            guard let preset = MCPServer.preset(for: name) else {
                throw ValidationError(
                    "unknown MCP server '\(name)'; known: "
                        + MCPServer.presets.keys.sorted().joined(separator: ", "))
            }
            if !servers.contains(where: { $0.name == preset.name }) {
                servers.append(preset)
            }
        }

        // An MCP server is installed while an agent's environment is built and
        // is declared in a file at a path the agent's profile names. A raw
        // image has neither, so the flag could only be silently ignored -- and
        // it would be ignored after booting a VM and running the workload,
        // which is a slow way to find out.
        if !mcp.isEmpty, profile == nil {
            throw ValidationError(
                "--mcp needs an agent: MCP servers are installed into an agent's "
                    + "cached environment and declared where its profile says.\n"
                    + "Run an agent (airlock agents ls), or add the server to a "
                    + "profile with: airlock agents edit <name>")
        }

        let effectiveAllow =
            allow + (profile?.allow ?? []) + config.allow + servers.flatMap(\.allow)
        let effectiveDeny = deny + config.deny
        let effectiveSecrets = secret + (profile?.secrets ?? []) + config.secrets
        let effectiveMounts = mount + (profile?.mounts ?? [])
        let effectiveClone = clone || (config.clone ?? false)
        let effectiveCpus = cpus ?? config.cpus ?? 4
        let effectiveMemory = memory ?? config.memory ?? "4g"
        if command.isEmpty, let profile { command = profile.command }

        let policy = try NetworkPolicy(allow: effectiveAllow, deny: effectiveDeny)
        let forwards = try publish.map(PortForward.parse)

        if let existing = try? store.load(id), existing.state == .running {
            throw CleanExit.message(
                "sandbox '\(id)' is already running; use airlock exec \(id) -- <cmd>")
        }

        // A credential is useless if policy forbids reaching its domain, and
        // silently doing nothing would be baffling. Widen for bound domains.
        var launchAllow = effectiveAllow
        let profileBindings = profile?.bindings ?? []
        for service in effectiveSecrets {
            // A profile imported from a kit brings its own bindings, which can
            // describe a service airlock has no preset for and can name more
            // than one domain.
            let supplied = profileBindings.filter { $0.service == service }
            let resolved =
                supplied.isEmpty
                ? CredentialBinding.preset(for: service).map { [$0] } ?? []
                : supplied
            guard !resolved.isEmpty else {
                throw ValidationError(
                    "no binding for secret '\(service)'; airlock has no preset for it "
                        + "and no profile supplied one")
            }
            for binding in resolved where !launchAllow.contains(binding.domain) {
                launchAllow.append(binding.domain)
            }
        }

        if policy.allow.isEmpty && effectiveSecrets.isEmpty {
            FileHandle.standardError.write(
                Data("airlock: no --allow rules; this sandbox reaches nothing\n".utf8))
        }

        // Say so, rather than leaving the agent quietly without the guidance
        // its kit wrote for it.
        if let instructions = profile?.agentInstructions, !effectiveClone {
            FileHandle.standardError.write(
                Data(
                    ("airlock: not writing \(instructions.filename); it would add a file "
                        + "to your working tree. Use --clone to give the agent its own.\n")
                        .utf8))
        }

        // A template is a filesystem someone configured by hand, so it wins
        // over the agent's reproducible cached environment.
        var preparedRootfs: String?
        if let template {
            let templates = TemplateStore(paths: paths)
            guard templates.exists(template) else {
                throw TemplateError.notFound(template)
            }
            preparedRootfs = templates.path(template).path(percentEncoded: false)
        }

        var profileWithMCP = profile
        if profileWithMCP != nil { profileWithMCP?.mcp = servers }
        if let profile = profileWithMCP, !profile.allInstall.isEmpty, template == nil {
            let preparer = AgentPreparer(paths: paths)
            let cache = RootfsCache(paths: paths)
            if rebuild || !cache.isCached(profile) {
                FileHandle.standardError.write(
                    Data("airlock: preparing '\(profile.name)' (first run only)\n".utf8))
            }
            let rootfs = try await preparer.prepare(
                profile, gatewayBinary: gateway, force: rebuild
            ) { progress in
                if case .installing(let step, let total, let cmd) = progress {
                    // A kit install step is a multi-line program; printing its
                    // first 70 characters spilled a truncated `case` block
                    // across the terminal.
                    FileHandle.standardError.write(
                        Data("  [\(step)/\(total)] \(AgentPreparer.summary(of: cmd))\n".utf8))
                }
            }
            preparedRootfs = rootfs.path(percentEncoded: false)
        }
        Self.trace("agent prepare", since: &mark)

        var launch = LaunchSpec(
            name: id,
            image: image,
            command: command,
            allow: launchAllow,
            deny: effectiveDeny,
            cpus: effectiveCpus,
            memoryInBytes: try Self.parseMemory(effectiveMemory),
            privileged: privileged || docker,
            secrets: effectiveSecrets,
            docker: docker || (profile?.docker ?? false),
            mounts: effectiveMounts,
            preparedRootfs: preparedRootfs,
            agent: profile?.name,
            ports: publish,
            clone: effectiveClone,
            mcp: servers,
            mcpConfigPath: profile?.mcpConfigPath,
            runAsUser: profile?.runAsUser
        )
        launch.environment = profile?.environment ?? [:]
        launch.files = profile?.files ?? []
        launch.startup = profile?.startup ?? []
        launch.agentInstructions = profile?.agentInstructions
        launch.extraBindings = profileBindings
        // An agent with no explicit workspace should see the directory the
        // user is standing in — that is what they mean by running it here.
        if let workspace {
            launch.workspace = URL(filePath: workspace).standardizedFileURL
                .path(percentEncoded: false)
        } else if profile != nil {
            launch.workspace = FileManager.default.currentDirectoryPath
        }

        if detach {
            try await Self.spawnSupervisor(launch: launch, paths: paths, store: store)
            print(id)
            return
        }

        // An agent like Claude Code is a full-screen program: without a PTY it
        // cannot render, and keystrokes never reach it. Attach one whenever we
        // actually have a terminal to attach.
        let interactive = tty && isatty(STDIN_FILENO) == 1 && isatty(STDOUT_FILENO) == 1
        let hostTerminal: Terminal? = interactive ? try? Terminal.current : nil

        var spec = try launch.sandboxSpec(terminal: hostTerminal != nil)
        spec.hostTerminal = hostTerminal
        if hostTerminal != nil {
            // Programs check TERM before drawing anything.
            spec.environment["TERM"] =
                ProcessInfo.processInfo.environment["TERM"]
                ?? "xterm-256color"
            // The PTY resize is a separate call that lands just after the
            // process starts, so seed the size in the environment as well for
            // anything that reads it immediately.
            if let size = try? hostTerminal?.size {
                spec.environment["COLUMNS"] = String(size.width)
                spec.environment["LINES"] = String(size.height)
            }
        }
        let sandbox = Sandbox(spec: spec, paths: paths)

        // Only a sandbox the user can refer to later earns a record. An
        // auto-named foreground run is ephemeral, and persisting it would
        // litter `airlock ls` with entries nobody can act on — including when
        // the run is interrupted before it can clean up.
        let persist = name != nil
        if persist { try store.save(launch.record) }

        if let hostTerminal {
            try hostTerminal.setraw()
        }
        // Always restore the terminal, including on a thrown error — leaving a
        // shell in raw mode makes it unusable.
        defer { hostTerminal?.tryReset() }

        // Ctrl-C must take the sandbox and its gateway with it. Without this
        // the CLI dies and leaves a VM running that the user cannot see.
        let interrupted = Mutex(false)
        let trap = SignalTrap {
            let alreadyHandling = interrupted.withLock { was -> Bool in
                let previous = was
                was = true
                return previous
            }
            // A second Ctrl-C means the user is done waiting.
            if alreadyHandling { Darwin.exit(130) }

            hostTerminal?.tryReset()
            FileHandle.standardError.write(
                Data("\nairlock: stopping sandbox...\n".utf8))
            Task {
                await sandbox.stop()
                Darwin.exit(130)
            }
        }
        trap.arm()
        defer { trap.disarm() }

        Self.trace("pre-start", since: &mark)
        try await sandbox.start(gatewayBinary: gateway)
        Self.trace("start total", since: &mark)
        for forward in forwards {
            FileHandle.standardError.write(
                Data("airlock: published \(forward)\n".utf8))
        }

        let status: Int32
        if let hostTerminal {
            status = try await Self.attach(sandbox, terminal: hostTerminal)
        } else {
            status = try await sandbox.wait()
        }

        Self.trace("wait", since: &mark)
        if showPolicyLog {
            let records = await sandbox.auditRecords()
            if records.isEmpty {
                print("no network decisions recorded")
            } else {
                for r in records {
                    let verdict = r.allowed ? "allow" : "deny "
                    let names = (r.names?.joined(separator: ",")).map { " \($0)" } ?? ""
                    print("\(verdict) \(r.proto) \(r.address):\(r.port) \(r.reason)\(names)")
                }
            }
        }

        await sandbox.stop()
        Self.trace("stop", since: &mark)
        // An ephemeral run leaves nothing behind. Its socket directory is
        // per-sandbox and would otherwise accumulate in /tmp forever, one per
        // invocation.
        if !persist {
            for directory in paths.allDirectories(id) {
                try? FileManager.default.removeItem(at: directory)
            }
        }
        if persist {
            var finished = launch.record
            finished.supervisorPID = nil
            try? store.save(finished)
        }
        if status != 0 { throw ExitCode(status) }
    }

    /// Launch the supervisor that will hold this sandbox after we exit.
    ///
    /// The child is fully detached — its own session, streams redirected — so
    /// closing the terminal that started it does not take the sandbox with it.
    static func spawnSupervisor(
        launch: LaunchSpec, paths: AirlockPaths, store: SandboxStore
    ) async throws {
        let directory = paths.socketDirectory(launch.name)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let specPath = directory.appending(path: "launch.json")
        try JSONEncoder().encode(launch).write(to: specPath, options: .atomic)

        let process = Process()
        process.executableURL = URL(filePath: CommandLine.arguments[0]).resolvingSymlinksInPath()
        process.arguments = ["supervise", "--spec", specPath.path]

        let logPath = directory.appending(path: "supervisor.log")
        FileManager.default.createFile(atPath: logPath.path, contents: nil)
        let log = try FileHandle(forWritingTo: logPath)
        process.standardOutput = log
        process.standardError = log
        process.standardInput = FileHandle.nullDevice
        try process.run()

        // Wait for the control socket, which is the supervisor's own signal
        // that the VM is up and reachable.
        let socket = ControlClient.path(for: launch.name, paths: paths)
        let deadline = Date().addingTimeInterval(180)
        while !FileManager.default.fileExists(atPath: socket.path) {
            guard process.isRunning else {
                let detail = (try? String(contentsOf: logPath, encoding: .utf8)) ?? ""
                throw CleanExit.message(
                    "sandbox failed to start:\n\(detail.suffix(2000))")
            }
            guard Date() < deadline else {
                process.terminate()
                throw CleanExit.message("timed out waiting for sandbox to start")
            }
            try await Task.sleep(for: .milliseconds(100))
        }
    }

    /// Run an interactive session: keep the guest's PTY in step with ours until
    /// the process exits.
    static func attach(_ sandbox: Sandbox, terminal: Terminal) async throws -> Int32 {
        try? await sandbox.resize(to: terminal.size)

        let resizes = AsyncSignalHandler.create(notify: [SIGWINCH])
        return try await withThrowingTaskGroup(of: Int32?.self) { group in
            group.addTask {
                for await _ in resizes.signals {
                    try? await sandbox.resize(to: terminal.size)
                }
                return nil
            }
            group.addTask {
                try await sandbox.wait()
            }
            // The first non-nil result is the exit status; the resize task only
            // ends when cancelled.
            while let result = try await group.next() {
                if let status = result {
                    group.cancelAll()
                    return status
                }
            }
            return 0
        }
    }

    static func parseMemory(_ raw: String) throws -> UInt64 {
        let lower = raw.lowercased()
        let multiplier: UInt64
        let digits: Substring
        if lower.hasSuffix("g") {
            multiplier = 1024 * 1024 * 1024
            digits = lower.dropLast()
        } else if lower.hasSuffix("m") {
            multiplier = 1024 * 1024
            digits = lower.dropLast()
        } else {
            multiplier = 1024 * 1024  // bare numbers are MiB, as in sandboxy
            digits = lower[...]
        }
        guard let value = UInt64(digits), value > 0 else {
            throw ValidationError("invalid memory value '\(raw)'; try 4g or 512m")
        }
        return value * multiplier
    }
}

/// Finds the gateway binary next to the running executable, falling back to the
/// build tree so the CLI works from a checkout without installing.
enum InstallLayout {
    static func gatewayBinary() -> URL {
        if let override = ProcessInfo.processInfo.environment["AIRLOCK_GATEWAY"] {
            return URL(filePath: override)
        }

        let exe = URL(filePath: CommandLine.arguments[0]).resolvingSymlinksInPath()
        var directory = exe.deletingLastPathComponent()

        // An installed layout puts the gateway beside the CLI. A checkout puts
        // the CLI under .build/<triple>/<config>/ and the gateway under
        // .build/bin/, so walk up rather than guessing the depth.
        for _ in 0..<5 {
            for candidate in [
                directory.appending(path: "gvairlock"),
                directory.appending(path: "bin/gvairlock"),
            ] where FileManager.default.isExecutableFile(atPath: candidate.path) {
                return candidate
            }
            let parent = directory.deletingLastPathComponent()
            if parent == directory { break }
            directory = parent
        }
        return exe.deletingLastPathComponent().appending(path: "gvairlock")
    }
}
