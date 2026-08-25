import AirlockKit
import ArgumentParser
import Foundation

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

    @Argument(help: "Container image to run.")
    var image: String

    @Argument(parsing: .postTerminator, help: "Command to run inside the sandbox, after --.")
    var command: [String] = []

    @Option(name: .customLong("allow"), help: "Permit egress to this host; repeatable.")
    var allow: [String] = []

    @Option(name: .customLong("deny"), help: "Refuse egress to this host; repeatable. Deny wins.")
    var deny: [String] = []

    @Option(name: .long, help: "Sandbox name. Defaults to a generated one.")
    var name: String?

    @Option(name: .long, help: "Number of CPUs.")
    var cpus: Int = 4

    @Option(name: .long, help: "Memory, e.g. 4g or 512m.")
    var memory: String = "4g"

    @Option(name: .shortAndLong, help: "Host directory to mount at /workspace.")
    var workspace: String?

    @Flag(name: .long, help: "Print every policy decision when the sandbox exits.")
    var showPolicyLog: Bool = false

    @Flag(
        name: [.short, .long],
        help: "Leave the sandbox running in the background and print its name.")
    var detach: Bool = false

    @Option(
        name: .long,
        help: """
            Inject a stored secret for this service; repeatable. The guest             receives a sentinel, never the value.
            """)
    var secret: [String] = []

    @Flag(
        name: .long,
        help: """
            Run a private dockerd inside the sandbox, on its own disk. Implies             --privileged. Containers it starts sit behind the same egress             policy. The image must already contain dockerd.
            """)
    var docker: Bool = false

    @Flag(
        name: .long,
        help: """
            Grant every Linux capability inside the sandbox. Does not weaken             egress policy, which is enforced outside the guest.
            """)
    var privileged: Bool = false

    func run() async throws {
        let policy = try NetworkPolicy(allow: allow, deny: deny)
        let id = name ?? "airlock-\(UInt32.random(in: 0..<0xFFFF_FFFF))"
        try SandboxStore.validate(name: id)

        var command = self.command
        if command.first == "--" { command.removeFirst() }

        let paths = AirlockPaths()
        let store = SandboxStore(paths: paths)

        if let existing = try? store.load(id), existing.state == .running {
            throw CleanExit.message(
                "sandbox '\(id)' is already running; use airlock exec \(id) -- <cmd>")
        }

        // A credential is useless if policy forbids reaching its domain, and
        // silently doing nothing would be baffling. Widen for bound domains.
        var launchAllow = allow
        for service in secret {
            guard let binding = CredentialBinding.preset(for: service) else {
                throw ValidationError(
                    "no built-in binding for secret '\(service)'")
            }
            if !launchAllow.contains(binding.domain) {
                launchAllow.append(binding.domain)
            }
        }

        if policy.allow.isEmpty && secret.isEmpty {
            FileHandle.standardError.write(
                Data("airlock: no --allow rules; this sandbox reaches nothing\n".utf8))
        }

        var launch = LaunchSpec(
            name: id,
            image: image,
            command: command,
            allow: launchAllow,
            deny: deny,
            cpus: cpus,
            memoryInBytes: try Self.parseMemory(memory),
            privileged: privileged || docker,
            secrets: secret,
            docker: docker
        )
        if let workspace {
            launch.workspace = URL(filePath: workspace).standardizedFileURL
                .path(percentEncoded: false)
        }

        if detach {
            try await Self.spawnSupervisor(launch: launch, paths: paths, store: store)
            print(id)
            return
        }

        var spec = try launch.sandboxSpec()
        spec.terminal = false
        let sandbox = Sandbox(spec: spec, paths: paths)
        let gateway = InstallLayout.gatewayBinary()

        try store.save(launch.record)
        try await sandbox.start(gatewayBinary: gateway)
        let status = try await sandbox.wait()

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
        try? store.remove(id)
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
