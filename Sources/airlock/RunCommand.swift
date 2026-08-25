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
        name: .long,
        help: """
            Grant every Linux capability inside the sandbox. Does not weaken             egress policy, which is enforced outside the guest.
            """)
    var privileged: Bool = false

    func run() async throws {
        let policy = try NetworkPolicy(allow: allow, deny: deny)
        let id = name ?? "airlock-\(UInt32.random(in: 0..<0xFFFF_FFFF))"

        // captureForPassthrough hands us the `--` separator too; the guest must
        // not see it as argv[0].
        var command = self.command
        if command.first == "--" { command.removeFirst() }

        var spec = SandboxSpec(
            id: id,
            image: image,
            command: command,
            policy: policy,
            cpus: cpus,
            memoryInBytes: try Self.parseMemory(memory),
            privileged: privileged
        )
        if let workspace {
            spec.workspace = URL(filePath: workspace).standardizedFileURL
        }

        let paths = AirlockPaths()
        let sandbox = Sandbox(spec: spec, paths: paths)
        let gateway = InstallLayout.gatewayBinary()

        if policy.allow.isEmpty {
            FileHandle.standardError.write(
                Data("airlock: no --allow rules; this sandbox reaches nothing\n".utf8))
        }

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
        if status != 0 { throw ExitCode(status) }
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
