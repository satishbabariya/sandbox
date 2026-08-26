import AirlockKit
import ArgumentParser
import Containerization
import ContainerizationOS
import Darwin
import Foundation

struct ExecCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "exec",
        abstract: "Run a command inside a running sandbox.",
        discussion: """
            The command lands in the same VM behind the same single network \
            interface, so the sandbox's egress policy applies to it too.
            """
    )

    @Argument(help: "Sandbox name.")
    var name: String

    @Argument(parsing: .postTerminator, help: "Command to run, after --.")
    var command: [String] = []

    @Option(name: .shortAndLong, help: "Environment variable KEY=VALUE; repeatable.")
    var env: [String] = []

    @Option(name: .long, help: "Working directory inside the sandbox.")
    var workdir: String?

    @Flag(
        name: [.customShort("t"), .long],
        inversion: .prefixedNo,
        help: "Attach a terminal. Defaults to on when stdin is a terminal.")
    var tty: Bool = true

    func run() async throws {
        guard !command.isEmpty else {
            throw ValidationError("no command given; use: airlock exec \(name) -- <cmd>")
        }
        let paths = AirlockPaths()
        let store = SandboxStore(paths: paths)
        let record = try store.load(name)
        guard record.state == .running else {
            throw ControlSocketError.notRunning(name)
        }

        var environment: [String: String] = [:]
        for entry in env {
            let parts = entry.split(separator: "=", maxSplits: 1)
            if parts.count == 2 {
                environment[String(parts[0])] = String(parts[1])
            } else if let value = ProcessInfo.processInfo.environment[entry] {
                environment[entry] = value
            }
        }

        let client = ControlClient(path: ControlClient.path(for: name, paths: paths))

        let interactive = tty && isatty(STDIN_FILENO) == 1 && isatty(STDOUT_FILENO) == 1
        if interactive, let terminal = try? Terminal.current {
            try Self.runInteractive(
                client: client, terminal: terminal, command: command,
                environment: environment, workdir: workdir)
            return
        }

        var exitStatus: Int32 = 0
        var failure: String?

        try client.send(
            .exec(command: command, environment: environment, workingDirectory: workdir)
        ) { response in
            switch response {
            case .output(let stream, let base64):
                guard let data = Data(base64Encoded: base64) else { return true }
                let handle: FileHandle = stream == .stdout ? .standardOutput : .standardError
                try? handle.write(contentsOf: data)
                return true
            case .exited(let status):
                exitStatus = status
                return false
            case .failure(let message):
                failure = message
                return false
            default:
                return true
            }
        }

        if let failure {
            throw CleanExit.message("exec failed: \(failure)")
        }
        if exitStatus != 0 { throw ExitCode(exitStatus) }
    }

    /// Interactive exec: forward keystrokes and window changes on the same
    /// connection that carries the process output back.
    static func runInteractive(
        client: ControlClient, terminal: Terminal, command: [String],
        environment: [String: String], workdir: String?
    ) throws {
        var environment = environment
        environment["TERM"] =
            environment["TERM"] ?? ProcessInfo.processInfo.environment["TERM"]
            ?? "xterm-256color"

        let size = try terminal.size
        try terminal.setraw()
        defer { terminal.tryReset() }

        var exitStatus: Int32 = 0
        var failure: String?

        try client.sendInteractive(
            .execTTY(
                command: command, environment: environment, workingDirectory: workdir,
                rows: UInt16(size.height), columns: UInt16(size.width)),
            terminal: terminal
        ) { response in
            switch response {
            case .output(_, let base64):
                guard let data = Data(base64Encoded: base64) else { return true }
                try? FileHandle.standardOutput.write(contentsOf: data)
                return true
            case .exited(let status):
                exitStatus = status
                return false
            case .failure(let message):
                failure = message
                return false
            default:
                return true
            }
        }

        terminal.tryReset()
        if let failure {
            throw CleanExit.message("exec failed: \(failure)")
        }
        if exitStatus != 0 { throw ExitCode(exitStatus) }
    }
}

struct ListCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ls",
        abstract: "List sandboxes.",
        aliases: ["list"]
    )

    func run() async throws {
        let records = SandboxStore().list()
        guard !records.isEmpty else {
            print("no sandboxes")
            return
        }
        let rows =
            [["NAME", "STATE", "IMAGE", "EGRESS", "CREATED"]]
            + records.map { record in
                [
                    record.name,
                    record.state.rawValue,
                    Self.shortImage(record.image),
                    Self.summariseEgress(record.allow),
                    Self.age(record.createdAt),
                ]
            }
        let widths = (0..<5).map { column in
            rows.map { $0[column].count }.max() ?? 0
        }
        for row in rows {
            let line = (0..<5).map { column in
                row[column].padding(
                    toLength: column == 4 ? row[column].count : widths[column],
                    withPad: " ", startingAt: 0)
            }.joined(separator: "  ")
            print(line)
        }
    }

    /// An agent profile carries a dozen or more rules, and printing them all
    /// makes the table unreadable. Show the first and a count.
    static func summariseEgress(_ allow: [String]) -> String {
        guard let first = allow.first else { return "none" }
        if allow.count == 1 { return first }
        return "\(first) +\(allow.count - 1)"
    }

    /// Registry and namespace are noise in a list; the tag is not.
    static func shortImage(_ reference: String) -> String {
        var text = reference
        for prefix in ["docker.io/library/", "docker.io/", "ghcr.io/"]
        where text.hasPrefix(prefix) {
            text = String(text.dropFirst(prefix.count))
            break
        }
        return text
    }

    static func age(_ date: Date) -> String {
        let seconds = Int(Date().timeIntervalSince(date))
        switch seconds {
        case ..<60: return "\(seconds)s ago"
        case ..<3600: return "\(seconds / 60)m ago"
        case ..<86400: return "\(seconds / 3600)h ago"
        default: return "\(seconds / 86400)d ago"
        }
    }
}

struct StopCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "stop",
        abstract: "Stop a running sandbox, keeping its record."
    )

    @Argument(help: "Sandbox name.")
    var name: String

    func run() async throws {
        let paths = AirlockPaths()
        let store = SandboxStore(paths: paths)
        var record = try store.load(name)
        guard record.state == .running else {
            print("\(name) is already stopped")
            return
        }

        let client = ControlClient(path: ControlClient.path(for: name, paths: paths))
        do {
            _ = try client.request(.stop)
        } catch {
            // The supervisor may already be gone or wedged; fall back to a
            // signal so a broken control socket cannot strand a VM.
            if let pid = record.supervisorPID, ProcessLiveness.isAlive(pid) {
                kill(pid, SIGTERM)
            }
        }

        for _ in 0..<100 {
            if let pid = record.supervisorPID, !ProcessLiveness.isAlive(pid) { break }
            usleep(100_000)
        }
        record.supervisorPID = nil
        try store.save(record)
        print("stopped \(name)")
    }
}

struct RemoveCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "rm",
        abstract: "Remove a sandbox and its record.",
        aliases: ["remove"]
    )

    @Argument(help: "Sandbox name.")
    var name: String

    @Flag(name: .shortAndLong, help: "Stop it first if it is running.")
    var force: Bool = false

    func run() async throws {
        let paths = AirlockPaths()
        let store = SandboxStore(paths: paths)
        let record = try store.load(name)

        if record.state == .running {
            guard force else {
                throw CleanExit.message(
                    "\(name) is running; stop it first or pass --force")
            }
            var stop = StopCommand()
            stop.name = name
            try await stop.run()
        }

        try store.remove(name)
        for directory in paths.allDirectories(name) {
            try? FileManager.default.removeItem(at: directory)
        }
        print("removed \(name)")
    }
}

struct LogsCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "logs",
        abstract: "Show console output from a detached sandbox."
    )

    @Argument(help: "Sandbox name.")
    var name: String

    func run() async throws {
        let paths = AirlockPaths()
        _ = try SandboxStore(paths: paths).load(name)
        let log = paths.socketDirectory(name).appending(path: "console.log")
        guard let data = try? Data(contentsOf: log) else {
            print("no console output recorded for \(name)")
            return
        }
        FileHandle.standardOutput.write(data)
    }
}

struct PruneCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "prune",
        abstract: "Remove every stopped sandbox and its runtime state."
    )

    func run() async throws {
        let paths = AirlockPaths()
        let store = SandboxStore(paths: paths)
        let stopped = store.list().filter { $0.state == .stopped }
        guard !stopped.isEmpty else {
            print("nothing to prune")
            return
        }
        for record in stopped {
            try? store.remove(record.name)
            for directory in paths.allDirectories(record.name) {
                try? FileManager.default.removeItem(at: directory)
            }
            print("removed \(record.name)")
        }
    }
}

struct PortsCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ports",
        abstract: "Show ports published from a sandbox."
    )

    @Argument(help: "Sandbox name.")
    var name: String

    func run() async throws {
        let paths = AirlockPaths()
        _ = try SandboxStore(paths: paths).load(name)
        let specPath = paths.socketDirectory(name).appending(path: "launch.json")
        guard let data = try? Data(contentsOf: specPath),
            let launch = try? JSONDecoder().decode(LaunchSpec.self, from: data)
        else {
            print("no published ports recorded for \(name)")
            return
        }
        guard !launch.ports.isEmpty else {
            print("no published ports")
            return
        }
        for raw in launch.ports {
            if let forward = try? PortForward.parse(raw) {
                print(forward.description)
            }
        }
    }
}
