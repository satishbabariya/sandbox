import ArgumentParser
import Containerization
import ContainerizationOS
import Darwin
import Foundation
import SandboxKit

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
            throw ValidationError("no command given; use: sandbox exec \(name) -- <cmd>")
        }
        let paths = SandboxPaths()
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
        let paths = SandboxPaths()
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
        let paths = SandboxPaths()
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
        let paths = SandboxPaths()
        _ = try SandboxStore(paths: paths).load(name)
        let log = paths.socketDirectory(name).appending(path: "console.log")
        guard let data = try? Data(contentsOf: log) else {
            print("no console output recorded for \(name)")
            return
        }
        // Console output is capped, so a sandbox that printed a great deal has
        // had its earliest output dropped. Saying so is the difference between
        // output that starts mid-sentence and output that looks complete but
        // is not.
        let rotated = log.appendingPathExtension("prev")
        if FileManager.default.fileExists(atPath: rotated.path) {
            let size =
                (try? FileManager.default.attributesOfItem(atPath: rotated.path)[.size])
                .flatMap { $0 as? Int64 } ?? 0
            FileHandle.standardError.write(
                Data(
                    ("sandbox: this sandbox printed more than the log holds; earlier output "
                        + "was dropped. The previous \(ByteCountFormatter.string(fromByteCount: size, countStyle: .file)) "
                        + "is at \(rotated.path)\n").utf8))
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
        let paths = SandboxPaths()
        let store = SandboxStore(paths: paths)
        var removed = 0

        for record in store.list() where record.state == .stopped {
            try? store.remove(record.name)
            for directory in paths.allDirectories(record.name) {
                try? FileManager.default.removeItem(at: directory)
            }
            print("removed \(record.name)")
            removed += 1
        }

        // Sweep runtime directories with no record behind them. A crash, a
        // kill -9, or an older build that did not clean up leaves these in
        // /tmp, and nothing else would ever remove them.
        let orphans = Self.orphanedRuntimeDirectories(store: store)
        var gateways = 0
        var supervisors = 0
        for directory in orphans {
            // Before the directory goes: the gateway's pid is in it, and the
            // gateway is what actually holds resources. Removing the directory
            // first would leave a process nothing could ever find again.
            // The supervisor first: it owns the VM and the gateway, so
            // stopping it is what actually frees the memory, and it takes the
            // gateway with it on the way out.
            if Self.terminate(pidFile: "supervisor.pid", in: directory) { supervisors += 1 }
            if Self.terminate(pidFile: "gateway.pid", in: directory) { gateways += 1 }
            try? FileManager.default.removeItem(at: directory)
        }
        if !orphans.isEmpty {
            print("removed \(orphans.count) orphaned runtime director\(orphans.count == 1 ? "y" : "ies")")
            removed += orphans.count
        }
        // Rootfs and runtime directories left by runs that were killed. These
        // are the ones that actually cost disk: a rootfs is hundreds of MB.
        let abandoned = Self.abandonedStateDirectories(store: store, paths: paths)
        var reclaimed: Int64 = 0
        for directory in abandoned {
            reclaimed += Self.directorySize(directory)
            try? FileManager.default.removeItem(at: directory)
        }
        if !abandoned.isEmpty {
            print(
                "removed \(abandoned.count) abandoned director\(abandoned.count == 1 ? "y" : "ies")"
                    + ", reclaiming \(ByteCountFormatter.string(fromByteCount: reclaimed, countStyle: .file))")
            removed += abandoned.count
        }

        // Anything whose directory was already gone before this ran, and so
        // could never have been found through a pid file.
        for stray in StrayProcess.all() where ProcessLiveness.isAlive(stray.pid) {
            if kill(stray.pid, SIGTERM) == 0 {
                print("stopped stray \(stray.kind) (\(stray.directory))")
                removed += 1
            }
        }

        if supervisors > 0 {
            print(
                "stopped \(supervisors) orphaned supervisor\(supervisors == 1 ? "" : "s")")
        }
        if gateways > 0 {
            print("stopped \(gateways) orphaned gateway\(gateways == 1 ? "" : "s")")
        }

        if removed == 0 { print("nothing to prune") }
    }

    /// Disk actually occupied by a directory tree.
    ///
    /// Allocated size rather than apparent: a rootfs is a sparse 8GB file
    /// holding a few hundred MB, and reporting the apparent size would claim to
    /// have reclaimed storage that was never used.
    static func directorySize(_ url: URL) -> Int64 {
        guard
            let enumerator = FileManager.default.enumerator(
                at: url, includingPropertiesForKeys: [.totalFileAllocatedSizeKey])
        else { return 0 }
        var total: Int64 = 0
        for case let file as URL in enumerator {
            let size =
                (try? file.resourceValues(forKeys: [.totalFileAllocatedSizeKey])
                    .totalFileAllocatedSize) ?? 0
            total += Int64(size)
        }
        return total
    }

    /// Stop the process whose pid a runtime directory records, if it is alive.
    ///
    /// Returns whether one was actually signalled, so prune can say so rather
    /// than claiming to have tidied something it did not.
    static func terminate(pidFile name: String, in directory: URL) -> Bool {
        let pidFile = directory.appending(path: name)
        guard let text = try? String(contentsOf: pidFile, encoding: .utf8),
            let pid = pid_t(text.trimmingCharacters(in: .whitespacesAndNewlines)),
            pid > 0
        else { return false }

        // A pid file outlives the process it names, and pids are reused, so
        // "something answers to this number" is not enough to signal it.
        // kill(0) only reports existence and permission -- what makes it safe
        // is checking the process is one of ours.
        guard kill(pid, 0) == 0, StrayProcess.isOurs(pid: pid) else { return false }
        return kill(pid, SIGTERM) == 0
    }

    /// Runtime directories under /tmp whose sandbox no longer exists.
    static func orphanedRuntimeDirectories(store: SandboxStore) -> [URL] {
        let known = Set(store.list().map(\.name))
        let temporary = URL(filePath: "/tmp")
        let entries =
            (try? FileManager.default.contentsOfDirectory(
                at: temporary, includingPropertiesForKeys: nil)) ?? []
        return entries.filter { url in
            let name = url.lastPathComponent
            guard name.hasPrefix("sandbox-") else { return false }
            // Directories only. A sandbox's runtime state is a directory, and
            // matching on the prefix alone made this delete any file someone
            // had named sandbox-something in /tmp -- which it has no business
            // touching, and which cost a log file during testing.
            var isDirectory: ObjCBool = false
            guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory),
                isDirectory.boolValue
            else { return false }
            // A record is not what makes a sandbox live. An ephemeral run keeps
            // none by design, so matching on records alone made prune stop the
            // gateway of a sandbox that was still working -- `sandbox run
            // claude` in one terminal lost its network to an `sandbox prune` in
            // another. What settles it is whether the processes it names are
            // still running.
            guard !isInUse(directory: url) else { return false }
            return !known.contains(String(name.dropFirst("sandbox-".count)))
        }
    }

    /// Rootfs and runtime directories under the state directory that no sandbox
    /// owns any more.
    ///
    /// A run that exits normally clears its own. One that is killed -- a
    /// timeout, a crash, a machine going to sleep -- does not, and nothing ever
    /// reclaimed those: 280 of them had accumulated here, holding 52GB, with no
    /// command that would remove one.
    ///
    /// An ephemeral run deliberately keeps no record, so a record is not enough
    /// to tell an abandoned directory from one in use. What settles it is
    /// whether a process still owns the sandbox: every run writes its gateway's
    /// pid, and a foreground one is alive for exactly as long as the user is
    /// using it.
    ///
    /// Age alone was tried first and is not sufficient. A directory's
    /// modification time does not move while a sandbox writes inside its
    /// rootfs, so an interactive session that outlived the margin was treated
    /// as abandoned -- and pruning deleted the rootfs of a running sandbox out
    /// from under it. Age is kept as a second condition, for the case where the
    /// pid files are gone too.
    static func abandonedStateDirectories(
        store: SandboxStore, paths: SandboxPaths, olderThan age: TimeInterval = 3600
    ) -> [URL] {
        let known = Set(store.list().map(\.name))
        let cutoff = Date().addingTimeInterval(-age)
        var found: [URL] = []
        for parent in [paths.runtimeRoot, paths.containerRootParent] {
            let entries =
                (try? FileManager.default.contentsOfDirectory(
                    at: parent, includingPropertiesForKeys: [.contentModificationDateKey])) ?? []
            for url in entries where !known.contains(url.lastPathComponent) {
                guard !isInUse(url.lastPathComponent, paths: paths) else { continue }
                let modified =
                    (try? url.resourceValues(forKeys: [.contentModificationDateKey])
                        .contentModificationDate) ?? Date.distantPast
                if modified < cutoff { found.append(url) }
            }
        }
        return found
    }

    /// Whether a foreground run is using this sandbox right now.
    static func isInUse(_ id: String, paths: SandboxPaths) -> Bool {
        isInUse(directory: paths.socketDirectory(id))
    }

    /// The same question asked of a runtime directory directly.
    ///
    /// Only a foreground run counts. It keeps no record by design -- the user
    /// is looking at it, so there is nothing to look it up by later -- and
    /// treating that as abandoned had prune stop the gateway of a sandbox that
    /// was still working.
    ///
    /// A detached sandbox is the opposite case. It is reachable only through
    /// its record, so one whose record is gone cannot be listed, exec'd into
    /// or stopped, and leaving it running helps nobody. The two are told apart
    /// by supervisor.pid, which only a detached sandbox writes.
    static func isInUse(directory runtime: URL) -> Bool {
        let supervisor = runtime.appending(path: "supervisor.pid")
        guard !FileManager.default.fileExists(atPath: supervisor.path) else { return false }

        guard
            let text = try? String(
                contentsOf: runtime.appending(path: "gateway.pid"), encoding: .utf8),
            let pid = Int32(text.trimmingCharacters(in: .whitespacesAndNewlines))
        else { return false }
        // Identity as well as liveness. A pid file outlives its process and
        // pids are reused, so a stale one pointing at whatever now holds that
        // number would otherwise protect a directory nothing is using.
        return ProcessLiveness.isAlive(pid) && StrayProcess.isOurs(pid: pid)
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
        let paths = SandboxPaths()
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
