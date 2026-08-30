import ArgumentParser
import Containerization
import ContainerizationOS
import Darwin
import Foundation
import SandboxKit

/// The process that holds a detached sandbox.
///
/// Not meant to be typed by hand — `sandbox run --detach` spawns it. It boots
/// the sandbox, serves a control socket, and stays alive until asked to stop,
/// which is what lets `sandbox exec` reach a sandbox after the launching
/// command has exited.
struct SuperviseCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "supervise",
        abstract: "Hold a detached sandbox. Spawned by 'sandbox run --detach'.",
        shouldDisplay: false
    )

    @Option(name: .long, help: "Path to the serialised launch spec.")
    var spec: String

    func run() async throws {
        // First thing, before any work: a supervisor that wedges during boot
        // used to leave an empty log, which made a ten-minute launch stall
        // impossible to attribute. Every phase below says when it happened.
        FileHandle.standardError.write(Data("supervise: reading spec \(spec)\n".utf8))
        let data = try Data(contentsOf: URL(filePath: spec))
        let launch = try JSONDecoder().decode(LaunchSpec.self, from: data)
        FileHandle.standardError.write(Data("supervise: booting '\(launch.name)'\n".utf8))

        let paths = SandboxPaths()
        let store = SandboxStore(paths: paths)
        let logDirectory = paths.socketDirectory(launch.name)
        try FileManager.default.createDirectory(
            at: logDirectory, withIntermediateDirectories: true)

        // A detached sandbox has no terminal to write to, so its streams go to
        // a file the user can read back later.
        // Bounded: the guest decides how much it prints, and a shell loop
        // fills a disk from in here at hundreds of megabytes a second.
        let logPath = logDirectory.appending(path: "console.log")
        let writer = try RotatingFileWriter(path: logPath)

        var spec = try launch.sandboxSpec(stdout: writer, stderr: writer)
        // The launcher resolves secrets in the user's security session and
        // hands them over on stdin; this process cannot reach the keychain.
        if let handed = try? FileHandle.standardInput.readToEnd(), !handed.isEmpty {
            spec.presetBroker = try? JSONDecoder().decode(BrokerConfiguration.self, from: handed)
        }
        let sandbox = Sandbox(spec: spec, paths: paths)

        try await sandbox.start(gatewayBinary: InstallLayout.gatewayBinary())
        FileHandle.standardError.write(Data("supervise: '\(launch.name)' is up\n".utf8))

        var record = launch.record
        record.supervisorPID = ProcessInfo.processInfo.processIdentifier
        try store.save(record)

        // Also written beside the gateway's pid, because the record is the one
        // thing that can go missing while this process is still holding a VM.
        // Then nothing knows the supervisor exists, and it stays resident with
        // no sandbox to belong to.
        try? Data("\(record.supervisorPID ?? 0)\n".utf8).write(
            to: paths.socketDirectory(launch.name).appending(path: "supervisor.pid"),
            options: .atomic)

        let socketPath = ControlClient.path(for: launch.name, paths: paths)
        let shutdown = ShutdownSignal()

        // The sandbox ends when the command it was started with ends, the way
        // a container does. Without this, nothing noticed the exit: the
        // record said "running" for as long as the supervisor lived, and an
        // exec against the dead init failed with a vmexec error instead of
        // "not running".
        let mainProcess = Task {
            _ = try? await sandbox.wait()
            await shutdown.signal()
        }

        let server = ControlServer(path: socketPath) { request, client in
            switch request {
            case .exec(let command, let environment, let workingDirectory):
                do {
                    let out = ClientWriter(fd: client, stream: .stdout)
                    let err = ClientWriter(fd: client, stream: .stderr)
                    let process = try await sandbox.exec(
                        command,
                        environment: environment,
                        workingDirectory: workingDirectory,
                        stdout: out,
                        stderr: err
                    )
                    ControlServer.send(.started(pid: 0), to: client)
                    let status = try await process.wait()
                    ControlServer.send(.exited(status: status.exitCode), to: client)
                } catch {
                    ControlServer.send(.failure("\(error)"), to: client)
                }
            case .info:
                ControlServer.send(
                    .info(
                        SandboxInfo(
                            name: launch.name,
                            image: launch.image,
                            allow: launch.allow,
                            deny: launch.deny,
                            guestAddress: SandboxInterface.Defaults.guest,
                            gatewayAddress: SandboxInterface.Defaults.gateway
                        )), to: client)
            case .policyLog:
                ControlServer.send(.policyLog(await sandbox.auditRecords()), to: client)
            case .execTTY(let command, let environment, let workingDirectory, let rows, let columns):
                do {
                    let input = PipedInput()
                    let output = ClientWriter(fd: client, stream: .stdout)
                    let process = try await sandbox.execInteractive(
                        command,
                        environment: environment,
                        workingDirectory: workingDirectory,
                        input: input,
                        output: output,
                        size: Terminal.Size(width: columns, height: rows)
                    )
                    ControlServer.send(.started(pid: 0), to: client)

                    // Keep reading the same connection for keystrokes and
                    // window changes while the process runs.
                    let pump = Task.detached {
                        var reader = LineReader(fd: client)
                        while let line = reader.next() {
                            guard
                                let request = try? ControlCodec.decode(
                                    ControlRequest.self, from: line)
                            else { continue }
                            switch request {
                            case .input(let base64):
                                if let data = Data(base64Encoded: base64) {
                                    input.send(data)
                                }
                            case .resize(let rows, let columns):
                                try? await process.resize(
                                    to: Terminal.Size(width: columns, height: rows))
                            case .closeInput:
                                input.finish()
                            default:
                                break
                            }
                        }
                        input.finish()
                    }

                    let status = try await process.wait()
                    pump.cancel()
                    try? await process.delete()
                    ControlServer.send(.exited(status: status.exitCode), to: client)
                } catch {
                    ControlServer.send(.failure("\(error)"), to: client)
                }
            case .input, .resize, .closeInput:
                // Only meaningful inside an interactive exec, where the pump
                // above consumes them.
                break
            case .copyIn(let hostPath, let guestPath):
                do {
                    try await sandbox.copyIn(
                        from: URL(filePath: hostPath), to: guestPath)
                    ControlServer.send(.copied, to: client)
                } catch {
                    ControlServer.send(.failure("\(error)"), to: client)
                }
            case .copyOut(let guestPath, let hostPath):
                do {
                    try await sandbox.copyOut(
                        from: guestPath, to: URL(filePath: hostPath))
                    ControlServer.send(.copied, to: client)
                } catch {
                    ControlServer.send(.failure("\(error)"), to: client)
                }
            case .snapshot(let destination):
                do {
                    // Freeze so the copy cannot capture a half-written state.
                    try await sandbox.withFrozenFilesystem {
                        try TemplateStore(paths: paths).save(
                            from: paths.containerRoot(launch.name)
                                .appending(path: "rootfs.ext4"),
                            as: URL(filePath: destination).deletingPathExtension()
                                .lastPathComponent,
                            overwrite: true)
                    }
                    ControlServer.send(.snapshotted, to: client)
                } catch {
                    ControlServer.send(.failure("\(error)"), to: client)
                }
            case .stop:
                ControlServer.send(.exited(status: 0), to: client)
                await shutdown.signal()
            }
            close(client)
        }

        try server.start()
        let serveTask = Task { await server.serve() }

        await shutdown.wait()

        mainProcess.cancel()
        serveTask.cancel()
        server.stop()
        await sandbox.stop()

        record.supervisorPID = nil
        try? store.save(record)
    }
}

/// Lets the control handler ask the supervisor's main task to wind down.
actor ShutdownSignal {
    private var continuation: CheckedContinuation<Void, Never>?
    private var signalled = false

    func signal() {
        signalled = true
        continuation?.resume()
        continuation = nil
    }

    func wait() async {
        if signalled { return }
        await withCheckedContinuation { continuation = $0 }
    }
}

/// Streams a guest process's output back over the control connection, tagged so
/// the client can keep stdout and stderr apart.
final class ClientWriter: Writer, @unchecked Sendable {
    private let fd: Int32
    private let stream: SandboxKit.OutputStream
    private let lock = NSLock()

    init(fd: Int32, stream: SandboxKit.OutputStream) {
        self.fd = fd
        self.stream = stream
    }

    func write(_ data: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        // Base64 keeps arbitrary process output from breaking the line framing.
        let response = ControlResponse.output(
            stream: stream, base64: data.base64EncodedString())
        guard let frame = try? ControlCodec.encode(response) else { return }
        _ = frame.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
    }

    func close() throws {}
}
