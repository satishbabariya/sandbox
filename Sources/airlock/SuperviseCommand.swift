import AirlockKit
import ArgumentParser
import Containerization
import Darwin
import Foundation

/// The process that holds a detached sandbox.
///
/// Not meant to be typed by hand — `airlock run --detach` spawns it. It boots
/// the sandbox, serves a control socket, and stays alive until asked to stop,
/// which is what lets `airlock exec` reach a sandbox after the launching
/// command has exited.
struct SuperviseCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "supervise",
        abstract: "Hold a detached sandbox. Spawned by 'airlock run --detach'.",
        shouldDisplay: false
    )

    @Option(name: .long, help: "Path to the serialised launch spec.")
    var spec: String

    func run() async throws {
        let data = try Data(contentsOf: URL(filePath: spec))
        let launch = try JSONDecoder().decode(LaunchSpec.self, from: data)

        let paths = AirlockPaths()
        let store = SandboxStore(paths: paths)
        let logDirectory = paths.socketDirectory(launch.name)
        try FileManager.default.createDirectory(
            at: logDirectory, withIntermediateDirectories: true)

        // A detached sandbox has no terminal to write to, so its streams go to
        // a file the user can read back later.
        let logPath = logDirectory.appending(path: "console.log")
        FileManager.default.createFile(atPath: logPath.path, contents: nil)
        let logHandle = try FileHandle(forWritingTo: logPath)
        let writer = StreamWriter(logHandle)

        let sandbox = Sandbox(
            spec: try launch.sandboxSpec(stdout: writer, stderr: writer),
            paths: paths
        )

        try await sandbox.start(gatewayBinary: InstallLayout.gatewayBinary())

        var record = launch.record
        record.supervisorPID = ProcessInfo.processInfo.processIdentifier
        try store.save(record)

        let socketPath = ControlClient.path(for: launch.name, paths: paths)
        let shutdown = ShutdownSignal()

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
                            guestAddress: AirlockInterface.Defaults.guest,
                            gatewayAddress: AirlockInterface.Defaults.gateway
                        )), to: client)
            case .policyLog:
                ControlServer.send(.policyLog(await sandbox.auditRecords()), to: client)
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
            case .stop:
                ControlServer.send(.exited(status: 0), to: client)
                await shutdown.signal()
            }
            close(client)
        }

        try server.start()
        let serveTask = Task { await server.serve() }

        await shutdown.wait()

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
    private let stream: AirlockKit.OutputStream
    private let lock = NSLock()

    init(fd: Int32, stream: AirlockKit.OutputStream) {
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
