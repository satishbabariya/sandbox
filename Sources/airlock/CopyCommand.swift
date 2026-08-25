import AirlockKit
import ArgumentParser
import Foundation

struct CopyCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "cp",
        abstract: "Copy files between the host and a running sandbox.",
        discussion: """
            Paths inside a sandbox are written SANDBOX:/path, as with docker cp. \
            Exactly one side must name a sandbox.

              airlock cp ./patch.diff devbox:/workspace/patch.diff
              airlock cp devbox:/workspace/out.log ./out.log
            """,
        aliases: ["copy"]
    )

    @Argument(help: "Source: a host path, or SANDBOX:/path.")
    var source: String

    @Argument(help: "Destination: a host path, or SANDBOX:/path.")
    var destination: String

    func run() async throws {
        let from = Location(source)
        let to = Location(destination)

        switch (from, to) {
        case (.host, .host):
            throw ValidationError(
                "neither path names a sandbox; use SANDBOX:/path on one side")
        case (.sandbox(let a, _), .sandbox(let b, _)):
            throw ValidationError(
                "both paths name sandboxes ('\(a)' and '\(b)'); copy via the host")

        case (.host(let hostPath), .sandbox(let name, let guestPath)):
            let client = try connect(name)
            try perform(client, .copyIn(hostPath: absolute(hostPath), guestPath: guestPath))
            print("copied \(hostPath) -> \(name):\(guestPath)")

        case (.sandbox(let name, let guestPath), .host(let hostPath)):
            let client = try connect(name)
            try perform(client, .copyOut(guestPath: guestPath, hostPath: absolute(hostPath)))
            print("copied \(name):\(guestPath) -> \(hostPath)")
        }
    }

    private func absolute(_ path: String) -> String {
        URL(filePath: path).standardizedFileURL.path(percentEncoded: false)
    }

    private func connect(_ name: String) throws -> ControlClient {
        let paths = AirlockPaths()
        let record = try SandboxStore(paths: paths).load(name)
        guard record.state == .running else {
            throw ControlSocketError.notRunning(name)
        }
        return ControlClient(path: ControlClient.path(for: name, paths: paths))
    }

    private func perform(_ client: ControlClient, _ request: ControlRequest) throws {
        guard let response = try client.request(request) else {
            throw CleanExit.message("no response from the sandbox")
        }
        if case .failure(let message) = response {
            throw CleanExit.message("copy failed: \(message)")
        }
    }

    /// `SANDBOX:/path` names a sandbox; anything else is a host path.
    ///
    /// A Windows-style drive letter is not a concern here, but a relative path
    /// containing a colon would be, so the sandbox side must be a valid name
    /// followed by an absolute path.
    enum Location {
        case host(String)
        case sandbox(String, String)

        init(_ raw: String) {
            guard let colon = raw.firstIndex(of: ":") else {
                self = .host(raw)
                return
            }
            let name = String(raw[raw.startIndex..<colon])
            let path = String(raw[raw.index(after: colon)...])
            guard (try? SandboxStore.validate(name: name)) != nil, path.hasPrefix("/") else {
                self = .host(raw)
                return
            }
            self = .sandbox(name, path)
        }
    }
}
