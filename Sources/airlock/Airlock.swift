import AirlockKit
import ArgumentParser

@main
struct Airlock: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "airlock",
        abstract: "Run coding agents in sandboxes whose network egress they cannot bypass.",
        version: AirlockVersion.current,
        subcommands: [
            RunCommand.self, ExecCommand.self, ListCommand.self,
            StopCommand.self, RemoveCommand.self, LogsCommand.self,
            PruneCommand.self, PortsCommand.self,
            PolicyCommand.self, SecretCommand.self, AgentsCommand.self,
            SuperviseCommand.self,
        ]
    )
}

struct PolicyCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "policy",
        abstract: "Inspect and test network policy.",
        subcommands: [PolicyCheck.self]
    )
}

struct PolicyCheck: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "check",
        abstract: "Report whether a host would be allowed by the given patterns."
    )

    @Argument(help: "Host to test, optionally host:port.")
    var target: String

    @Option(name: .customLong("allow"), help: "Allow pattern; repeatable.")
    var allow: [String] = []

    @Option(name: .customLong("deny"), help: "Deny pattern; repeatable. Deny wins.")
    var deny: [String] = []

    func run() async throws {
        let (host, port) = try SplitTarget.parse(target)
        let policy = try NetworkPolicy(allow: allow, deny: deny)
        let decision = policy.evaluate(host: host, port: port)
        print(decision.render(host: host, port: port))
        if case .denied = decision { throw ExitCode(1) }
    }
}

enum SplitTarget {
    static func parse(_ raw: String) throws -> (String, UInt16?) {
        guard let colon = raw.lastIndex(of: ":"), !raw.hasPrefix("[") else {
            return (raw, nil)
        }
        let after = raw[raw.index(after: colon)...]
        guard let port = UInt16(after) else { return (raw, nil) }
        return (String(raw[raw.startIndex..<colon]), port)
    }
}

extension PolicyDecision {
    func render(host: String, port: UInt16?) -> String {
        let target = port.map { "\(host):\($0)" } ?? host
        switch self {
        case .allowed(let by):
            return "allow  \(target)  (matched allow '\(by)')"
        case .denied(let by):
            if let by {
                return "deny   \(target)  (matched deny '\(by)')"
            }
            return "deny   \(target)  (no allow rule matched)"
        }
    }
}
