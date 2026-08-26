import AirlockKit
import ArgumentParser
import Foundation

struct AgentsCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "agents",
        abstract: "List and customise agent definitions.",
        discussion: """
            An agent bundles the image, install steps, default egress, and \
            credential it needs, so 'airlock run claude' works without knowing \
            any of them. Drop JSON in ~/.airlock/agents to add your own or \
            override a built-in of the same name.
            """,
        subcommands: [
            AgentsList.self, AgentsShow.self, AgentsEdit.self, AgentsRemove.self,
            AgentsCache.self,
        ],
        defaultSubcommand: AgentsList.self
    )
}

struct AgentsList: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ls",
        abstract: "List available agents.",
        aliases: ["list"]
    )

    func run() async throws {
        let registry = AgentRegistry()
        let cache = RootfsCache()
        let custom = Set(registry.userProfiles().map(\.name))

        var rows = [["NAME", "AGENT", "IMAGE", "READY", "SOURCE"]]
        for profile in registry.all() {
            rows.append([
                profile.name,
                profile.displayName,
                profile.image,
                cache.isCached(profile) ? "yes" : "no",
                custom.contains(profile.name) ? "custom" : "built-in",
            ])
        }
        let widths = (0..<5).map { column in rows.map { $0[column].count }.max() ?? 0 }
        for row in rows {
            print(
                (0..<5).map { column in
                    row[column].padding(
                        toLength: column == 4 ? row[column].count : widths[column],
                        withPad: " ", startingAt: 0)
                }.joined(separator: "  "))
        }
    }
}

struct AgentsShow: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "show",
        abstract: "Print an agent's full definition."
    )

    @Argument(help: "Agent name.")
    var name: String

    func run() async throws {
        let profile = try AgentRegistry().profile(named: name)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        print(String(decoding: try encoder.encode(profile), as: UTF8.self))
    }
}

struct AgentsEdit: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "edit",
        abstract: "Write an agent's definition to ~/.airlock/agents so you can change it."
    )

    @Argument(help: "Agent name. A new name scaffolds from the shell agent.")
    var name: String

    func run() async throws {
        let registry = AgentRegistry()
        var profile: AgentProfile
        if let existing = try? registry.profile(named: name) {
            profile = existing
        } else {
            profile = try registry.profile(named: "shell")
            profile.name = name
            profile.displayName = name
        }
        try registry.write(profile)
        let path = registry.agentsDirectory.appending(path: "\(name).json")
        print("wrote \(path.path)")
        print("edit it, then: airlock run \(name)")
    }
}

struct AgentsCache: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "cache",
        abstract: "Inspect or clear prepared agent environments."
    )

    @Flag(name: .long, help: "Delete every cached environment.")
    var clear: Bool = false

    @Option(name: .long, help: "Delete just this agent's cached environment.")
    var rm: String?

    func run() async throws {
        let cache = RootfsCache()
        if let rm {
            let profile = try AgentRegistry().profile(named: rm)
            try await cache.remove(profile)
            print("removed cached environment for '\(rm)'")
            return
        }
        if clear {
            try await cache.removeAll()
            print("cleared all cached environments")
            return
        }
        let entries = cache.list()
        guard !entries.isEmpty else {
            print("no cached environments")
            return
        }
        var total: UInt64 = 0
        for entry in entries {
            total += entry.bytes
            print("\(entry.key)  \(Self.human(entry.bytes))")
        }
        print("total  \(Self.human(total))")
    }

    static func human(_ bytes: UInt64) -> String {
        let units = ["B", "KiB", "MiB", "GiB"]
        var value = Double(bytes)
        var unit = 0
        while value >= 1024, unit < units.count - 1 {
            value /= 1024
            unit += 1
        }
        return String(format: "%.1f %@", value, units[unit])
    }
}

/// Removes a custom agent.
///
/// `kit import` creates these, so there has to be a way to get rid of one --
/// otherwise trying a kit means editing ~/.airlock/agents by hand afterwards.
struct AgentsRemove: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "rm",
        abstract: "Remove a custom agent.",
        aliases: ["remove"]
    )

    @Argument(help: "Agent name.")
    var name: String

    func run() async throws {
        let registry = AgentRegistry()
        try registry.remove(name)
        // A custom profile can shadow a built-in, in which case removing it
        // brings the built-in back rather than leaving nothing.
        if AgentProfile.builtIns.contains(where: { $0.name == name }) {
            print("removed custom '\(name)'; the built-in is in use again")
        } else {
            print("removed '\(name)'")
        }
    }
}
