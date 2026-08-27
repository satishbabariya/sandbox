import ArgumentParser
import Foundation
import SandboxKit

struct ConfigCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "config",
        abstract: "Defaults applied to every sandbox.",
        discussion: """
            Settings live in ~/.sandbox/config.json. Flags override them, with \
            one exception: 'deny' is additive and cannot be weakened by a flag, \
            so a block set here holds for every sandbox on the machine.
            """,
        subcommands: [ConfigShow.self, ConfigSet.self, ConfigUnset.self, ConfigPath.self]
    )

    static let knownKeys = ["defaultAgent", "cpus", "memory", "allow", "deny", "clone", "secrets"]
}

struct ConfigShow: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "show",
        abstract: "Print the current settings."
    )

    func run() async throws {
        let config = try SandboxConfig.load()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        print(String(decoding: try encoder.encode(config), as: UTF8.self))

        let path = SandboxConfig.path()
        if !FileManager.default.fileExists(atPath: path.path) {
            print("")
            print("(no config file yet; these are the built-in defaults)")
        }
    }
}

struct ConfigSet: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "set",
        abstract: "Change a setting.",
        discussion: """
            List settings take repeated values:
              sandbox config set allow '*.internal.corp' registry.example.com
            """
    )

    @Argument(help: "Setting name.")
    var key: String

    @Argument(help: "Value, or several for a list setting.")
    var values: [String] = []

    func run() async throws {
        var config = try SandboxConfig.load()
        guard let first = values.first else {
            throw ValidationError("no value given; use 'sandbox config unset \(key)' to clear it")
        }

        switch key {
        case "defaultAgent":
            // Fail here rather than at the next run, where the error would be
            // detached from the change that caused it.
            _ = try AgentRegistry().profile(named: first)
            config.defaultAgent = first
        case "cpus":
            guard let count = Int(first) else {
                throw ValidationError("cpus must be a number")
            }
            config.cpus = count
        case "memory":
            _ = try RunCommand.parseMemory(first)
            config.memory = first
        case "clone":
            config.clone = (first as NSString).boolValue
        case "allow":
            config.allow = values
        case "deny":
            config.deny = values
        case "secrets":
            config.secrets = values
        default:
            throw ConfigError.unknownKey(key, known: ConfigCommand.knownKeys)
        }

        try config.validate()
        try config.save()
        print("set \(key)")
    }
}

struct ConfigUnset: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "unset",
        abstract: "Clear a setting, restoring the built-in default."
    )

    @Argument(help: "Setting name.")
    var key: String

    func run() async throws {
        var config = try SandboxConfig.load()
        switch key {
        case "defaultAgent": config.defaultAgent = nil
        case "cpus": config.cpus = nil
        case "memory": config.memory = nil
        case "clone": config.clone = nil
        case "allow": config.allow = []
        case "deny": config.deny = []
        case "secrets": config.secrets = []
        default:
            throw ConfigError.unknownKey(key, known: ConfigCommand.knownKeys)
        }
        try config.save()
        print("unset \(key)")
    }
}

struct ConfigPath: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "path",
        abstract: "Print where the config file lives."
    )

    func run() async throws {
        print(SandboxConfig.path().path)
    }
}
