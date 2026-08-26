import AirlockKit
import ArgumentParser
import Foundation

struct SnapshotCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "snapshot",
        abstract: "Save a sandbox's filesystem as a reusable template.",
        discussion: """
            An agent environment is reproducible from its profile. A template is \
            the other thing: a sandbox you configured by hand — extra packages, a \
            checked-out branch, a logged-in CLI — captured so the next one starts \
            from it.

            The filesystem is frozen for the copy, so the template is consistent \
            rather than a snapshot of a half-written state.
            """
    )

    @Argument(help: "Running sandbox to capture.")
    var sandbox: String

    @Argument(help: "Template name.")
    var template: String

    @Flag(name: .shortAndLong, help: "Replace an existing template.")
    var force: Bool = false

    func run() async throws {
        try SandboxStore.validate(name: template)
        let paths = AirlockPaths()
        let store = TemplateStore(paths: paths)

        if store.exists(template), !force {
            throw TemplateError.alreadyExists(template)
        }

        let record = try SandboxStore(paths: paths).load(sandbox)
        guard record.state == .running else {
            // A stopped sandbox has no supervisor to freeze its filesystem, and
            // copying it unfrozen could capture a torn state.
            throw CleanExit.message(
                "'\(sandbox)' is not running; start it before snapshotting")
        }

        let client = ControlClient(path: ControlClient.path(for: sandbox, paths: paths))
        guard let response = try client.request(.snapshot(destination: template)) else {
            throw CleanExit.message("no response from the sandbox")
        }
        if case .failure(let message) = response {
            throw CleanExit.message("snapshot failed: \(message)")
        }

        let bytes = store.list().first { $0.name == template }?.bytes ?? 0
        print("saved template '\(template)' (\(AgentsCache.human(bytes)))")
        print("start from it with: airlock run --template \(template) <image>")
    }
}

struct TemplatesCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "templates",
        abstract: "List and remove saved templates.",
        subcommands: [TemplatesList.self, TemplatesRemove.self]
    )
}

struct TemplatesList: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ls",
        abstract: "List saved templates.",
        aliases: ["list"]
    )

    func run() async throws {
        let entries = TemplateStore().list()
        guard !entries.isEmpty else {
            print("no templates")
            return
        }
        let width = entries.map(\.name.count).max() ?? 0
        for entry in entries {
            let name = entry.name.padding(toLength: width, withPad: " ", startingAt: 0)
            print("\(name)  \(AgentsCache.human(entry.bytes))  \(ListCommand.age(entry.created))")
        }
    }
}

struct TemplatesRemove: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "rm",
        abstract: "Remove a template.",
        aliases: ["remove"]
    )

    @Argument(help: "Template name.")
    var name: String

    func run() async throws {
        try TemplateStore().remove(name)
        print("removed template '\(name)'")
    }
}
