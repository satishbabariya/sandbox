import ArgumentParser
import Foundation
import SandboxKit

struct KitCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "kit",
        abstract: "Import Docker Sandboxes kits as agent profiles.",
        discussion: """
            Kits are the extension format Docker Sandboxes uses. This reads a \
            faithful subset and reports what it cannot honour, rather than \
            quietly producing a sandbox the kit author did not describe.
            """,
        subcommands: [KitInspect.self, KitImport.self]
    )
}

struct KitInspect: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "inspect",
        abstract: "Show what a kit would become, without importing it."
    )

    @Argument(help: "Directory containing spec.yaml, or the file itself.")
    var path: String

    @Option(name: .long, help: "Layer a mixin kit on top; repeatable.")
    var with: [String] = []

    @Option(
        name: .long,
        help: """
            Show this kit, itself a mixin, layered onto an existing agent. \
            Defaults to the agent the mixin's requires.agent names.
            """)
    var onto: String?

    func run() async throws {
        let spec = try KitInspect.loadSpec(path)
        let translation: KitTranslation
        if spec.kind == "mixin" {
            if let baseName = onto ?? spec.requires?.agent {
                let base = try AgentRegistry().profile(named: baseName)
                translation = try KitComposer.compose(
                    onto: base, mixins: [spec] + with.map(KitInspect.loadSpec))
                print("(layered onto '\(baseName)')")
            } else {
                // No affinity: show what the mixin would contribute, so its
                // author can still see the translation without inventing a
                // base to hang it on.
                translation = try KitComposer.translateMixin(spec)
                print("(a mixin with no requires.agent; shown alone -- layer it with --onto or --with)")
            }
        } else {
            translation = try KitInspect.translate(path, mixins: with)
        }
        let profile = translation.profile

        print("name:        \(profile.name)")
        print("displayName: \(profile.displayName)")
        print("image:       \(profile.image)")
        if !profile.command.isEmpty {
            print("command:     \(profile.command.joined(separator: " "))")
        }
        if !profile.allow.isEmpty {
            print("allow:       \(profile.allow.count) rule(s)")
            for rule in profile.allow.prefix(6) { print("               \(rule)") }
            if profile.allow.count > 6 { print("               …") }
        }
        if !profile.secrets.isEmpty {
            print("secrets:     \(profile.secrets.joined(separator: ", "))")
        }
        if !profile.install.isEmpty {
            print("install:     \(profile.install.count) step(s)")
        }
        if !profile.environment.isEmpty {
            print("environment: \(profile.environment.count) variable(s)")
        }

        KitInspect.report(translation)
    }

    static func translate(_ path: String, mixins: [String] = []) throws -> KitTranslation {
        let base = try loadSpec(path)
        guard !mixins.isEmpty else {
            return try KitTranslator.translate(base)
        }
        return try KitComposer.compose(base: base, mixins: try mixins.map(loadSpec))
    }

    static func loadSpec(_ path: String) throws -> KitSpec {
        var url = URL(filePath: path).standardizedFileURL
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory),
            isDirectory.boolValue
        {
            url = url.appending(path: "spec.yaml")
        }
        guard FileManager.default.isReadableFile(atPath: url.path) else {
            throw KitError.notFound(url)
        }
        return try KitSpec.load(from: url)
    }

    /// Print the gaps loudly. A kit that quietly lost a rule would produce a
    /// sandbox its author did not describe.
    static func report(_ translation: KitTranslation) {
        guard translation.hasWarnings else { return }
        print("")
        for note in translation.notes {
            print("note:        \(note)")
        }
        for item in translation.unsupported {
            print("UNSUPPORTED: \(item)")
        }
    }
}

struct KitImport: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "import",
        abstract: "Import a kit as an agent profile you can run."
    )

    @Argument(help: "Directory containing spec.yaml, or the file itself.")
    var path: String

    @Option(name: .long, help: "Name for the imported agent. Defaults to the kit's name.")
    var name: String?

    @Option(name: .long, help: "Layer a mixin kit on top; repeatable.")
    var with: [String] = []

    @Option(
        name: .long,
        help: """
            Layer this kit, itself a mixin, onto an existing agent. \
            Defaults to the agent the mixin's requires.agent names.
            """)
    var onto: String?

    @Flag(name: .shortAndLong, help: "Overwrite an existing profile of that name.")
    var force: Bool = false

    func run() async throws {
        var translation = try Self.translateForImport(path, mixins: with, onto: onto)
        if let name {
            try SandboxStore.validate(name: name)
            translation.profile.name = name
        }

        let registry = AgentRegistry()
        let existing = registry.userProfiles().contains { $0.name == translation.profile.name }
        if existing, !force {
            throw CleanExit.message(
                "an agent named '\(translation.profile.name)' already exists; "
                    + "pass --force to replace it")
        }

        try registry.write(translation.profile)
        print("imported '\(translation.profile.name)'")
        KitInspect.report(translation)
        print("")
        print("run it with: sandbox run \(translation.profile.name)")
    }

    /// A sandbox kit translates as itself; a mixin composes onto the agent it
    /// belongs to. `requires.agent` is the mixin saying which one that is --
    /// code-server names claude -- so importing it alone does the layering
    /// its author described, and --onto overrides the target.
    static func translateForImport(
        _ path: String, mixins: [String], onto: String?
    ) throws -> KitTranslation {
        let spec = try KitInspect.loadSpec(path)
        guard spec.kind == "mixin" else {
            return try KitInspect.translate(path, mixins: mixins)
        }
        guard let baseName = onto ?? spec.requires?.agent else {
            // A mixin with no affinity has nothing to land on by itself.
            throw KitError.mixinNotSupported(spec.name)
        }
        let base = try AgentRegistry().profile(named: baseName)
        var translation = try KitComposer.compose(
            onto: base, mixins: [spec] + mixins.map(KitInspect.loadSpec))
        // The composed agent is a new thing; without a distinct name it would
        // shadow the base it was layered onto.
        translation.profile.name = spec.name
        translation.profile.displayName = spec.displayName ?? spec.name
        return translation
    }
}
