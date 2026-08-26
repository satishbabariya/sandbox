import Foundation

/// Turns a Docker Sandboxes kit into an airlock agent profile.
///
/// The translation is partial by necessity — the two engines are not the same
/// shape. What matters is that the gaps are *stated*. A kit that silently lost
/// its deny rules or half its install steps would produce a sandbox the author
/// did not describe, and in the deny case a weaker one.
public struct KitTranslation: Sendable {
    public var profile: AgentProfile
    /// Fields airlock understood but changed in some way.
    public var notes: [String]
    /// Fields airlock could not honour at all.
    public var unsupported: [String]

    public var hasWarnings: Bool { !notes.isEmpty || !unsupported.isEmpty }
}

public enum KitTranslator {
    public static func translate(_ spec: KitSpec) throws -> KitTranslation {
        var notes: [String] = []
        var unsupported: [String] = []

        if let kind = spec.kind, kind == "mixin" {
            // A mixin has no image and is meant to be composed onto a sandbox.
            throw KitError.mixinNotSupported(spec.name)
        }
        guard let image = spec.sandbox?.image, !image.isEmpty else {
            throw KitError.missingImage(spec.name)
        }
        if spec.extends != nil {
            unsupported.append("extends: parent kits are not resolved; flatten it first")
        }
        if let mixins = spec.mixins, !mixins.isEmpty {
            unsupported.append(
                "mixins: \(mixins.joined(separator: ", ")) are not composed")
        }

        // Command: entrypoint plus the default argument list.
        var command = spec.sandbox?.entrypoint ?? []
        if let defaults = spec.sandbox?.command?.default {
            command += defaults
        }
        if spec.sandbox?.command?.interactive != nil {
            notes.append(
                "command.interactive ignored; airlock attaches a terminal automatically")
        }

        let allow = spec.permissions?.network?.allow ?? []
        let deny = spec.permissions?.network?.deny ?? []
        if !deny.isEmpty {
            // airlock's profile has no deny list; surfacing it is better than
            // dropping a rule the author wrote deliberately.
            notes.append(
                "network.deny (\(deny.joined(separator: ", "))) must be passed as "
                    + "--deny or set in config; a profile carries no deny list")
        }

        // Credentials: only the API-key-into-a-header shape maps.
        var secrets: [String] = []
        var bindings: [CredentialBinding] = []
        for credential in spec.credentials ?? [] {
            if let oauth = credential.oauth {
                let endpoint = oauth.tokenEndpoint?.description ?? "an OAuth provider"
                unsupported.append(
                    "credentials[\(credential.service)].oauth (\(endpoint)): airlock reuses "
                        + "an existing host sign-in but cannot perform the flow")
                continue
            }
            guard let inject = credential.apiKey?.inject, !inject.isEmpty else {
                notes.append(
                    "credentials[\(credential.service)] has no inject rule and was skipped")
                continue
            }
            // The kit states the domain, header and format for every
            // credential it uses, so it can describe a service airlock has no
            // preset for -- and can name several domains for one credential,
            // which is how a regional API is expressed. Both are taken from
            // the kit rather than refused.
            let declared = inject.compactMap { rule -> CredentialBinding? in
                guard let header = Self.header(for: rule) else { return nil }
                return CredentialBinding(
                    service: credential.service,
                    domain: rule.domain,
                    header: header,
                    format: Self.format(for: rule),
                    // The kit names the variable its tool reads; without it the
                    // credential is brokered but the tool never sends anything.
                    environmentVariable: credential.apiKey?.name)
            }
            guard !declared.isEmpty else {
                notes.append(
                    "credentials[\(credential.service)] declares no header or scheme "
                        + "to inject with; it will not be injected")
                continue
            }
            secrets.append(credential.service)
            bindings.append(contentsOf: declared)
        }

        // Install steps. `user` is dropped: airlock runs the prepare sandbox as
        // root, which is a superset of what a step asking for uid 1000 needs.
        var install: [String] = []
        for step in spec.setup?.install ?? [] {
            install.append(step.command.shellCommand)
        }
        // Startup commands run as root at every start. `background` is not
        // honoured -- a command that never returns would hold the sandbox
        // before the agent ever ran -- so those are reported rather than run.
        var startup: [StartupCommand] = []
        for step in spec.setup?.startup ?? [] {
            let background = step.background ?? false
            switch step.command {
            case .argv(let parts) where !parts.isEmpty:
                startup.append(StartupCommand(argv: parts, background: background))
            case .shell(let text):
                startup.append(
                    StartupCommand(argv: ["/bin/sh", "-c", text], background: background))
            case .argv:
                continue
            }
        }

        var files: [GuestFile] = []
        for entry in spec.setup?.files ?? [] {
            guard let content = entry.content else {
                // `source` entries point at a file in the kit's own files/
                // tree, which airlock does not fetch.
                unsupported.append(
                    "setup.files[\(entry.path)] has no inline content and was not written")
                continue
            }
            files.append(GuestFile(path: entry.path, content: content, mode: entry.mode))
        }

        if spec.ports?.isEmpty == false {
            notes.append("ports are not published automatically; use -p")
        }

        // Handled here as well as in the mixin path: a sandbox kit's own
        // instructions were being dropped without even a note, which is the
        // one outcome the translator is supposed to make impossible.
        var instructions: AgentInstructions?
        if let content = spec.agentInstructions?.content {
            instructions = AgentInstructions(
                filename: spec.agentInstructions?.filename, content: content)
            notes.append(
                "agentInstructions is written only with --clone; into your own "
                    + "working tree it would be a kit adding a file to your repository")
        }

        let profile = AgentProfile(
            name: spec.name,
            displayName: spec.displayName ?? spec.name,
            image: image,
            install: install,
            command: command,
            allow: allow,
            secrets: secrets,
            environment: spec.environment?.variables ?? [:],
            docker: spec.security?.privileged ?? false,
            files: files,
            startup: startup,
            agentInstructions: instructions,
            bindings: bindings
        )

        return KitTranslation(profile: profile, notes: notes, unsupported: unsupported)
    }
}

extension KitTranslator {
    /// The header a rule injects into. `scheme` is sugar for the Authorization
    /// header, which is how most kits express a bearer token.
    static func header(for rule: KitSpec.Credential.APIKey.Inject) -> String? {
        if let header = rule.header, !header.isEmpty { return header }
        if let scheme = rule.scheme, !scheme.isEmpty { return "authorization" }
        return nil
    }

    /// A kit writes the value template with `%s`; airlock writes it with `{}`.
    /// A rule that gives only a scheme means "<scheme> <secret>".
    static func format(for rule: KitSpec.Credential.APIKey.Inject) -> String {
        if let format = rule.format, !format.isEmpty {
            return format.replacingOccurrences(of: "%s", with: "{}")
        }
        if let scheme = rule.scheme, !scheme.isEmpty { return "\(scheme) {}" }
        return "{}"
    }
}

public enum KitError: Error, CustomStringConvertible {
    case missingImage(String)
    case mixinNotSupported(String)
    case notFound(URL)
    case notAMixin(String)

    public var description: String {
        switch self {
        case .missingImage(let name):
            return """
                kit '\(name)' declares no sandbox.image
                airlock cannot build from sandbox.build yet, so the kit needs a prebuilt image
                """
        case .mixinNotSupported(let name):
            // A mixin has no image and no command of its own, so there is
            // nothing to run it as. It has to be layered onto a sandbox kit,
            // which is what --with does.
            return """
                '\(name)' is a mixin: it adds to a sandbox kit rather than being one
                layer it onto a sandbox kit with: airlock kit inspect <sandbox-kit> --with \(name)
                """
        case .notFound(let url):
            return "no spec.yaml at \(url.path)"
        case .notAMixin(let name):
            return "'\(name)' is not a mixin; only mixins can be layered with --with"
        }
    }
}
