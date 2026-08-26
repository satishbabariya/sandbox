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
            if CredentialBinding.preset(for: credential.service) == nil {
                notes.append(
                    "credentials[\(credential.service)] has no airlock binding; "
                        + "it will not be injected")
                continue
            }
            secrets.append(credential.service)
            if inject.count > 1 {
                notes.append(
                    "credentials[\(credential.service)] injects into \(inject.count) domains; "
                        + "airlock's binding covers one")
            }
        }

        // Install steps. `user` is dropped: airlock runs the prepare sandbox as
        // root, which is a superset of what a step asking for uid 1000 needs.
        var install: [String] = []
        for step in spec.setup?.install ?? [] {
            install.append(step.command.shellCommand)
        }
        if let startup = spec.setup?.startup, !startup.isEmpty {
            unsupported.append(
                "setup.startup: \(startup.count) command(s) that run on every start "
                    + "are not supported; fold them into the launch command")
        }
        if let files = spec.setup?.files, !files.isEmpty {
            // These could be written, but silently materialising files a kit
            // expected at specific modes is worse than saying so.
            unsupported.append(
                "setup.files: \(files.count) file(s) are not written; "
                    + "add them to the image or the launch command")
        }

        if spec.ports?.isEmpty == false {
            notes.append("ports are not published automatically; use -p")
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
            docker: spec.security?.privileged ?? false
        )

        return KitTranslation(profile: profile, notes: notes, unsupported: unsupported)
    }
}

public enum KitError: Error, CustomStringConvertible {
    case missingImage(String)
    case mixinNotSupported(String)
    case notFound(URL)

    public var description: String {
        switch self {
        case .missingImage(let name):
            return """
                kit '\(name)' declares no sandbox.image
                airlock cannot build from sandbox.build yet, so the kit needs a prebuilt image
                """
        case .mixinNotSupported(let name):
            return """
                '\(name)' is a mixin, which is meant to be composed onto a sandbox kit
                airlock has no composition model; import the sandbox kit instead
                """
        case .notFound(let url):
            return "no spec.yaml at \(url.path)"
        }
    }
}
