import Foundation

/// Turns a Docker Sandboxes kit into an sandbox agent profile.
///
/// The translation is partial by necessity — the two engines are not the same
/// shape. What matters is that the gaps are *stated*. A kit that silently lost
/// its deny rules or half its install steps would produce a sandbox the author
/// did not describe, and in the deny case a weaker one.
public struct KitTranslation: Sendable {
    public var profile: AgentProfile
    /// Fields sandbox understood but changed in some way.
    public var notes: [String]
    /// Fields sandbox could not honour at all.
    public var unsupported: [String]

    public var hasWarnings: Bool { !notes.isEmpty || !unsupported.isEmpty }

    public init(profile: AgentProfile, notes: [String] = [], unsupported: [String] = []) {
        self.profile = profile
        self.notes = notes
        self.unsupported = unsupported
    }
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
                "command.interactive ignored; sandbox attaches a terminal automatically")
        }

        let allow = spec.permissions?.network?.allow ?? []
        let deny = spec.permissions?.network?.deny ?? []
        if !deny.isEmpty {
            // sandbox's profile has no deny list; surfacing it is better than
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
                    "credentials[\(credential.service)].oauth (\(endpoint)): a sign-in "
                        + "already on the host is reused, but the flow cannot be performed here")
                continue
            }
            guard let inject = credential.apiKey?.inject, !inject.isEmpty else {
                notes.append(
                    "credentials[\(credential.service)] has no inject rule and was skipped")
                continue
            }
            // The kit states the domain, header and format for every
            // credential it uses, so it can describe a service sandbox has no
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

        // Install steps. Root is a permission superset of any user a step
        // asks for, but not a behaviour superset: `uv tool install` as root
        // puts the tool in /root/.local, while the kit's entrypoint expects
        // it in the agent's home. A step that names an unprivileged user runs
        // as uid 1000 -- the same identity the privilege drop hands the agent
        // at runtime -- so what it installs lands where the agent can run it.
        var install: [String] = []
        for step in spec.setup?.install ?? [] {
            let command = step.command.shellCommand
            if let user = step.user, user != "0", user != "root" {
                install.append(Self.runAsAgentUser(command))
            } else {
                install.append(command)
            }
        }
        // Startup commands run as root at every start. `background` is not
        // honoured -- a command that never returns would hold the sandbox
        // before the agent ever ran -- so those are reported rather than run.
        var startup: [StartupCommand] = []
        for step in spec.setup?.startup ?? [] {
            let background = step.background ?? false
            let asAgent = step.user.map { $0 != "0" && $0 != "root" } ?? false
            switch step.command {
            case .argv(let parts) where !parts.isEmpty:
                if asAgent {
                    startup.append(
                        StartupCommand(
                            argv: [
                                "/bin/sh", "-c",
                                Self.runAsAgentUser(shellJoin(parts)),
                            ], background: background))
                } else {
                    startup.append(StartupCommand(argv: parts, background: background))
                }
            case .shell(let text):
                startup.append(
                    StartupCommand(
                        argv: ["/bin/sh", "-c", asAgent ? Self.runAsAgentUser(text) : text],
                        background: background))
            case .argv:
                continue
            }
        }

        var files: [GuestFile] = []
        for entry in spec.setup?.files ?? [] {
            guard let content = entry.content else {
                // `source` entries point at a file in the kit's own files/
                // tree, which sandbox does not fetch.
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
            // The privilege drop is sandbox's, not the image's. Relying on the
            // image's USER left every root-assuming bootstrap -- CA trust,
            // startup commands, /etc/hosts -- running unprivileged and
            // failing, some of them into 2>/dev/null.
            runAsUser: "agent",
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

    /// A kit writes the value template with `%s`; sandbox writes it with `{}`.
    /// A rule that gives only a scheme means "<scheme> <secret>".
    /// Wrap an install command so it runs as the agent's identity: uid 1000,
    /// reusing whatever user the image already has there or creating one, with
    /// that user's home -- the same resolution the runtime privilege drop
    /// performs, so build-time and run-time agree on whose home things are in.
    ///
    /// The command travels base64-encoded: it is an arbitrary multi-line bash
    /// program from a kit, and splicing one into a quoted su argument is how
    /// installs broke the last time.
    static func runAsAgentUser(_ command: String) -> String {
        let encoded = Data(command.utf8).base64EncodedString()
        return """
            SANDBOX_STEP_USER=$(getent passwd 1000 2>/dev/null | cut -d: -f1)
            if [ -z "$SANDBOX_STEP_USER" ]; then
              adduser -D -u 1000 agent >/dev/null 2>&1 \
                || useradd -m -u 1000 -s /bin/bash agent >/dev/null 2>&1 || true
              SANDBOX_STEP_USER=$(getent passwd 1000 2>/dev/null | cut -d: -f1)
            fi
            if [ -z "$SANDBOX_STEP_USER" ]; then
              echo "sandbox: no uid 1000 user could be created; running the step as root" >&2
              echo \(shellSingleQuote(encoded)) | base64 -d | /bin/bash
            else
              SANDBOX_STEP_HOME=$(getent passwd 1000 | cut -d: -f6)
              [ -n "$SANDBOX_STEP_HOME" ] || SANDBOX_STEP_HOME=/home/$SANDBOX_STEP_USER
              mkdir -p "$SANDBOX_STEP_HOME"
              chown 1000 "$SANDBOX_STEP_HOME"
              echo \(shellSingleQuote(encoded)) | base64 -d > /tmp/sandbox-step.sh
              chown 1000 /tmp/sandbox-step.sh
              su -s /bin/bash "$SANDBOX_STEP_USER" -c "HOME=$SANDBOX_STEP_HOME /bin/bash /tmp/sandbox-step.sh"
              SANDBOX_STEP_RC=$?
              rm -f /tmp/sandbox-step.sh
              [ "$SANDBOX_STEP_RC" -eq 0 ]
            fi
            """
    }

    static func shellJoin(_ parts: [String]) -> String {
        parts.map(shellSingleQuote).joined(separator: " ")
    }

    static func shellSingleQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

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
                building from sandbox.build is not supported yet, so the kit needs a
                prebuilt image
                """
        case .mixinNotSupported(let name):
            // A mixin has no image and no command of its own, so there is
            // nothing to run it as. It has to be layered onto a sandbox kit,
            // which is what --with does.
            return """
                '\(name)' is a mixin: it adds to an agent rather than being one
                layer it onto the agent it belongs to:  sandbox kit import \(name) --onto <agent>
                or onto a sandbox kit:                  sandbox kit import <sandbox-kit> --with \(name)
                """
        case .notFound(let url):
            return "no spec.yaml at \(url.path)"
        case .notAMixin(let name):
            return "'\(name)' is not a mixin; only mixins can be layered with --with"
        }
    }
}
