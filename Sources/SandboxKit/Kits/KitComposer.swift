import Foundation

/// Composes a sandbox kit with the mixins layered onto it.
///
/// A mixin has no image and is not runnable alone — it adds egress, install
/// steps, environment, and credentials to a sandbox kit. Refusing them meant
/// half the published kits could not be imported at all.
///
/// Merge order follows the kit lifecycle: the base kit first, then each mixin
/// in declaration order. Rules per section:
///
/// - egress: set union, order preserved. Widening only.
/// - install: concatenated, base first, so a mixin runs with the base present.
/// - startup: concatenated, base first, for the same reason.
/// - files: keyed by path, mixin wins, as for environment.
/// - environment: later wins, since a mixin layered on top is the more
///   specific statement.
/// - credentials: union by service.
public enum KitComposer {
    /// Compose a base kit with mixins, reporting anything that could not be
    /// carried across from any of them.
    public static func compose(
        base: KitSpec,
        mixins: [KitSpec]
    ) throws -> KitTranslation {
        var result = try KitTranslator.translate(base)

        for mixin in mixins {
            guard mixin.kind == "mixin" else {
                throw KitError.notAMixin(mixin.name)
            }
            // A mixin may declare which agent it belongs to. Layering it onto a
            // different one would produce something its author never tested.
            if let required = mixin.requires?.agent, required != base.name {
                result.notes.append(
                    "mixin '\(mixin.name)' declares requires.agent: \(required), "
                        + "but is being layered onto '\(base.name)'")
            }

            let layer = try translateMixin(mixin)
            result.profile = merge(result.profile, layer.profile)
            result.notes += layer.notes.map { "[\(mixin.name)] \($0)" }
            result.unsupported += layer.unsupported.map { "[\(mixin.name)] \($0)" }
        }
        return result
    }

    /// Compose mixins onto an existing agent — a built-in like claude, or an
    /// agent already imported. This is what a mixin's `requires.agent` names:
    /// code-server declares it belongs on the claude agent, and layering it
    /// there is the whole point of the kit.
    public static func compose(
        onto base: AgentProfile,
        mixins: [KitSpec]
    ) throws -> KitTranslation {
        var result = KitTranslation(profile: base)

        for mixin in mixins {
            guard mixin.kind == "mixin" else {
                throw KitError.notAMixin(mixin.name)
            }
            if let required = mixin.requires?.agent, required != base.name {
                result.notes.append(
                    "mixin '\(mixin.name)' declares requires.agent: \(required), "
                        + "but is being layered onto '\(base.name)'")
            }
            let layer = try translateMixin(mixin)
            result.profile = merge(result.profile, layer.profile)
            result.notes += layer.notes.map { "[\(mixin.name)] \($0)" }
            result.unsupported += layer.unsupported.map { "[\(mixin.name)] \($0)" }
        }
        return result
    }

    /// A mixin has no image, so it cannot go through the sandbox translator.
    /// This reads the same sections and leaves the image blank.
    public static func translateMixin(_ spec: KitSpec) throws -> KitTranslation {
        var stand = spec
        // Borrow a placeholder image so the sandbox path can be reused; the
        // merge only reads the fields a mixin actually contributes.
        stand.sandbox = KitSpec.Sandbox(
            image: "mixin-placeholder",
            entrypoint: nil,
            command: nil)
        stand.kind = "sandbox"
        var translated = try KitTranslator.translate(stand)
        translated.profile.image = ""
        translated.profile.command = []

        if let content = spec.agentInstructions?.content {
            translated.profile.agentInstructions = AgentInstructions(
                filename: spec.agentInstructions?.filename, content: content)
            translated.notes.append(
                "agentInstructions is written only with --clone; into your own "
                    + "working tree it would be a kit adding a file to your repository")
        }
        return translated
    }

    static func merge(_ base: AgentProfile, _ layer: AgentProfile) -> AgentProfile {
        var merged = base

        // Union, order preserved. A mixin can only widen egress, never narrow
        // it, so composing cannot quietly grant less than the base allowed.
        var seenAllow = Set(base.allow)
        for rule in layer.allow where seenAllow.insert(rule).inserted {
            merged.allow.append(rule)
        }

        // Base install steps first: a mixin's installer expects the base
        // toolchain to already be there.
        merged.install += layer.install

        var seenSecret = Set(base.secrets)
        for service in layer.secrets where seenSecret.insert(service).inserted {
            merged.secrets.append(service)
        }

        var seenMount = Set(base.mounts)
        for mount in layer.mounts where seenMount.insert(mount).inserted {
            merged.mounts.append(mount)
        }

        // Later wins: a mixin layered on top is the more specific statement.
        for (key, value) in layer.environment {
            merged.environment[key] = value
        }

        var seenServer = Set(base.mcp.map(\.name))
        for server in layer.mcp where seenServer.insert(server.name).inserted {
            merged.mcp.append(server)
        }

        // Startup runs base first, for the same reason install does: a mixin's
        // startup work assumes the base is already set up.
        merged.startup += layer.startup

        // Files are keyed by path, and the mixin wins -- layering a kit on top
        // is the more specific statement, exactly as it is for environment. A
        // mixin that replaces the base's launcher script is doing so on
        // purpose.
        for file in layer.files {
            if let existing = merged.files.firstIndex(where: { $0.path == file.path }) {
                merged.files[existing] = file
            } else {
                merged.files.append(file)
            }
        }

        // A binding is keyed by service and domain together, because one
        // service legitimately has several domains.
        var seenBinding = Set(base.bindings.map { "\($0.service)|\($0.domain)" })
        for binding in layer.bindings
        where seenBinding.insert("\(binding.service)|\(binding.domain)").inserted {
            merged.bindings.append(binding)
        }

        // Later wins, as for environment: a mixin layered on top is the more
        // specific statement about what the agent should be told.
        if let instructions = layer.agentInstructions {
            merged.agentInstructions = instructions
        }

        // Privilege is a union: if any layer needs it, the sandbox needs it.
        merged.docker = base.docker || layer.docker

        return merged
    }
}
