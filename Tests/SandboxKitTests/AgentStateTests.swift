import Foundation
import Testing

@testable import SandboxKit

/// The persistent agent home: mounts marked `state` are the agent's own copy
/// of its configuration, seeded once and kept between runs. These pin the two
/// halves that make it work -- the parse and the guest-side linking -- and the
/// property that motivated it: nothing is copied inside the guest any more.
@Suite("agent state")
struct AgentStateTests {
    @Test("':state' parses, and tolerates a source that does not exist yet")
    func stateParses() throws {
        // A host that has never run the agent has no config to seed from, and
        // that must not stop the sandbox: the state starts empty and whatever
        // the agent writes still persists.
        let mount = try #require(
            MountSpec.parse("~/never-ran-this-agent-\(UUID().uuidString):/root/.claude:state"))
        #expect(mount.state)
        #expect(!mount.copy)
        #expect(!mount.readOnly)
        #expect(mount.destination == "/root/.claude")
    }

    @Test("every other mode still requires the source to exist")
    func otherModesRequireSource() {
        let missing = "~/never-ran-this-agent-\(UUID().uuidString)"
        #expect(MountSpec.parse("\(missing):/root/.claude:copy") == nil)
        #expect(MountSpec.parse("\(missing):/root/.claude:ro") == nil)
        #expect(MountSpec.parse("\(missing):/root/.claude") == nil)
    }

    @Test("the state bootstrap links, and copies nothing")
    func stateLinksNotCopies() {
        let script = Sandbox.stateBootstrap(
            wrapping: ["/bin/true"],
            links: [
                ("/root/.claude", "/sandbox-state/.claude"),
                ("/root/.claude.json", "/sandbox-state/.claude.json"),
            ]
        ).joined(separator: " ")

        // The whole point: the previous design copied 700 MB through virtiofs
        // at every start, 45 seconds before the agent ran anything.
        #expect(!script.contains("cp "))
        #expect(script.contains("ln -sn '/sandbox-state/.claude' '/root/.claude'"))
        #expect(script.contains("ln -sn '/sandbox-state/.claude.json' '/root/.claude.json'"))
        #expect(script.contains("exec \"$@\""))
    }

    @Test("a destination an image already ships is replaced, not descended into")
    func destinationIsReplaced() {
        let script = Sandbox.stateBootstrap(
            wrapping: ["/bin/true"], links: [("/root/.claude", "/sandbox-state/.claude")]
        ).joined(separator: " ")

        // Without -n, ln into an existing directory creates .claude/.claude
        // and the agent reads the image's stale config forever.
        let rmBeforeLink = script.range(of: "rm -rf '/root/.claude'")
        let link = script.range(of: "ln -sn")
        #expect(rmBeforeLink != nil && link != nil)
        if let rmBeforeLink, let link {
            #expect(rmBeforeLink.lowerBound < link.lowerBound)
        }
    }

    @Test("an empty command is left alone")
    func emptyCommandUntouched() {
        #expect(Sandbox.stateBootstrap(wrapping: [], links: [("/a", "/b")]) == [])
    }

    @Test("no links, no wrapper")
    func noLinksNoWrapper() {
        #expect(Sandbox.stateBootstrap(wrapping: ["/bin/true"], links: []) == ["/bin/true"])
    }

    @Test("built-in agents persist their configuration")
    func builtInsUseState() {
        // Every built-in that mounts agent config should keep it between runs.
        for profile in AgentProfile.builtIns {
            for raw in profile.mounts {
                #expect(
                    !raw.hasSuffix(":copy"),
                    "\(profile.name) still discards \(raw) at exit")
            }
        }
    }
}
