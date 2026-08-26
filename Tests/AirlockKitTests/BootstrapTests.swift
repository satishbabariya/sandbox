import Foundation
import Testing

@testable import AirlockKit

/// The guest command is assembled by wrapping it in nested shell scripts. What
/// those scripts do before `exec` is invisible from the outside, so the cost
/// and the correctness of each layer are pinned here.
@Suite("guest bootstrap")
struct BootstrapTests {
    /// Recursing over a shared workspace once cost 20 seconds of startup on a
    /// 45,000-file repository, and achieved nothing: the share is virtiofs and
    /// reports host ownership however the guest chowns it.
    @Test("a shared workspace is never walked recursively")
    func sharedWorkspaceIsNotWalked() {
        let script = Sandbox.dropPrivilegeBootstrap(
            wrapping: ["/bin/true"], user: "agent", workspace: "/workspace", cloned: false
        ).joined(separator: " ")

        #expect(!script.contains("chown -R \"$TARGET_UID\" \"/workspace\""))
    }

    /// A clone is a real tree in the rootfs, made by the clone step running as
    /// root. Without this the agent cannot write its own workspace.
    @Test("a cloned workspace is handed to the agent")
    func clonedWorkspaceIsChowned() {
        let script = Sandbox.dropPrivilegeBootstrap(
            wrapping: ["/bin/true"], user: "agent", workspace: "/workspace", cloned: true
        ).joined(separator: " ")

        #expect(script.contains("chown -R \"$TARGET_UID\" \"/workspace\""))
    }

    /// The home directory is small and genuinely needs owning: the agent's
    /// staged credentials are copied there as root just above.
    @Test("the home directory is always chowned")
    func homeIsAlwaysChowned() {
        for cloned in [true, false] {
            let script = Sandbox.dropPrivilegeBootstrap(
                wrapping: ["/bin/true"], user: "agent", workspace: "/workspace", cloned: cloned
            ).joined(separator: " ")
            #expect(script.contains("chown -R \"$TARGET_UID\" \"$HOME_DIR\""))
        }
    }

    /// Appending, never replacing: pointing the bundle at our CA alone would
    /// stop every other certificate on the internet from verifying.
    @Test("the CA is appended to the system bundle, not substituted for it")
    func trustAppends() {
        let script = Sandbox.trustBootstrap(wrapping: ["/bin/true"]).joined(separator: " ")
        #expect(script.contains(">> \"$bundle\""))
        // Appending contains the truncating form as a substring, so the
        // append has to be removed before looking for a real truncation.
        let withoutAppends = script.replacingOccurrences(of: ">> \"$bundle\"", with: "")
        #expect(!withoutAppends.contains("> \"$bundle\""))
    }

    /// Every layer must end in exec, or the agent runs as a child of the
    /// bootstrap shell and stops receiving signals sent to the container.
    @Test("every layer execs rather than forking")
    func layersExec() {
        let layers = [
            Sandbox.dropPrivilegeBootstrap(
                wrapping: ["/bin/true"], user: "agent", workspace: "/w", cloned: false),
            Sandbox.trustBootstrap(wrapping: ["/bin/true"]),
            Sandbox.cloneBootstrap(wrapping: ["/bin/true"], destination: "/w"),
        ]
        for layer in layers {
            #expect(layer.joined(separator: " ").contains("exec"))
        }
    }

    /// An empty command means there is nothing to wrap; producing a script
    /// anyway would invent a process the caller never asked for.
    @Test("an empty command is left alone")
    func emptyCommandUntouched() {
        #expect(
            Sandbox.dropPrivilegeBootstrap(
                wrapping: [], user: "agent", workspace: "/w", cloned: true
            ).isEmpty)
        #expect(Sandbox.trustBootstrap(wrapping: []).isEmpty)
        #expect(Sandbox.cloneBootstrap(wrapping: [], destination: "/w").isEmpty)
    }
}
