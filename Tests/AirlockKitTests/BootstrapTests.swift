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

/// Kit content is arbitrary text that ends up inside a generated shell script.
/// These pin the two things that keeps safe: the quoting, and the encoding.
@Suite("guest provisioning")
struct ProvisioningTests {
    /// A single quote in a path would otherwise close airlock's own quoting and
    /// let the rest of the string run as commands in the guest's bootstrap.
    @Test("a quote in a path cannot escape its quoting")
    func quotingIsClosed() {
        let hostile = "/tmp/x'; touch /pwned; echo '"
        let quoted = Sandbox.shellQuote(hostile)

        #expect(quoted.hasPrefix("'") && quoted.hasSuffix("'"))
        // Every embedded quote is the escape sequence, never a bare one that
        // would end the literal early.
        let inner = quoted.dropFirst().dropLast()
        #expect(!inner.contains("'") || inner.contains("'\\''"))
        #expect(quoted.contains("touch /pwned"))  // present as data...
        let script = Sandbox.filesBootstrap(
            wrapping: ["/bin/true"], files: [GuestFile(path: hostile, content: "x")]
        ).joined(separator: " ")
        #expect(!script.contains("; touch /pwned; echo ;"))  // ...never as a command
    }

    /// Content never appears literally in the script, so no byte in it can be
    /// read as syntax by the shell that writes it out.
    @Test("file content travels encoded, not inline")
    func contentIsEncoded() {
        let content = "it's \"quoted\" $HOME `whoami`\nsecond\n"
        let script = Sandbox.filesBootstrap(
            wrapping: ["/bin/true"], files: [GuestFile(path: "/tmp/f", content: content)]
        ).joined(separator: " ")

        #expect(!script.contains("`whoami`"))
        #expect(!script.contains("$HOME"))
        #expect(script.contains(Data(content.utf8).base64EncodedString()))
        #expect(script.contains("base64 -d"))
    }

    /// A reader must never observe a partially written file, so it is written
    /// beside its destination and moved into place.
    @Test("files are moved into place, not written in place")
    func writesAreAtomic() {
        let script = Sandbox.filesBootstrap(
            wrapping: ["/bin/true"], files: [GuestFile(path: "/tmp/f", content: "x", mode: "0755")]
        ).joined(separator: " ")

        #expect(script.contains(".airlock-part"))
        #expect(script.contains("mv -f"))
        // The mode is applied before the move, so the file is never briefly
        // visible at the wrong permissions.
        let chmod = script.range(of: "chmod")
        let move = script.range(of: "mv -f")
        #expect(chmod != nil && move != nil && chmod!.lowerBound < move!.lowerBound)
    }

    /// A daemon never returns. Waiting for one would hold the sandbox before
    /// the agent ever ran, which is how a kit's helper became a hang.
    @Test("a background command is started and not waited for")
    func backgroundIsDetached() {
        let script = Sandbox.startupBootstrap(
            wrapping: ["/bin/true"],
            startup: [StartupCommand(argv: ["/usr/bin/daemon"], background: true)]
        ).joined(separator: " ")
        #expect(script.contains("&"))
    }

    /// A foreground command that fails must not stop the sandbox: these
    /// reconcile state, and refusing to launch the agent because a helper
    /// declined would be worse than running without it.
    @Test("a failing foreground command is reported, not fatal")
    func foregroundFailureIsNotFatal() {
        let script = Sandbox.startupBootstrap(
            wrapping: ["/bin/true"],
            startup: [StartupCommand(argv: ["/bin/false"])]
        ).joined(separator: " ")
        #expect(script.contains("||"))
        #expect(script.contains("startup command failed"))
        #expect(!script.contains("set -e"))
    }

    /// Nothing declared means nothing wrapped -- an empty layer would still
    /// cost a process and a shell parse on every start.
    @Test("nothing declared wraps nothing")
    func emptyIsNotWrapped() {
        #expect(Sandbox.filesBootstrap(wrapping: ["/bin/true"], files: []) == ["/bin/true"])
        #expect(Sandbox.startupBootstrap(wrapping: ["/bin/true"], startup: []) == ["/bin/true"])
        // An argv of no words is not a command.
        #expect(
            Sandbox.startupBootstrap(
                wrapping: ["/bin/true"], startup: [StartupCommand(argv: [])]) == ["/bin/true"])
    }

    /// Resolving the sandbox's own hostname cost 10s per lookup, and enough
    /// software does it on startup that it read as a hang.
    @Test("the sandbox's hostname is made resolvable")
    func hostnameIsLocal() {
        let script = Sandbox.hostnameBootstrap(wrapping: ["/bin/true"]).joined(separator: " ")
        #expect(script.contains("/etc/hosts"))
        #expect(script.contains("127.0.0.1"))
        // Appended only when absent: an image that already maps its own name
        // must not collect a duplicate on every start.
        #expect(script.contains("grep -qw"))
        #expect(script.contains(">>/etc/hosts"))
    }
}
