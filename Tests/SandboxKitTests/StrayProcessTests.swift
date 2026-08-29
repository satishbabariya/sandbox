import Foundation
import Testing

@testable import SandboxKit

/// What this decides gets a SIGTERM, so the line that must never match is worth
/// more attention than the ones that must. Matching on the command line as a
/// whole rather than on the executable killed the shell this was tested from.
@Suite("stray process matching")
struct StrayProcessTests {
    @Test("our own supervisor and gateway are recognised")
    func ours() {
        let supervisor = StrayProcess.parse(
            line: " 50708 1 /usr/local/bin/sandbox supervise --spec /tmp/sandbox-demo/launch.json")
        #expect(supervisor?.kind == .supervisor)
        #expect(supervisor?.pid == 50708)
        #expect(supervisor?.directory == "/tmp/sandbox-demo")

        let gateway = StrayProcess.parse(
            line: "50709 50708 /usr/local/bin/gvsandbox -config /tmp/sandbox-demo/gateway.yaml")
        #expect(gateway?.kind == .gateway)
        #expect(gateway?.directory == "/tmp/sandbox-demo")
    }

    /// The dangerous cases: every one of these mentions our names, and none of
    /// them is ours.
    @Test("a process that merely mentions us is left alone")
    func notOurs() {
        for line in [
            // The shell a test runs in. This one was actually killed.
            "58001 1 /bin/zsh -c sandbox supervise /tmp/sandbox-demo/launch.json",
            "58002 1 /bin/sh -c pgrep -f 'sandbox supervise' /tmp/sandbox-demo",
            "58003 1 grep gvsandbox /tmp/sandbox-demo/notes",
            "58004 1 /usr/bin/vim /tmp/sandbox-demo/gateway.yaml",
            "58005 1 tail -f /tmp/sandbox-demo/gateway.log",
            // Our binary, but not the supervisor -- someone's interactive run.
            "58006 1 /usr/local/bin/sandbox run alpine --name /tmp/sandbox-demo",
            "58007 1 /usr/local/bin/sandbox ls",
        ] {
            #expect(StrayProcess.parse(line: line) == nil, "should not match: \(line)")
        }
    }

    /// Without a runtime directory there is nothing to judge liveness against,
    /// so there is no basis for killing it.
    @Test("one of ours with no runtime directory is not a candidate")
    func noDirectory() {
        #expect(StrayProcess.parse(line: "1 1 /usr/local/bin/sandbox supervise --help") == nil)
        #expect(StrayProcess.parse(line: "2 1 /usr/local/bin/gvsandbox -version") == nil)
    }

    @Test("malformed lines are ignored rather than guessed at")
    func malformed() {
        for line in ["", "   ", "notapid 1 /usr/local/bin/gvsandbox /tmp/sandbox-x", "12345"] {
            #expect(StrayProcess.parse(line: line) == nil)
        }
    }

    /// The directory existing is what separates a running sandbox from a
    /// leftover, so a live one must survive the sweep.
    @Test("a process whose directory still exists is not stray")
    func liveSandboxSurvives() {
        let listing = """
             900 1 /usr/local/bin/sandbox supervise --spec /tmp/sandbox-live/launch.json
             901 900 /usr/local/bin/gvsandbox -config /tmp/sandbox-dead/gateway.yaml
            """
        let strays = StrayProcess.parse(listing).filter { $0.directory != "/tmp/sandbox-live" }
        #expect(strays.count == 1)
        #expect(strays.first?.directory == "/tmp/sandbox-dead")
    }

    /// The gateway of a run that was killed rather than stopped: its runtime
    /// directory is still there, so the directory test alone said "live", and
    /// sixteen of these were found running, the oldest for two days. What
    /// gives it away is the parent: the gateway is spawned as a direct child
    /// of the CLI or the supervisor, so init as its parent means the owner
    /// died without stopping it.
    @Test("a gateway reparented to init is stray even with its directory intact")
    func orphanedGatewayIsStray() {
        let orphan = StrayProcess.parse(
            line: "3412 1 /opt/homebrew/bin/gvsandbox -config /tmp/sandbox-x/gateway.yaml")!
        let owned = StrayProcess.parse(
            line: "3413 900 /opt/homebrew/bin/gvsandbox -config /tmp/sandbox-x/gateway.yaml")!
        #expect(StrayProcess.isStray(orphan) { _ in true })
        #expect(!StrayProcess.isStray(owned) { _ in true })
    }

    /// A supervisor at ppid 1 is the normal shape of a detached sandbox --
    /// detaching from its spawner is its whole design. Killing it on that
    /// evidence would stop every healthy detached sandbox on the machine.
    @Test("a detached supervisor is not mistaken for an orphan")
    func detachedSupervisorSurvives() {
        let supervisor = StrayProcess.parse(
            line: "900 1 /usr/local/bin/sandbox supervise --spec /tmp/sandbox-live/launch.json")!
        #expect(!StrayProcess.isStray(supervisor) { _ in true })
    }
}

/// A pid file outlives the process it names and pids are reused, so deciding to
/// signal one on liveness alone eventually sends a SIGTERM meant for a gateway
/// to whatever now holds that number.
@Suite("process identity")
struct ProcessIdentityTests {
    @Test("our own processes are recognised")
    func ours() {
        #expect(StrayProcess.isOurs(pid: 1234) { _ in "sandbox" })
        #expect(StrayProcess.isOurs(pid: 1234) { _ in "gvsandbox" })
        // A full path is what ps reports for some processes.
        #expect(StrayProcess.isOurs(pid: 1234) { _ in "/usr/local/bin/gvsandbox" } == false)
    }

    /// The case that matters: the number is live, and it is not ours.
    @Test("anything else is left alone")
    func notOurs() {
        for name in ["sleep", "zsh", "node", "Finder", "sandboxd", "my-sandbox"] {
            #expect(!StrayProcess.isOurs(pid: 1234) { _ in name }, "should not match \(name)")
        }
    }

    @Test("a pid that no longer exists is not ours")
    func gone() {
        #expect(!StrayProcess.isOurs(pid: 1234) { _ in nil })
        #expect(!StrayProcess.isOurs(pid: 0) { _ in "sandbox" })
        #expect(!StrayProcess.isOurs(pid: -1) { _ in "sandbox" })
    }

    /// This process is sandbox's test runner, not sandbox.
    @Test("the real lookup answers for a live process")
    func realLookup() {
        let mine = ProcessInfo.processInfo.processIdentifier
        #expect(StrayProcess.commandName(pid: mine) != nil)
        #expect(StrayProcess.commandName(pid: 999_999) == nil)
    }
}
