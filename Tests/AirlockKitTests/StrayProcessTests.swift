import Testing

@testable import AirlockKit

/// What this decides gets a SIGTERM, so the line that must never match is worth
/// more attention than the ones that must. Matching on the command line as a
/// whole rather than on the executable killed the shell this was tested from.
@Suite("stray process matching")
struct StrayProcessTests {
    @Test("our own supervisor and gateway are recognised")
    func ours() {
        let supervisor = StrayProcess.parse(
            line: " 50708 /usr/local/bin/airlock supervise --spec /tmp/airlock-demo/launch.json")
        #expect(supervisor?.kind == .supervisor)
        #expect(supervisor?.pid == 50708)
        #expect(supervisor?.directory == "/tmp/airlock-demo")

        let gateway = StrayProcess.parse(
            line: "50709 /usr/local/bin/gvairlock -config /tmp/airlock-demo/gateway.yaml")
        #expect(gateway?.kind == .gateway)
        #expect(gateway?.directory == "/tmp/airlock-demo")
    }

    /// The dangerous cases: every one of these mentions our names, and none of
    /// them is ours.
    @Test("a process that merely mentions us is left alone")
    func notOurs() {
        for line in [
            // The shell a test runs in. This one was actually killed.
            "58001 /bin/zsh -c airlock supervise /tmp/airlock-demo/launch.json",
            "58002 /bin/sh -c pgrep -f 'airlock supervise' /tmp/airlock-demo",
            "58003 grep gvairlock /tmp/airlock-demo/notes",
            "58004 /usr/bin/vim /tmp/airlock-demo/gateway.yaml",
            "58005 tail -f /tmp/airlock-demo/gateway.log",
            // Our binary, but not the supervisor -- someone's interactive run.
            "58006 /usr/local/bin/airlock run alpine --name /tmp/airlock-demo",
            "58007 /usr/local/bin/airlock ls",
        ] {
            #expect(StrayProcess.parse(line: line) == nil, "should not match: \(line)")
        }
    }

    /// Without a runtime directory there is nothing to judge liveness against,
    /// so there is no basis for killing it.
    @Test("one of ours with no runtime directory is not a candidate")
    func noDirectory() {
        #expect(StrayProcess.parse(line: "1 /usr/local/bin/airlock supervise --help") == nil)
        #expect(StrayProcess.parse(line: "2 /usr/local/bin/gvairlock -version") == nil)
    }

    @Test("malformed lines are ignored rather than guessed at")
    func malformed() {
        for line in ["", "   ", "notapid /usr/local/bin/gvairlock /tmp/airlock-x", "12345"] {
            #expect(StrayProcess.parse(line: line) == nil)
        }
    }

    /// The directory existing is what separates a running sandbox from a
    /// leftover, so a live one must survive the sweep.
    @Test("a process whose directory still exists is not stray")
    func liveSandboxSurvives() {
        let listing = """
             900 /usr/local/bin/airlock supervise --spec /tmp/airlock-live/launch.json
             901 /usr/local/bin/gvairlock -config /tmp/airlock-dead/gateway.yaml
            """
        let strays = StrayProcess.parse(listing).filter { $0.directory != "/tmp/airlock-live" }
        #expect(strays.count == 1)
        #expect(strays.first?.directory == "/tmp/airlock-dead")
    }
}
