import Foundation
import Testing

@testable import SandboxKit

/// A kit install step is a multi-line bash program, not a command line. These
/// pin the three things that assumption broke.
@Suite("install script assembly")
struct InstallScriptTests {
    /// The bug that stopped every real kit installing: the step was spliced
    /// into an echo to report progress, truncated mid-expression, and the
    /// resulting unterminated `$(` failed to parse before anything ran.
    @Test("a step is never spliced into the script that runs it")
    func stepIsNotSpliced() {
        let step = """
            set -euo pipefail
            ARCH=$(dpkg --print-architecture)
            case "$ARCH" in
              arm64) echo "it's arm" ;;
            esac
            """
        let script = AgentPreparer.installScript(for: [step])

        // The program itself travels encoded; only its base64 appears.
        #expect(script.contains(Data(step.utf8).base64EncodedString()))
        #expect(!script.contains("case \"$ARCH\""))
        // The label does name the step, but inside single quotes, where a
        // command substitution is inert -- and it is never cut mid-expression,
        // which is what turned it into an unterminated `$(`.
        #expect(script.contains("'[1/1] ARCH=$(dpkg --print-architecture)'"))
        #expect(!script.contains("--print-architectur'"))
    }

    /// Appending `|| { ... }` to a multi-line step guards only its last line,
    /// so a step that failed halfway was reported as having succeeded.
    @Test("the whole step is checked, not its last line")
    func failureIsDetected() {
        let script = AgentPreparer.installScript(for: ["a\nb\nc"])
        #expect(script.contains("|| { printf"))
        // The check applies to the runner, which is given the entire step.
        #expect(script.contains("\"$RUNNER\" /tmp/sandbox-install-step"))
    }

    /// `set -euo pipefail` is the near-universal opening line of a kit step and
    /// is not POSIX, so dash cannot run one.
    @Test("bash runs the step where the image has it")
    func prefersBash() {
        let script = AgentPreparer.installScript(for: ["echo hi"])
        #expect(script.contains("command -v bash"))
        #expect(script.contains("RUNNER=bash"))
        // ...and an image with no bash still installs.
        #expect(script.contains("RUNNER=sh"))
    }

    /// Progress output is one line. A step's first line is usually `set -e` or
    /// a comment, which says nothing about what it does.
    @Test("the progress label is one meaningful line")
    func labelIsUseful() {
        let summary = AgentPreparer.summary(
            of: """
                # Install Trivy from a pinned release.
                set -euo pipefail
                TRIVY_VERSION=0.70.0
                curl -fsSL "$URL"
                """)
        #expect(summary == "TRIVY_VERSION=0.70.0")
        #expect(!summary.contains("\n"))
    }

    @Test("a long label is truncated rather than wrapped")
    func labelIsBounded() {
        let summary = AgentPreparer.summary(of: String(repeating: "x", count: 200))
        #expect(summary.count <= 60)
        #expect(summary.hasSuffix("…"))
    }

    /// A label goes into the generated script too, so a quote in a step must
    /// not be able to close the quoting around it.
    @Test("a quote in a step cannot escape the progress label")
    func labelIsQuoted() {
        let script = AgentPreparer.installScript(for: ["echo '; touch /pwned; echo '"])
        #expect(!script.contains("; touch /pwned; echo ;"))
        #expect(script.contains("'\\''"))
    }

    @Test("no steps, no script to run them")
    func noSteps() {
        let script = AgentPreparer.installScript(for: [])
        #expect(!script.contains("sandbox-install-step"))
    }
}
