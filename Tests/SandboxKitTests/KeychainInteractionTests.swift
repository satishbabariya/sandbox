import Foundation
import Testing

@testable import SandboxKit

/// Reading a keychain item can raise a system dialog. With nobody at the
/// terminal that dialog is never answered and the read blocks forever, which is
/// how `sandbox run claude` came to sit for nineteen minutes with an empty
/// runtime directory and no output at all.
@Suite("keychain interaction")
struct KeychainInteractionTests {
    /// The tests themselves run without a terminal, which is exactly the
    /// situation the policy exists for.
    @Test("with nobody at the terminal, a prompt is refused rather than waited on")
    func refusedWithoutATerminal() {
        #expect(isatty(STDIN_FILENO) == 0, "this test is meaningless on a tty")
        #expect(KeychainInteraction.automatic == .refused)
    }

    /// The refusal has to say what to do about it. "keychain read failed:
    /// interaction not allowed" is the system's wording and tells a user
    /// nothing they can act on.
    @Test("the refusal explains how to grant access")
    func messageIsActionable() {
        let message = String(describing: SecretError.needsAuthorisation("anthropic"))
        #expect(message.contains("anthropic"))
        #expect(message.contains("sandbox secret check"))
        #expect(message.contains("Always Allow"))
    }

    /// A missing secret and a secret that cannot be read are different
    /// problems: one is fixed by storing it, the other by approving it.
    @Test("a missing secret is not reported as an authorisation problem")
    func distinctFromNotFound() {
        let missing = String(describing: SecretError.notFound("anthropic"))
        #expect(missing.contains("no secret stored"))
        #expect(!missing.contains("Always Allow"))
    }
}
