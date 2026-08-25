import Foundation

/// A rule for injecting one secret into requests bound for one domain.
///
/// The guest never holds the secret. It sends the sentinel, and the broker on
/// the host swaps in the real value per request — and only for a domain named
/// here, so a stolen sentinel is worthless anywhere else.
public struct CredentialBinding: Codable, Sendable, Equatable {
    /// Keychain service name, e.g. "anthropic".
    public var service: String
    /// The only domain this secret may be sent to.
    public var domain: String
    /// Header to set on the outbound request.
    public var header: String
    /// How to render the value. `{}` is replaced with the secret.
    public var format: String

    public init(service: String, domain: String, header: String, format: String = "{}") {
        self.service = service
        self.domain = domain
        self.header = header
        self.format = format
    }

    /// What the guest is given in place of the real value.
    public static let sentinel = "airlock-managed"

    /// Bindings for services agents commonly need, so the common case is
    /// `airlock secret set anthropic` and nothing else.
    public static let presets: [String: CredentialBinding] = [
        "anthropic": CredentialBinding(
            service: "anthropic", domain: "api.anthropic.com",
            header: "x-api-key", format: "{}"),
        "openai": CredentialBinding(
            service: "openai", domain: "api.openai.com",
            header: "authorization", format: "Bearer {}"),
        "github": CredentialBinding(
            service: "github", domain: "api.github.com",
            header: "authorization", format: "Bearer {}"),
        "gemini": CredentialBinding(
            service: "gemini", domain: "generativelanguage.googleapis.com",
            header: "x-goog-api-key", format: "{}"),
    ]

    /// The environment variable an agent expects, set to the sentinel so tools
    /// that require *something* present still run.
    public static let sentinelEnvironment: [String: String] = [
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "github": "GITHUB_TOKEN",
        "gemini": "GEMINI_API_KEY",
    ]

    public static func preset(for service: String) -> CredentialBinding? {
        presets[service.lowercased()]
    }
}

/// What the supervisor hands the gateway: bindings with their secrets resolved.
///
/// Written to a 0600 file on the *host*, inside the sandbox's runtime
/// directory. That directory is never shared into the VM, so the guest has no
/// path to it.
public struct ResolvedCredential: Codable, Sendable, Equatable {
    public var domain: String
    public var header: String
    /// Already formatted, e.g. "Bearer sk-...".
    public var value: String

    public init(domain: String, header: String, value: String) {
        self.domain = domain
        self.header = header
        self.value = value
    }
}

public struct BrokerConfiguration: Codable, Sendable, Equatable {
    public var credentials: [ResolvedCredential]

    public init(credentials: [ResolvedCredential]) {
        self.credentials = credentials
    }

    /// Resolve bindings against the keychain.
    ///
    /// A binding whose secret is missing is skipped rather than fatal: the
    /// sandbox should still start, and the request will simply fail
    /// unauthenticated with a clear reason in the policy log.
    public static func resolve(
        bindings: [CredentialBinding],
        store: SecretStore = SecretStore()
    ) -> (BrokerConfiguration, missing: [String]) {
        var resolved: [ResolvedCredential] = []
        var missing: [String] = []
        for binding in bindings {
            guard let secret = try? store.get(binding.service) else {
                missing.append(binding.service)
                continue
            }
            resolved.append(
                ResolvedCredential(
                    domain: binding.domain,
                    header: binding.header,
                    value: binding.format.replacingOccurrences(of: "{}", with: secret)
                ))
        }
        return (BrokerConfiguration(credentials: resolved), missing)
    }
}
