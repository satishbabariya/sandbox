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
    /// The environment variable the tool reads this credential from, set in
    /// the guest to the sentinel.
    ///
    /// Carried on the binding rather than looked up in a table, because a kit
    /// names it: a credential sandbox ships no preset for still has to reach
    /// the tool that wants it. Without this, such a credential got a binding
    /// and an allowed domain and then never fired, because nothing told the
    /// tool there was a key at all.
    public var environmentVariable: String?

    /// Headers to strip before injecting.
    ///
    /// An agent may authenticate differently from the credential backing it:
    /// one signed in with OAuth still sends an API-key header when the
    /// corresponding environment variable is set. Leaving that header in place
    /// sends the sentinel alongside the real token and the server rejects it.
    public var replaceHeaders: [String]

    public init(
        service: String, domain: String, header: String, format: String = "{}",
        replaceHeaders: [String] = [], environmentVariable: String? = nil
    ) {
        self.service = service
        self.domain = domain
        self.header = header
        self.format = format
        self.replaceHeaders = replaceHeaders
        self.environmentVariable = environmentVariable
    }

    private enum CodingKeys: String, CodingKey {
        case service, domain, header, format, replaceHeaders, environmentVariable
    }

    /// Only the service, domain and header are required, so a binding written
    /// by hand stays terse and one written by an older sandbox keeps decoding.
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            service: try c.decode(String.self, forKey: .service),
            domain: try c.decode(String.self, forKey: .domain),
            header: try c.decode(String.self, forKey: .header),
            format: try c.decodeIfPresent(String.self, forKey: .format) ?? "{}",
            replaceHeaders: try c.decodeIfPresent([String].self, forKey: .replaceHeaders) ?? [],
            environmentVariable: try c.decodeIfPresent(
                String.self, forKey: .environmentVariable))
    }

    /// What the guest is given in place of the real value.
    public static let sentinel = "sandbox-managed"

    /// Bindings for services agents commonly need, so the common case is
    /// `sandbox secret set anthropic` and nothing else.
    public static let presets: [String: CredentialBinding] = [
        "anthropic": CredentialBinding(
            service: "anthropic", domain: "api.anthropic.com",
            header: "x-api-key", format: "{}",
            environmentVariable: "ANTHROPIC_API_KEY"),
        "openai": CredentialBinding(
            service: "openai", domain: "api.openai.com",
            header: "authorization", format: "Bearer {}",
            environmentVariable: "OPENAI_API_KEY"),
        "github": CredentialBinding(
            service: "github", domain: "api.github.com",
            header: "authorization", format: "Bearer {}",
            environmentVariable: "GITHUB_TOKEN"),
        "gemini": CredentialBinding(
            service: "gemini", domain: "generativelanguage.googleapis.com",
            header: "x-goog-api-key", format: "{}",
            environmentVariable: "GEMINI_API_KEY"),
        // Reuses an OAuth sign-in already on the host rather than a stored key.
        "claude": CredentialBinding(
            service: "claude", domain: "api.anthropic.com",
            header: "authorization", format: "Bearer {}",
            // Claude Code sends x-api-key when ANTHROPIC_API_KEY is set, which
            // it is, to the sentinel. Both headers reaching the server means
            // the sentinel is judged alongside the real token.
            replaceHeaders: ["x-api-key"]),
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
    /// Headers the gateway strips before injecting.
    public var replace: [String]

    public init(domain: String, header: String, value: String, replace: [String] = []) {
        self.domain = domain
        self.header = header
        self.value = value
        self.replace = replace
    }
}

public struct BrokerConfiguration: Codable, Sendable, Equatable {
    public var credentials: [ResolvedCredential]

    public init(credentials: [ResolvedCredential]) {
        self.credentials = credentials
    }

    /// Resolve bindings to values.
    ///
    /// A binding whose secret is missing is skipped rather than fatal: the
    /// sandbox should still start, and the request will simply fail
    /// unauthenticated with a clear reason in the policy log.
    ///
    /// An explicitly stored secret wins over an OAuth token the agent already
    /// holds, because setting one is a deliberate act and should not be
    /// silently shadowed by a stale sign-in.
    public static func resolve(
        bindings: [CredentialBinding],
        store: SecretStore = SecretStore()
    ) -> (BrokerConfiguration, missing: [String], expired: [String]) {
        var resolved: [ResolvedCredential] = []
        var missing: [String] = []
        var expired: [String] = []

        for binding in bindings {
            var secret = try? store.get(binding.service)

            if secret == nil,
                let (_, source) = CredentialBinding.oauthPreset(for: binding.service),
                let credential = try? source.read()
            {
                if let expiry = credential.expiry, expiry < Date() {
                    // Injecting a dead token would fail with a confusing 401.
                    expired.append(binding.service)
                } else {
                    secret = credential.token
                }
            }

            guard let secret else {
                missing.append(binding.service)
                continue
            }
            resolved.append(
                ResolvedCredential(
                    domain: binding.domain,
                    header: binding.header,
                    value: binding.format.replacingOccurrences(of: "{}", with: secret),
                    replace: binding.replaceHeaders
                ))
        }
        // Several bindings can cover the same domain — an API key and an OAuth
        // sign-in both authenticate api.anthropic.com. Warning about the one
        // that is unset, when the other resolved, is noise that reads as a
        // problem.
        let covered = Set(resolved.map(\.domain))
        let domainFor = { (service: String) -> String? in
            bindings.first { $0.service == service }?.domain
        }
        missing = missing.filter { service in
            guard let domain = domainFor(service) else { return true }
            return !covered.contains(domain)
        }
        expired = expired.filter { service in
            guard let domain = domainFor(service) else { return true }
            return !covered.contains(domain)
        }

        return (BrokerConfiguration(credentials: resolved), missing, expired)
    }
}
