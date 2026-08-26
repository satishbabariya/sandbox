import Foundation
import Security

/// Reads a credential another application already stores in the login keychain.
///
/// Agents are commonly signed in with OAuth rather than an API key, and the
/// resulting token lives in that application's own keychain item. Reading it on
/// the host means an OAuth-signed-in agent gets the same treatment as one using
/// an API key: the guest holds a sentinel, and the real token is substituted
/// per request.
///
/// macOS will ask the user to authorise this the first time, which is correct —
/// it is their credential, and they should be told something else wants it.
public struct HostKeychainSource: Codable, Sendable, Equatable {
    /// Keychain service name, e.g. "Claude Code-credentials".
    public var service: String
    /// Path into the stored JSON, e.g. ["claudeAiOauth", "accessToken"].
    public var jsonPath: [String]
    /// Sibling key holding a Unix expiry, in seconds or milliseconds.
    public var expiryPath: [String]?

    public init(service: String, jsonPath: [String], expiryPath: [String]? = nil) {
        self.service = service
        self.jsonPath = jsonPath
        self.expiryPath = expiryPath
    }

    /// Read the token, or nil when the item is absent or the path does not
    /// resolve. Absence is normal — the user may not have signed in.
    public func read() throws -> (token: String, expiry: Date?)? {
        guard let data = try Self.rawItem(service: service) else { return nil }
        guard
            let root = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            throw SecretError.invalidValue
        }
        guard let token = Self.string(at: jsonPath, in: root) else { return nil }

        var expiry: Date?
        if let expiryPath, let raw = Self.number(at: expiryPath, in: root) {
            // Some apps store seconds, others milliseconds. Anything past the
            // year 3000 in seconds is certainly milliseconds.
            expiry = Date(timeIntervalSince1970: raw > 32_503_680_000 ? raw / 1000 : raw)
        }
        return (token, expiry)
    }

    static func rawItem(service: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            throw SecretError.keychain(status, operation: "read '\(service)'")
        }
        return data
    }

    static func string(at path: [String], in root: [String: Any]) -> String? {
        var node: Any = root
        for key in path {
            guard let dictionary = node as? [String: Any], let next = dictionary[key] else {
                return nil
            }
            node = next
        }
        return node as? String
    }

    static func number(at path: [String], in root: [String: Any]) -> Double? {
        var node: Any = root
        for key in path {
            guard let dictionary = node as? [String: Any], let next = dictionary[key] else {
                return nil
            }
            node = next
        }
        if let value = node as? Double { return value }
        if let value = node as? Int { return Double(value) }
        return nil
    }
}

/// Where a credential's value comes from.
public enum CredentialSource: Codable, Sendable, Equatable {
    /// A value the user stored with `airlock secret set`.
    case airlockKeychain
    /// A token another application already holds, typically from an OAuth
    /// sign-in the user has already completed.
    case hostKeychain(HostKeychainSource)
}

extension CredentialBinding {
    /// Bindings that reuse a sign-in the user has already done, so `airlock run
    /// claude` works without a separate `airlock secret set`.
    public static let oauthPresets: [String: (CredentialBinding, HostKeychainSource)] = [
        "claude": (
            CredentialBinding(
                service: "claude",
                domain: "api.anthropic.com",
                header: "authorization",
                format: "Bearer {}"),
            HostKeychainSource(
                service: "Claude Code-credentials",
                jsonPath: ["claudeAiOauth", "accessToken"],
                expiryPath: ["claudeAiOauth", "expiresAt"])
        )
    ]

    public static func oauthPreset(for service: String) -> (CredentialBinding, HostKeychainSource)? {
        oauthPresets[service.lowercased()]
    }
}
