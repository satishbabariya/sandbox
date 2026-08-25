import Foundation
import Security

public enum SecretError: Error, CustomStringConvertible {
    case keychain(OSStatus, operation: String)
    case notFound(String)
    case invalidValue

    public var description: String {
        switch self {
        case .keychain(let status, let operation):
            let message =
                SecCopyErrorMessageString(status, nil) as String?
                ?? "OSStatus \(status)"
            return "keychain \(operation) failed: \(message)"
        case .notFound(let service):
            return "no secret stored for '\(service)'"
        case .invalidValue:
            return "secret value must be valid UTF-8"
        }
    }
}

/// Secrets for services the sandbox may authenticate to, held in the macOS
/// Keychain.
///
/// The point of storing them here rather than in a config file is that the
/// value never has to be materialised where the sandbox can read it. The
/// broker pulls it at request time on the host; the guest only ever sees a
/// sentinel.
public struct SecretStore: Sendable {
    /// Namespaced so airlock's entries are distinguishable from anything else
    /// in the user's keychain.
    public static let servicePrefix = "com.airlock.secret."

    public init() {}

    private func account(_ service: String) -> String {
        Self.servicePrefix + service.lowercased()
    }

    public func set(_ service: String, value: String) throws {
        guard let data = value.data(using: .utf8) else { throw SecretError.invalidValue }
        let key = account(service)

        // Try update first so repeated `secret set` overwrites rather than
        // erroring with duplicate-item.
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: key,
        ]
        let update: [String: Any] = [kSecValueData as String: data]

        let updateStatus = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else {
            throw SecretError.keychain(updateStatus, operation: "update")
        }

        var add = query
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw SecretError.keychain(addStatus, operation: "add")
        }
    }

    public func get(_ service: String) throws -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: account(service),
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status != errSecItemNotFound else { throw SecretError.notFound(service) }
        guard status == errSecSuccess, let data = item as? Data else {
            throw SecretError.keychain(status, operation: "read")
        }
        guard let value = String(data: data, encoding: .utf8) else {
            throw SecretError.invalidValue
        }
        return value
    }

    public func remove(_ service: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: account(service),
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status != errSecItemNotFound else { throw SecretError.notFound(service) }
        guard status == errSecSuccess else {
            throw SecretError.keychain(status, operation: "delete")
        }
    }

    /// Service names only — values are never listed, so a shoulder-surfed
    /// terminal cannot leak one.
    public func list() throws -> [String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let entries = items as? [[String: Any]] else {
            throw SecretError.keychain(status, operation: "list")
        }
        return
            entries
            .compactMap { $0[kSecAttrService as String] as? String }
            .filter { $0.hasPrefix(Self.servicePrefix) }
            .map { String($0.dropFirst(Self.servicePrefix.count)) }
            .sorted()
    }
}
