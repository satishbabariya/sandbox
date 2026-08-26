import Foundation
import Security

/// How a keychain read should behave when macOS wants the user to authorise it.
///
/// Reading an item can raise a system dialog. With a person at the terminal
/// that is the normal way to grant access once. With nobody there -- a script,
/// a CI step, an agent running unattended -- the dialog is never answered and
/// the read blocks forever: `airlock run claude` sat for nineteen minutes with
/// an empty runtime directory and no output, because a prompt nobody could see
/// was waiting behind it.
public enum KeychainInteraction: Sendable {
    case allowed
    case refused

    /// Prompt only when someone is there to answer.
    public static var automatic: KeychainInteraction {
        isatty(STDIN_FILENO) == 1 ? .allowed : .refused
    }
}

public enum SecretError: Error, CustomStringConvertible {
    case keychain(OSStatus, operation: String)
    case notFound(String)
    case invalidValue
    /// The item exists but macOS wanted the user to authorise reading it, and
    /// there was nobody to ask.
    case needsAuthorisation(String)

    public var description: String {
        switch self {
        case .keychain(let status, let operation):
            let message =
                SecCopyErrorMessageString(status, nil) as String?
                ?? "OSStatus \(status)"
            return "keychain \(operation) failed: \(message)"
        case .notFound(let service):
            return "no secret stored for '\(service)'"
        case .needsAuthorisation(let service):
            return """
                the keychain will not release '\(service)' without you approving it, \
                and nothing here can ask
                run `airlock secret check \(service)` once in a terminal and choose \
                Always Allow
                """
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

    public func get(
        _ service: String, interaction: KeychainInteraction = .automatic
    ) throws -> String {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: account(service),
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        if interaction == .refused {
            query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status != errSecItemNotFound else { throw SecretError.notFound(service) }
        guard status != errSecInteractionNotAllowed else {
            throw SecretError.needsAuthorisation(service)
        }
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
