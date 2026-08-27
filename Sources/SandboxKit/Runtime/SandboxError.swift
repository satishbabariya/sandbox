import Containerization
import ContainerizationEXT4
import ContainerizationOCI
import ContainerizationOS
import Darwin
import Foundation
import Logging
import SystemPackage

public enum SandboxError: Error, CustomStringConvertible {
    case kernelNotFound(URL)
    case notRunning
    /// A VM refused to start. Reported with the remedy when the cause is the
    /// missing entitlement, which is the overwhelmingly common one.
    case notEntitled(underlying: any Error)

    public var description: String {
        switch self {
        case .kernelNotFound(let url):
            return """
                no Linux kernel at \(url.path)
                fetch one with: sandbox kernel install
                """
        case .notEntitled(let underlying):
            // The reason carries the detail; the description alone is only
            // "Invalid virtual machine configuration", which says nothing.
            let error = underlying as NSError
            let reason = error.localizedFailureReason ?? error.localizedDescription
            // Only claim to know the cause when the system actually said so;
            // any other failure to start is passed through as it came.
            guard reason.contains("entitlement") else { return String(describing: underlying) }
            return """
                \(reason)
                the binary must be signed with com.apple.security.virtualization
                a plain `swift build`, or a `swift test`, replaces the signed one
                run: make build
                """
        case .notRunning:
            return "sandbox is not running"
        }
    }
}

/// Everything needed to bring one sandbox up.
