import AirlockKit
import ArgumentParser
import Foundation

struct SecretCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "secret",
        abstract: "Store credentials the sandbox can use but never see.",
        discussion: """
            Secrets live in the macOS Keychain. When a sandbox is bound to one, \
            the guest is given the sentinel '\(CredentialBinding.sentinel)' and \
            the real value is substituted on the host, per request, only for the \
            domain the credential is bound to.
            """,
        subcommands: [SecretSet.self, SecretList.self, SecretRemove.self],
        defaultSubcommand: SecretList.self
    )
}

struct SecretSet: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "set",
        abstract: "Store a secret. Reads the value from stdin."
    )

    @Argument(help: "Service name, e.g. anthropic, openai, github, gemini.")
    var service: String

    @Flag(name: .long, help: "Read the value from stdin instead of prompting.")
    var stdin: Bool = false

    func run() async throws {
        let value: String
        if stdin || !isatty(STDIN_FILENO).boolValue {
            let data = FileHandle.standardInput.readDataToEndOfFile()
            value = String(decoding: data, as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
        } else {
            // Prompt with echo off so the secret never appears on screen or in
            // shell history.
            value = try Self.promptWithoutEcho("value for '\(service)': ")
        }
        guard !value.isEmpty else {
            throw ValidationError("empty value; nothing stored")
        }

        try SecretStore().set(service, value: value)

        if let binding = CredentialBinding.preset(for: service) {
            print("stored '\(service)'; sandboxes may send it to \(binding.domain)")
        } else {
            print(
                """
                stored '\(service)'
                note: no built-in binding for '\(service)', so nothing will be \
                injected until one is added
                """)
        }
    }

    static func promptWithoutEcho(_ prompt: String) throws -> String {
        FileHandle.standardError.write(Data(prompt.utf8))
        var original = termios()
        tcgetattr(STDIN_FILENO, &original)
        var quiet = original
        quiet.c_lflag &= ~UInt(ECHO)
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet)
        defer {
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &original)
            FileHandle.standardError.write(Data("\n".utf8))
        }
        return readLine(strippingNewline: true) ?? ""
    }
}

struct SecretList: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ls",
        abstract: "List stored secret names. Values are never printed.",
        aliases: ["list"]
    )

    func run() async throws {
        let services = try SecretStore().list()
        guard !services.isEmpty else {
            print("no secrets stored")
            return
        }
        for service in services {
            if let binding = CredentialBinding.preset(for: service) {
                print("\(service)  ->  \(binding.domain)  (\(binding.header))")
            } else {
                print("\(service)  ->  (no binding; not injected)")
            }
        }
    }
}

struct SecretRemove: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "rm",
        abstract: "Remove a stored secret.",
        aliases: ["remove"]
    )

    @Argument(help: "Service name.")
    var service: String

    func run() async throws {
        try SecretStore().remove(service)
        print("removed '\(service)'")
    }
}

extension Int32 {
    var boolValue: Bool { self != 0 }
}
