import Foundation
import Yams

/// A Docker Sandboxes kit artifact, as far as airlock understands it.
///
/// Kits are the extension format `sbx` uses, and there is a body of existing
/// ones. Reading them means that work carries across rather than having to be
/// rewritten as an agent profile by hand.
///
/// This decodes a faithful subset. Everything it cannot honour is *reported*
/// rather than dropped — a silently ignored deny rule or install step would be
/// a correctness problem, and in the deny case a security one.
public struct KitSpec: Decodable, Sendable {
    public var schemaVersion: String?
    public var kind: String?
    public var name: String
    public var displayName: String?
    public var description: String?
    public var sandbox: Sandbox?
    public var permissions: Permissions?
    public var credentials: [Credential]?
    public var environment: Environment?
    public var setup: Setup?
    public var ports: [Port]?
    public var security: Security?
    public var mixins: [String]?
    public var `extends`: String?
    /// A mixin may declare which agent it belongs to.
    public var requires: Requires?
    /// Guidance a kit wants delivered to the agent.
    public var agentInstructions: AgentInstructions?

    public struct Requires: Decodable, Sendable {
        public var agent: String?
    }

    public struct AgentInstructions: Decodable, Sendable {
        public var filename: String?
        public var content: String?
    }

    public struct Sandbox: Decodable, Sendable {
        public var image: String?
        public var entrypoint: [String]?
        public var command: Command?

        public struct Command: Decodable, Sendable {
            public var `default`: [String]?
            public var interactive: [String]?
        }
    }

    public struct Permissions: Decodable, Sendable {
        public var network: Network?

        public struct Network: Decodable, Sendable {
            public var allow: [String]?
            public var deny: [String]?
        }
    }

    public struct Credential: Decodable, Sendable {
        public var service: String
        public var apiKey: APIKey?
        public var oauth: OAuth?

        public struct APIKey: Decodable, Sendable {
            public var name: String?
            public var proxyManaged: Bool?
            public var inject: [Inject]?

            public struct Inject: Decodable, Sendable {
                public var domain: String
                public var header: String?
                public var format: String?
                public var scheme: String?
            }
        }

        public struct OAuth: Decodable, Sendable {
            /// Real kits write this as `{host, path}`, not a string.
            public var tokenEndpoint: Endpoint?

            public struct Endpoint: Decodable, Sendable {
                public var host: String?
                public var path: String?

                public var description: String {
                    [host, path].compactMap { $0 }.joined()
                }
            }
        }
    }

    public struct Environment: Decodable, Sendable {
        public var variables: [String: String]?
    }

    public struct Setup: Decodable, Sendable {
        public var install: [Step]?
        public var startup: [Step]?
        public var files: [FileEntry]?

        /// `install` uses a command string; `startup` uses argv. Both shapes
        /// appear in real kits, so both decode.
        public struct Step: Decodable, Sendable {
            public var command: CommandValue
            public var user: String?
            public var background: Bool?
            public var description: String?

            public enum CommandValue: Decodable, Sendable {
                case shell(String)
                case argv([String])

                public init(from decoder: Decoder) throws {
                    let container = try decoder.singleValueContainer()
                    if let text = try? container.decode(String.self) {
                        self = .shell(text)
                    } else {
                        self = .argv(try container.decode([String].self))
                    }
                }

                public var shellCommand: String {
                    switch self {
                    case .shell(let text): return text
                    case .argv(let parts):
                        return parts.map(Self.quote).joined(separator: " ")
                    }
                }

                /// argv entries become one shell string, so anything with
                /// whitespace or a metacharacter has to survive the trip.
                static func quote(_ argument: String) -> String {
                    let safe = CharacterSet.alphanumerics.union(
                        CharacterSet(charactersIn: "-_./:=@"))
                    if argument.unicodeScalars.allSatisfy({ safe.contains($0) }) {
                        return argument
                    }
                    return "'" + argument.replacingOccurrences(of: "'", with: "'\\''") + "'"
                }
            }
        }

        public struct FileEntry: Decodable, Sendable {
            public var path: String
            public var mode: String?
            public var content: String?
            public var description: String?
        }
    }

    public struct Port: Decodable, Sendable {
        public var container: Int
        public var host: Int?
        public var proto: String?

        enum CodingKeys: String, CodingKey {
            case container
            case host
            case proto = "protocol"
        }
    }

    public struct Security: Decodable, Sendable {
        public var privileged: Bool?
    }

    public static func load(from url: URL) throws -> KitSpec {
        let text = try String(contentsOf: url, encoding: .utf8)
        return try YAMLDecoder().decode(KitSpec.self, from: text)
    }
}
