import Foundation

/// Normalisation of image references to the fully qualified form.
///
/// Every other container tool accepts `alpine:3.20`, and so does every kit and
/// every piece of documentation a user has ever read. sandbox's image store
/// wants `docker.io/library/alpine:3.20` and rejects anything shorter with
/// "invalid domain for image reference", which reads as the image being wrong
/// rather than the spelling. The rules here are Docker's own.
public enum ImageReference {
    /// Registry used when a reference names none.
    public static let defaultRegistry = "docker.io"
    /// Namespace used when a Docker Hub reference names none.
    public static let defaultNamespace = "library"

    /// Tag used when a reference names none.
    public static let defaultTag = "latest"

    /// Expand a reference to `registry/namespace/name:tag`, leaving the parts
    /// it already names alone.
    public static func normalised(_ reference: String) -> String {
        let trimmed = reference.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return trimmed }
        return withDefaultTag(withRegistry(trimmed))
    }

    private static func withRegistry(_ reference: String) -> String {
        guard let slash = reference.firstIndex(of: "/") else {
            // One segment is always a Docker Hub official image.
            return "\(defaultRegistry)/\(defaultNamespace)/\(reference)"
        }

        // A first segment is a registry when it looks like a host: it carries a
        // dot or a port, or it is localhost. "docker/sandbox-templates" has
        // neither, so "docker" is a Hub namespace and not a registry -- which
        // is exactly the case that made kits fail to run.
        let first = String(reference[reference.startIndex..<slash])
        if first == "localhost" || first.contains(".") || first.contains(":") {
            return reference
        }
        return "\(defaultRegistry)/\(reference)"
    }

    /// Append `:latest` when nothing else names a version.
    ///
    /// Only the last path segment is considered: a registry may carry a port,
    /// and `localhost:5000/app` names no tag despite the colon.
    private static func withDefaultTag(_ reference: String) -> String {
        let name = reference.split(separator: "/").last.map(String.init) ?? reference
        if name.contains("@") || name.contains(":") { return reference }
        return "\(reference):\(defaultTag)"
    }
}
