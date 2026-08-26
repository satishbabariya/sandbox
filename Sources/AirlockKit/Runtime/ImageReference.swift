import Foundation

/// Normalisation of image references to the fully qualified form.
///
/// Every other container tool accepts `alpine:3.20`, and so does every kit and
/// every piece of documentation a user has ever read. airlock's image store
/// wants `docker.io/library/alpine:3.20` and rejects anything shorter with
/// "invalid domain for image reference", which reads as the image being wrong
/// rather than the spelling. The rules here are Docker's own.
public enum ImageReference {
    /// Registry used when a reference names none.
    public static let defaultRegistry = "docker.io"
    /// Namespace used when a Docker Hub reference names none.
    public static let defaultNamespace = "library"

    /// Expand a reference to `registry/namespace/name:tag`, leaving one that
    /// already names a registry alone.
    public static func normalised(_ reference: String) -> String {
        let trimmed = reference.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return trimmed }

        guard let slash = trimmed.firstIndex(of: "/") else {
            // One segment is always a Docker Hub official image.
            return "\(defaultRegistry)/\(defaultNamespace)/\(trimmed)"
        }

        // A first segment is a registry when it looks like a host: it carries a
        // dot or a port, or it is localhost. "docker/sandbox-templates" has
        // neither, so "docker" is a Hub namespace and not a registry -- which
        // is exactly the case that made kits fail to run.
        let first = String(trimmed[trimmed.startIndex..<slash])
        if first == "localhost" || first.contains(".") || first.contains(":") {
            return trimmed
        }
        return "\(defaultRegistry)/\(trimmed)"
    }
}
