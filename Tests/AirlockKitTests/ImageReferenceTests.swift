import Testing

@testable import AirlockKit

/// Getting these rules wrong does not fail loudly -- it pulls a different
/// image, or refuses one that was spelled the way every other container tool
/// accepts. They are Docker's rules, pinned here.
@Suite("image references")
struct ImageReferenceTests {
    @Test("a bare name is a Docker Hub official image")
    func bareName() {
        #expect(ImageReference.normalised("alpine") == "docker.io/library/alpine")
        #expect(ImageReference.normalised("alpine:3.20") == "docker.io/library/alpine:3.20")
    }

    /// The case that made 14 of the 21 kits in the corpus fail to run: "docker"
    /// here is a Hub namespace, not a registry.
    @Test("a namespaced name goes to Docker Hub, not to a registry called docker")
    func namespacedName() {
        #expect(
            ImageReference.normalised("docker/sandbox-templates:shell-docker")
                == "docker.io/docker/sandbox-templates:shell-docker")
        #expect(ImageReference.normalised("nanoco/nanoclaw") == "docker.io/nanoco/nanoclaw")
    }

    /// A first segment that looks like a host is a registry and must be left
    /// exactly as written -- rewriting it would send credentials somewhere else.
    @Test("a reference that names a registry is untouched")
    func registryIsPreserved() {
        for reference in [
            "docker.io/library/alpine:3.20",
            "ghcr.io/apple/containerization/vminit:0.41.0",
            "quay.io/podman/hello",
            "registry.example.com:5000/team/app:v1",
            "localhost:5000/dev/app",
            "localhost/dev/app",
        ] {
            #expect(ImageReference.normalised(reference) == reference)
        }
    }

    /// A digest is part of the identity of the image; losing or mangling it
    /// would pull something else entirely.
    @Test("tags and digests survive")
    func tagsAndDigests() {
        #expect(
            ImageReference.normalised("alpine@sha256:abc123")
                == "docker.io/library/alpine@sha256:abc123")
        #expect(
            ImageReference.normalised("myorg/app@sha256:abc123")
                == "docker.io/myorg/app@sha256:abc123")
    }

    /// Normalising is what the store needs, so doing it twice must not build
    /// docker.io/library/docker.io/library/alpine.
    @Test("normalising twice changes nothing")
    func idempotent() {
        for reference in ["alpine", "docker/sandbox-templates:shell", "ghcr.io/o/i:1"] {
            let once = ImageReference.normalised(reference)
            #expect(ImageReference.normalised(once) == once)
        }
    }

    @Test("nothing in, nothing out")
    func empty() {
        #expect(ImageReference.normalised("") == "")
        #expect(ImageReference.normalised("   ") == "")
    }
}
