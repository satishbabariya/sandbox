# Homebrew formula for sandbox.
#
# NOT PUBLISHED YET. The url and sha256 below point at a release tag that does
# not exist; both are filled in by the release workflow when one is cut, which
# also publishes this file as a release asset. Copy it into the tap from there
# rather than editing it by hand, so the checksum is the one that was actually
# built.
#
# It exists here so that publishing is a matter of tagging, not of writing a
# formula under time pressure.
#
# Building from source rather than shipping a bottle: the binary must be
# codesigned with com.apple.security.virtualization on the machine it runs on,
# and a poured bottle would arrive without a signature that macOS accepts.
class Sandbox < Formula
  desc "Run coding agents in sandboxes whose network egress they cannot bypass"
  homepage "https://github.com/satishbabariya/sandbox"
  url "https://github.com/satishbabariya/sandbox/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "REPLACE_ON_RELEASE"
  license "Apache-2.0"
  head "https://github.com/satishbabariya/sandbox.git", branch: "main"

  depends_on arch: :arm64
  # Package.swift declares macOS 26 as its minimum. A version requirement
  # already implies the platform, and stating both is deprecated -- brew warns
  # on every command that touches the formula.
  depends_on macos: :tahoe
  depends_on "go" => :build

  def install
    # The release workflow stamps the version into a checkout it builds from,
    # but the source tarball still carries the placeholder -- so a formula that
    # skipped this would install a binary whose --version lies about itself.
    inreplace "Sources/SandboxKit/Version.swift", "0.0.1-dev", version.to_s unless build.head?

    # --disable-sandbox: SwiftPM compiles Package.swift inside its own
    # sandbox-exec, and macOS refuses to nest that inside brew's build sandbox
    # -- "sandbox_apply: Operation not permitted", before any source is read.
    system "make", "build", "CONFIG=release", "SWIFT_BUILD_FLAGS=--disable-sandbox"
    bin.install ".build/release/sandbox"
    bin.install ".build/bin/gvsandbox"
    pkgshare.install "scripts/acceptance.sh"
  end

  def caveats
    <<~EOS
      Fetch a guest kernel before the first run:
        sandbox kernel install

      Then check the install:
        sandbox doctor

      sandbox needs the com.apple.security.virtualization entitlement, which is
      applied at build time. If sandboxes fail to start with an entitlement
      error, reinstall with --build-from-source.
    EOS
  end

  test do
    assert_match "sandbox", shell_output("#{bin}/sandbox --help")
    # policy check needs no VM, so it is a real end-to-end check of the
    # matcher without requiring virtualization in the test sandbox.
    assert_match "deny", shell_output("#{bin}/sandbox policy check evil.com 2>&1", 1)
    assert_match "allow", shell_output("#{bin}/sandbox policy check example.com --allow example.com")
  end
end
