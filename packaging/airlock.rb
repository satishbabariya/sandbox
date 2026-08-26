# Homebrew formula for airlock.
#
# NOT PUBLISHED YET. The url and sha256 below point at a release tag that does
# not exist; both are filled in by the release workflow when one is cut. This
# file exists so that publishing is a matter of tagging, not of writing a
# formula under time pressure.
#
# Building from source rather than shipping a bottle: the binary must be
# codesigned with com.apple.security.virtualization on the machine it runs on,
# and a poured bottle would arrive without a signature that macOS accepts.
class Airlock < Formula
  desc "Run coding agents in sandboxes whose network egress they cannot bypass"
  homepage "https://github.com/satishbabariya/airlock"
  url "https://github.com/satishbabariya/airlock/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "REPLACE_ON_RELEASE"
  license "Apache-2.0"
  head "https://github.com/satishbabariya/airlock.git", branch: "main"

  depends_on arch: :arm64
  depends_on :macos
  # Package.swift declares macOS 26 as its minimum.
  depends_on macos: :tahoe
  depends_on "go" => :build

  def install
    system "make", "build", "CONFIG=release"
    bin.install ".build/release/airlock"
    bin.install ".build/bin/gvairlock"
    pkgshare.install "scripts/acceptance.sh"
  end

  def caveats
    <<~EOS
      Fetch a guest kernel before the first run:
        airlock kernel install

      Then check the install:
        airlock doctor

      airlock needs the com.apple.security.virtualization entitlement, which is
      applied at build time. If sandboxes fail to start with an entitlement
      error, reinstall with --build-from-source.
    EOS
  end

  test do
    assert_match "airlock", shell_output("#{bin}/airlock --help")
    # policy check needs no VM, so it is a real end-to-end check of the
    # matcher without requiring virtualization in the test sandbox.
    assert_match "deny", shell_output("#{bin}/airlock policy check evil.com 2>&1", 1)
    assert_match "allow", shell_output("#{bin}/airlock policy check example.com --allow example.com")
  end
end
