#!/bin/sh
# Install sandbox from the latest GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/satishbabariya/sandbox/main/install.sh | sh
#
# Downloads the release archive, verifies its published checksum, and installs
# the signed binaries. No compiler, no Xcode, no Go: the archive carries the
# codesigned binary, and a curl download does not acquire the quarantine
# attribute that a browser download would.
#
# Environment:
#   SANDBOX_VERSION      install this tag instead of the latest (e.g. v0.1.4)
#   SANDBOX_INSTALL_DIR  install here instead of ~/.local/bin
#
# Re-running upgrades in place.

set -eu

REPO="satishbabariya/sandbox"
INSTALL_DIR="${SANDBOX_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
fail() { printf 'install: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "Darwin" ] || fail "sandbox runs on macOS (this is $(uname -s))"
[ "$(uname -m)" = "arm64" ] || fail "sandbox needs Apple silicon (this is $(uname -m))"
MACOS_MAJOR=$(sw_vers -productVersion | cut -d. -f1)
[ "$MACOS_MAJOR" -ge 26 ] 2>/dev/null \
  || say "note: sandbox targets macOS 26; this is $(sw_vers -productVersion), untested"

# Resolve the tag. The API needs no auth for public releases, and the asset
# names embed the tag, so "latest/download/..." alone is not enough.
if [ -n "${SANDBOX_VERSION:-}" ]; then
  TAG="$SANDBOX_VERSION"
else
  TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep -m1 '"tag_name"' | cut -d'"' -f4) || true
  [ -n "$TAG" ] || fail "could not find the latest release of $REPO"
fi

ARCHIVE="sandbox-$TAG-darwin-arm64.tar.gz"
BASE="https://github.com/$REPO/releases/download/$TAG"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

say "downloading sandbox $TAG..."
curl -fsSL -o "$ARCHIVE" "$BASE/$ARCHIVE" \
  || fail "no archive at $BASE/$ARCHIVE — is $TAG a release?"
curl -fsSL -o "$ARCHIVE.sha256" "$BASE/$ARCHIVE.sha256" \
  || fail "the release has no checksum file; refusing to install unverified"

# The published checksum is the only authority; a mismatch means a corrupted
# or substituted download and nothing gets installed.
shasum -a 256 -c "$ARCHIVE.sha256" >/dev/null 2>&1 \
  || fail "checksum mismatch for $ARCHIVE; not installing it"
say "checksum verified"

tar -xzf "$ARCHIVE"
SRC="sandbox-$TAG-darwin-arm64/bin"
if [ ! -x "$SRC/sandbox" ] || [ ! -x "$SRC/gvsandbox" ]; then
  fail "archive layout unexpected"
fi

# Belt and braces: curl does not set the quarantine attribute, but if this
# archive travelled through something that did, the signature check at VM
# start would fail with an opaque error.
xattr -dr com.apple.quarantine "$SRC" 2>/dev/null || true

PREVIOUS=""
command -v sandbox >/dev/null 2>&1 && PREVIOUS=$(sandbox --version 2>/dev/null || true)

mkdir -p "$INSTALL_DIR"
cp "$SRC/sandbox" "$SRC/gvsandbox" "$INSTALL_DIR/"

if [ -n "$PREVIOUS" ]; then
  say "installed sandbox $TAG to $INSTALL_DIR (was $PREVIOUS)"
else
  say "installed sandbox $TAG to $INSTALL_DIR"
fi

# Make sure the shell can find it. Only the profile of the user's own shell is
# touched, the line is marked so a re-run does not add it twice, and nothing
# is edited when the directory is already on PATH.
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    LINE="export PATH=\"$INSTALL_DIR:\$PATH\" # added by sandbox installer"
    for PROFILE in "$HOME/.zshrc" "$HOME/.bash_profile"; do
      case "$PROFILE" in
        *zshrc) [ "${SHELL##*/}" = "zsh" ] || continue ;;
        *bash_profile) [ "${SHELL##*/}" = "bash" ] || continue ;;
      esac
      grep -qF "# added by sandbox installer" "$PROFILE" 2>/dev/null && continue
      printf '\n%s\n' "$LINE" >>"$PROFILE"
      say "added $INSTALL_DIR to PATH in $PROFILE (open a new terminal to pick it up)"
    done
    ;;
esac

if [ ! -e "$HOME/.sandbox/vmlinux-arm64" ]; then
  say ""
  say "next steps:"
  say "  sandbox kernel install   # guest kernel, ~280 MiB, once"
  say "  sandbox doctor           # checks everything at once"
else
  say "run 'sandbox doctor' to check the install"
fi
