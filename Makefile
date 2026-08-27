# sandbox
#
# The CLI must be codesigned with com.apple.security.virtualization or
# Virtualization refuses to start the VM at runtime. Ad-hoc signing is enough
# for local development; distribution needs a real identity.

CONFIG      ?= debug
SIGN_ID     ?= -
BUILD_DIR   := .build/$(CONFIG)
CLI         := $(BUILD_DIR)/sandbox
GATEWAY     := .build/bin/gvsandbox
KERNEL      := .local/vmlinux-arm64
SANDBOX_HOME ?= $(HOME)/.sandbox

KATA_VERSION ?= 3.17.0
KATA_URL := https://github.com/kata-containers/kata-containers/releases/download/$(KATA_VERSION)/kata-static-$(KATA_VERSION)-arm64.tar.xz
KATA_KERNEL := vmlinux-6.12.28-153

.PHONY: all
all: build

.PHONY: build
build: gateway sign

.PHONY: cli
cli:
	@swift build -c $(CONFIG)

# Signing is not optional. An unsigned binary builds fine and then fails at
# VM start with an opaque error, so do it as part of every build.
.PHONY: sign
sign: cli
	@codesign --force --sign $(SIGN_ID) \
	   --entitlements sandbox.entitlements \
	   --options runtime $(CLI) 2>/dev/null \
	 || codesign --force --sign $(SIGN_ID) --entitlements sandbox.entitlements $(CLI)
	@echo "signed $(CLI)"
	@codesign -d --entitlements - $(CLI) 2>&1 | grep -q virtualization \
	  && echo "  com.apple.security.virtualization present" \
	  || { echo "  ERROR: entitlement missing"; exit 1; }

# Must be phony and always recursed into. As a file target with no
# prerequisites, make would consider an existing binary up to date and never
# notice that the patches under netstack/ had changed — which silently shipped
# a stale gateway.
.PHONY: gateway
gateway:
	@$(MAKE) -C netstack

# A guest kernel is required to boot anything. Kata's is used because it is
# prebuilt for arm64 and is what containerization's own test suite fetches.
.PHONY: kernel
kernel: $(KERNEL)

$(KERNEL):
	@mkdir -p .local
	@echo "fetching kata $(KATA_VERSION) kernel"
	@curl -fSL --progress-bar -o .local/kata.tar.xz "$(KATA_URL)"
	@tar -xJf .local/kata.tar.xz -C .local/ ./opt/kata/share/kata-containers/$(KATA_KERNEL)
	@cp .local/opt/kata/share/kata-containers/$(KATA_KERNEL) $(KERNEL)
	@rm -rf .local/opt .local/kata.tar.xz
	@echo "kernel at $(KERNEL)"

# Stage the kernel where the CLI looks for it at runtime.
.PHONY: install-kernel
install-kernel: $(KERNEL)
	@mkdir -p $(SANDBOX_HOME)
	@cp $(KERNEL) $(SANDBOX_HOME)/vmlinux-arm64
	@echo "installed kernel to $(SANDBOX_HOME)/vmlinux-arm64"

# The CLI finds the gateway beside itself, so both go in the same bin
# directory. Installing the debug build would work but ships an unoptimised
# binary, so this builds release unless CONFIG says otherwise.
PREFIX ?= /usr/local

# Build the archive a release publishes.
#
# Defined here rather than only in the release workflow so it can be run and
# checked without cutting a tag: the tarball is what a user actually downloads,
# and the entitlement it carries is what decides whether it can start a VM at
# all. VERSION is the tag, e.g. v0.1.0.
VERSION ?= v0.0.0-dev
STAGE := sandbox-$(VERSION)-darwin-arm64

.PHONY: package
package:
	@$(MAKE) build CONFIG=release
	@rm -rf dist/$(STAGE)
	@mkdir -p dist/$(STAGE)/bin
	@cp .build/release/sandbox dist/$(STAGE)/bin/
	@cp $(GATEWAY) dist/$(STAGE)/bin/
	@cp README.md LICENSE SECURITY.md dist/$(STAGE)/
	@tar -czf dist/$(STAGE).tar.gz -C dist $(STAGE)
	# Recorded from inside dist/, so the file names the archive rather than the
	# path it happened to be built at. `shasum -c` looks for the name it is
	# given, and "dist/..." is not where a user who downloaded both has it.
	@cd dist && shasum -a 256 $(STAGE).tar.gz | tee $(STAGE).tar.gz.sha256
	@$(MAKE) verify-package

# Check the archive, not the build tree. codesign travels in an extended
# attribute, and an archive that dropped it would install cleanly and then fail
# at VM start with an error about entitlements rather than about the download.
.PHONY: verify-package
verify-package:
	@rm -rf dist/verify && mkdir -p dist/verify
	@tar -xzf dist/$(STAGE).tar.gz -C dist/verify
	@codesign -d --entitlements - dist/verify/$(STAGE)/bin/sandbox 2>&1 \
	  | grep -q virtualization \
	  || { echo "ERROR: the archived binary has no virtualization entitlement"; exit 1; }
	@test -x dist/verify/$(STAGE)/bin/gvsandbox \
	  || { echo "ERROR: the archive has no gateway, so no sandbox can start"; exit 1; }
	@dist/verify/$(STAGE)/bin/sandbox --version >/dev/null \
	  || { echo "ERROR: the archived binary does not run"; exit 1; }
	@echo "package ok: $$(dist/verify/$(STAGE)/bin/sandbox --version), entitlement intact"
	@rm -rf dist/verify

.PHONY: install
install:
	@$(MAKE) build CONFIG=release
	@mkdir -p $(PREFIX)/bin
	@cp .build/release/sandbox $(PREFIX)/bin/sandbox
	@cp $(GATEWAY) $(PREFIX)/bin/gvsandbox
	@codesign -d --entitlements - $(PREFIX)/bin/sandbox 2>&1 | grep -q virtualization \
	  || { echo "ERROR: installed binary lost its entitlement"; exit 1; }
	@echo "installed to $(PREFIX)/bin"
	@echo "next: sandbox kernel install && sandbox doctor"

.PHONY: uninstall
uninstall:
	@rm -f $(PREFIX)/bin/sandbox $(PREFIX)/bin/gvsandbox
	@echo "removed sandbox and gvsandbox from $(PREFIX)/bin"
	@echo "state in $(SANDBOX_HOME) was left alone; remove it by hand if you want it gone"

.PHONY: test
test:
	@swift test
	@$(MAKE) -C netstack test

.PHONY: clean
clean:
	@swift package clean
	@rm -rf .build
	@$(MAKE) -C netstack clean

.PHONY: acceptance
acceptance: build
	@scripts/acceptance.sh
