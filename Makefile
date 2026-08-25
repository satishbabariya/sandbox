# airlock
#
# The CLI must be codesigned with com.apple.security.virtualization or
# Virtualization refuses to start the VM at runtime. Ad-hoc signing is enough
# for local development; distribution needs a real identity.

CONFIG      ?= debug
SIGN_ID     ?= -
BUILD_DIR   := .build/$(CONFIG)
CLI         := $(BUILD_DIR)/airlock
GATEWAY     := .build/bin/gvairlock
KERNEL      := .local/vmlinux-arm64
AIRLOCK_HOME ?= $(HOME)/.airlock

KATA_VERSION ?= 3.17.0
KATA_URL := https://github.com/kata-containers/kata-containers/releases/download/$(KATA_VERSION)/kata-static-$(KATA_VERSION)-arm64.tar.xz
KATA_KERNEL := vmlinux-6.12.28-153

.PHONY: all
all: build

.PHONY: build
build: $(GATEWAY) sign

.PHONY: cli
cli:
	@swift build -c $(CONFIG)

# Signing is not optional. An unsigned binary builds fine and then fails at
# VM start with an opaque error, so do it as part of every build.
.PHONY: sign
sign: cli
	@codesign --force --sign $(SIGN_ID) \
	   --entitlements airlock.entitlements \
	   --options runtime $(CLI) 2>/dev/null \
	 || codesign --force --sign $(SIGN_ID) --entitlements airlock.entitlements $(CLI)
	@echo "signed $(CLI)"
	@codesign -d --entitlements - $(CLI) 2>&1 | grep -q virtualization \
	  && echo "  com.apple.security.virtualization present" \
	  || { echo "  ERROR: entitlement missing"; exit 1; }

$(GATEWAY):
	@$(MAKE) -C netstack

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
	@mkdir -p $(AIRLOCK_HOME)
	@cp $(KERNEL) $(AIRLOCK_HOME)/vmlinux-arm64
	@echo "installed kernel to $(AIRLOCK_HOME)/vmlinux-arm64"

.PHONY: test
test:
	@swift test
	@$(MAKE) -C netstack test

.PHONY: clean
clean:
	@swift package clean
	@rm -rf .build
	@$(MAKE) -C netstack clean
