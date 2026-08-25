# Builds gvairlock: gvisor-tap-vsock at a pinned commit, plus airlock's
# egress-policy patches.
#
# The upstream tree is not vendored into this repo. It is fetched at the SHA in
# UPSTREAM and the patches in patches/ are applied on top, so the entire
# difference between what upstream ships and what enforces your network policy
# is reviewable in one directory.

UPSTREAM_REPO ?= https://github.com/containers/gvisor-tap-vsock.git
UPSTREAM_SHA  := $(shell cat UPSTREAM)
WORK          ?= .work
BIN           ?= ../.build/bin/gvairlock

.PHONY: all
all: $(BIN)

$(WORK)/.fetched:
	@rm -rf $(WORK)
	@mkdir -p $(WORK)
	@echo "fetching gvisor-tap-vsock @ $(UPSTREAM_SHA)"
	@git -C $(WORK) init -q
	@git -C $(WORK) remote add origin $(UPSTREAM_REPO)
	@git -C $(WORK) fetch -q --depth 1 origin $(UPSTREAM_SHA)
	@git -C $(WORK) checkout -q FETCH_HEAD
	@touch $@

$(WORK)/.patched: $(WORK)/.fetched $(wildcard patches/*.patch)
	@echo "applying $(words $(wildcard patches/*.patch)) patch(es)"
	@git -C $(WORK) apply --whitespace=nowarn $(addprefix $(CURDIR)/,$(wildcard patches/*.patch))
	@touch $@

# The Swift and Go matchers must agree exactly; the Swift side powers
# `airlock policy check` while the Go side actually refuses the connection.
# Drift between them would make the CLI lie about what happens at runtime.
.PHONY: check-vectors
check-vectors: $(WORK)/.patched
	@diff -u ../testdata/host-patterns.json \
	        $(WORK)/pkg/policy/testdata/host-patterns.json \
	  && echo "conformance vectors match" \
	  || { echo "ERROR: policy test vectors have drifted between Swift and Go"; exit 1; }

$(BIN): $(WORK)/.patched check-vectors
	@mkdir -p $(dir $(BIN))
	@echo "building gvairlock"
	@cd $(WORK) && GOFLAGS=-mod=vendor CGO_ENABLED=0 go build -o $(CURDIR)/$(BIN) ./cmd/gvproxy
	@echo "built $(BIN)"

.PHONY: test
test: $(WORK)/.patched check-vectors
	@cd $(WORK) && GOFLAGS=-mod=vendor go test ./pkg/policy/ ./pkg/broker/ ./pkg/services/dns/ ./pkg/services/forwarder/

.PHONY: clean
clean:
	@rm -rf $(WORK) $(BIN)
