.PHONY: help build dev-install shim vet test test-all opa-test smoke e2e clean licenses licenses-check sign dist-tarball

BIN ?= bin/agentjail

## help        : list available targets
help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[1m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: $(BIN)  ## build the laptop binary

$(BIN):
	go build -o $(BIN) ./cmd/agentjail

INSTALL_DIR ?= $(HOME)/.agentjail/bin
DEV_BINS    := bin/agentjail bin/agentjail-hook bin/agentjail-daemon

dev-install: $(DEV_BINS)  ## build + install binaries, policy rules, and restart daemon; verify
	@echo "Installing binaries..."
	@mkdir -p $(INSTALL_DIR)
	@for b in $(DEV_BINS); do \
		name=$$(basename $$b); \
		cp $$b $(INSTALL_DIR)/$$name; \
		echo "  ✓ $$name"; \
	done
	@echo "Syncing policy rules..."
	@bin/agentjail install --for claude-code 2>&1 | grep -E "✓|⚠" | head -6
	@echo ""
	@echo "Verifying installation..."
	@ok=true; \
	for b in $(DEV_BINS); do \
		name=$$(basename $$b); \
		installed=$(INSTALL_DIR)/$$name; \
		if [ ! -f "$$installed" ]; then \
			echo "  ✗ $$name missing from $(INSTALL_DIR)"; ok=false; \
		else \
			src_hash=$$(shasum -a 256 $$b | cut -d' ' -f1); \
			dst_hash=$$(shasum -a 256 $$installed | cut -d' ' -f1); \
			if [ "$$src_hash" = "$$dst_hash" ]; then \
				echo "  ✓ $$name matches build"; \
			else \
				echo "  ✗ $$name hash mismatch (stale binary?)"; ok=false; \
			fi; \
		fi; \
	done; \
	$$ok && echo "" && echo "All binaries installed and verified. Restart Claude Code to activate." || \
		(echo "" && echo "Some binaries failed verification." && exit 1)

bin/agentjail-hook:
	go build -o bin/agentjail-hook ./cmd/agentjail-hook

bin/agentjail-daemon:
	go build -o bin/agentjail-daemon ./cmd/agentjail-daemon

shim:  ## build the C PATH shim into bin/agentjail-shim
	$(MAKE) -C agentjail/native/shim build

vet:  ## go vet on the laptop tree
	go vet ./...

test:  ## go test the laptop tree with -race
	go test ./... -race

test-all:  ## go test (all workspace modules) + opa test, all with -race
	go test ./... -race
	opa test agentpolicy/policies/

opa-test:  ## opa test over agentpolicy/policies/ (requires opa on PATH)
	opa test agentpolicy/policies/

smoke: ## run the end-to-end smoke tests (hook pipeline + OS sandbox)
	bash cmd/agentjail-hook/test/smoke.sh
	bash cmd/agentjail-shield/test/smoke.sh

e2e: ## full new-user E2E test (build, daemon, hook, store, replay, UI, filters, try)
	bash test/e2e-newuser.sh

# Full codesign identity, e.g. "Developer ID Application: NAME (TEAMID)".
# Kept out of the tree: set the APPLE_SIGNING_IDENTITY env var (the matching
# Developer ID certificate must be present in your login keychain).
APPLE_IDENTITY ?= $(APPLE_SIGNING_IDENTITY)

sign:  ## codesign macOS binaries (requires Developer ID certificate in keychain)
ifeq ($(shell uname),Darwin)
	@for bin in bin/agentjail bin/agentjail-hook bin/agentjail-daemon bin/agentjail-shield bin/agentjail-netproxy; do \
		if [ -f "$$bin" ]; then \
			echo "signing $$bin..."; \
			codesign --force --options runtime --sign "$(APPLE_IDENTITY)" --timestamp "$$bin"; \
		fi; \
	done
	@echo "all binaries signed"
else
	@echo "skip: codesign is macOS only"
endif

# dist-tarball builds all five binaries for a target platform and packs them
# in the flat layout install.sh expects (binaries at tarball top level). Used
# by test/testbed/testbed.sh provision to install a local build into a clean
# VM through the REAL user path (install.sh LOCAL_TARBALL= seam).
DIST_GOOS    ?= $(shell go env GOOS)
DIST_GOARCH  ?= $(shell go env GOARCH)
DIST_VERSION ?= dev-$(shell git rev-parse --short HEAD)
DIST_BINS    := agentjail agentjail-hook agentjail-daemon agentjail-shield agentjail-netproxy

dist-tarball:  ## build a release-layout tarball for testbed installs (DIST_GOOS/DIST_GOARCH to cross-build)
	@mkdir -p dist/$(DIST_GOOS)-$(DIST_GOARCH)
	@for bin in $(DIST_BINS); do \
		echo "building $$bin ($(DIST_GOOS)/$(DIST_GOARCH))..."; \
		GOOS=$(DIST_GOOS) GOARCH=$(DIST_GOARCH) CGO_ENABLED=0 \
		go build -ldflags "-X main.version=$(DIST_VERSION) -s -w" \
			-o dist/$(DIST_GOOS)-$(DIST_GOARCH)/$$bin ./cmd/$$bin; \
	done
	@tar -czf dist/agentjail-$(DIST_VERSION)-$(DIST_GOOS)-$(DIST_GOARCH).tar.gz \
		-C dist/$(DIST_GOOS)-$(DIST_GOARCH) $(DIST_BINS)
	@echo "dist/agentjail-$(DIST_VERSION)-$(DIST_GOOS)-$(DIST_GOARCH).tar.gz"

clean:  ## remove built binaries
	rm -rf bin/ dist/

licenses:  ## regenerate THIRD_PARTY_LICENSES from compiled-in deps
	./scripts/gen-third-party-licenses.sh

licenses-check:  ## fail if THIRD_PARTY_LICENSES is out of date (run after dep changes)
	./scripts/gen-third-party-licenses.sh --check
