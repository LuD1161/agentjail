.PHONY: help build adr-check dev-install dev-deploy shim vet test test-all opa-test smoke e2e clean ui ui-deps licenses licenses-check sign dist-tarball e2e-release chaos

BIN ?= bin/agentjail

## help        : list available targets
help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[1m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: $(BIN)  ## build the laptop binary

$(BIN):
	go build -o $(BIN) ./cmd/agentjail

INSTALL_DIR ?= $(HOME)/.agentjail/bin
# Only the 2 real binaries are ever copied into INSTALL_DIR as files. The
# subsequent `agentjail install` call below reconciles the four role
# symlinks (agentjail-daemon, agentjail-shield, agentjail-netproxy,
# agentjail-secrets) itself via selfupdate.EnsureRoleSymlinks -- never cp/mv
# a real binary over one of those names.
DEV_BINS    := bin/agentjail bin/agentjail-hook

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

dev-deploy:  ## build all 5 binaries from the working tree + hot-swap the local install and restart daemon (run from a plain terminal)
	./scripts/dev-deploy.sh

bin/agentjail-hook:
	go build -o bin/agentjail-hook ./cmd/agentjail-hook

bin/agentjail-daemon:  ## dev-only compile-check artifact; never installed as a real file (see DEV_BINS above)
	go build -o bin/agentjail-daemon ./cmd/agentjail-daemon

shim:  ## build the C PATH shim into bin/agentjail-shim
	$(MAKE) -C agentjail/native/shim build

vet:  ## go vet on the laptop tree
	go vet ./...

adr-check:  ## fail on duplicate ADR numbers / bad ADR filenames (ADR 0083)
	./scripts/adr-check.sh

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

e2e-release: ## RELEASE GATE: clean VM -> real installer -> policy enforcement (run before tagging)
	bash test/testbed/testbed.sh gate --worktree .

# Cadence: run locally before pushing to main, and before a major release. NOT
# every PR, NOT minor/patch, NOT in CI -- a local gate like e2e-release, not a
# runner job. Slow by construction (hookwatch is a 30s ticker), so kept out of
# e2e-release to keep the release gate fast enough to actually get run.
# See ADR 0092-chaos-run-cadence.
#
# Explicit list, never a chaos-*.sh glob: chaos-lib.sh matches that glob and is a
# sourced library, not a scenario.
CHAOS_SCENARIOS := chaos-daemon-outage chaos-supervisor-restart chaos-hook-tamper

chaos:  ## failure-injection suite against a provisioned testbed (TESTBED=<name>)
	@[ -n "$(TESTBED)" ] || { echo "usage: make chaos TESTBED=<name>   (see test/testbed/README.md)"; exit 2; }
	@failed=""; \
	for s in $(CHAOS_SCENARIOS); do \
		echo "=== $$s"; \
		bash test/testbed/testbed.sh test "$(TESTBED)" "$$s" || failed="$$failed $$s"; \
	done; \
	if [ -n "$$failed" ]; then echo ""; echo "chaos FAILED:$$failed"; exit 1; fi; \
	echo ""; echo "chaos: all $(words $(CHAOS_SCENARIOS)) scenarios passed"

# Full codesign identity, e.g. "Developer ID Application: NAME (TEAMID)".
# Kept out of the tree: set the APPLE_SIGNING_IDENTITY env var (the matching
# Developer ID certificate must be present in your login keychain).
APPLE_IDENTITY ?= $(APPLE_SIGNING_IDENTITY)

sign:  ## codesign macOS binaries (requires Developer ID certificate in keychain)
ifeq ($(shell uname),Darwin)
	@for bin in bin/agentjail bin/agentjail-hook; do \
		if [ -f "$$bin" ]; then \
			echo "signing $$bin..."; \
			codesign --force --options runtime --sign "$(APPLE_IDENTITY)" --timestamp "$$bin"; \
		fi; \
	done
	@echo "all binaries signed"
else
	@echo "skip: codesign is macOS only"
endif

# dist-tarball builds the two real binaries for a target platform and packs
# them in the flat layout install.sh expects (binaries at tarball top level).
# The four role names (agentjail-daemon, agentjail-shield, agentjail-netproxy,
# agentjail-secrets) are relative symlinks to agentjail, created at install
# time by install.sh / selfupdate.EnsureRoleSymlinks -- they are never shipped
# in the tarball. Used by test/testbed/testbed.sh provision to install a local
# build into a clean VM through the REAL user path (install.sh
# LOCAL_TARBALL= seam).
DIST_GOOS    ?= $(shell go env GOOS)
DIST_GOARCH  ?= $(shell go env GOARCH)
DIST_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev-$$(git rev-parse --short HEAD))
DIST_BINS    := agentjail agentjail-hook

dist-tarball:  ## build a release-layout tarball for testbed installs (DIST_GOOS/DIST_GOARCH to cross-build)
	@mkdir -p dist/$(DIST_GOOS)-$(DIST_GOARCH)
	@for bin in $(DIST_BINS); do \
		echo "building $$bin ($(DIST_GOOS)/$(DIST_GOARCH))..."; \
		GOOS=$(DIST_GOOS) GOARCH=$(DIST_GOARCH) CGO_ENABLED=0 \
		go build -ldflags "-X github.com/LuD1161/agentjail/internal/buildinfo.Version=$(DIST_VERSION) -s -w" \
			-o dist/$(DIST_GOOS)-$(DIST_GOARCH)/$$bin ./cmd/$$bin; \
	done
	@tar -czf dist/agentjail-$(DIST_VERSION)-$(DIST_GOOS)-$(DIST_GOARCH).tar.gz \
		-C dist/$(DIST_GOOS)-$(DIST_GOARCH) $(DIST_BINS)
	@echo "dist/agentjail-$(DIST_VERSION)-$(DIST_GOOS)-$(DIST_GOARCH).tar.gz"

clean:  ## remove built binaries
	rm -rf bin/ dist/

FRONTEND := cmd/agentjail/ui/frontend
SPA_DIST := cmd/agentjail/ui/static/dist

ui-deps:  ## install the web UI's npm dependencies (needs bun)
	cd $(FRONTEND) && bun install --frozen-lockfile

# Scrubs stale assets by hand because vite's emptyOutDir is off: it would delete
# the tracked $(SPA_DIST)/.gitkeep that keeps `go:embed all:static/dist` matching
# on a clean clone. Never re-enable emptyOutDir.
ui: ui-deps  ## build the React web UI into static/dist (embedded by go:embed)
	@mkdir -p $(SPA_DIST) && touch $(SPA_DIST)/.gitkeep
	@find $(SPA_DIST) -mindepth 1 ! -name .gitkeep -delete
	cd $(FRONTEND) && bun run build
	@test -f $(SPA_DIST)/index.html \
		|| { echo "ui: $(SPA_DIST)/index.html not produced — SPA would ship unbuilt"; exit 1; }
	@test -f $(SPA_DIST)/.gitkeep \
		|| { echo "ui: $(SPA_DIST)/.gitkeep was deleted — clean clones will not build"; exit 1; }

licenses: ui-deps  ## regenerate THIRD_PARTY_LICENSES from compiled-in Go + npm deps
	./scripts/gen-third-party-licenses.sh

licenses-check: ui-deps  ## fail if THIRD_PARTY_LICENSES is out of date (run after dep changes)
	./scripts/gen-third-party-licenses.sh --check
