.PHONY: help build shim vet test test-all opa-test smoke e2e clean licenses licenses-check

BIN ?= bin/agentjail

## help        : list available targets
help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[1m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: $(BIN)  ## build the laptop binary

$(BIN):
	go build -o $(BIN) ./cmd/agentjail

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

clean:  ## remove built binaries
	rm -rf bin/

licenses:  ## regenerate THIRD_PARTY_LICENSES from compiled-in deps
	./scripts/gen-third-party-licenses.sh

licenses-check:  ## fail if THIRD_PARTY_LICENSES is out of date (run after dep changes)
	./scripts/gen-third-party-licenses.sh --check
