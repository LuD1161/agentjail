CC ?= cc
CFLAGS ?= -Os -Wall -Wextra -std=c11
DEST ?= ../../../bin/agentjail-shim

TOOLS = git npm npx node sh bash zsh rm mv cp ls cat curl wget find ssh scp \
        python python3 pip pip3 chmod chown ln mkdir rmdir touch \
        ripgrep rg fd jq sed awk grep make go cargo rustc \
        yarn pnpm

build: $(DEST)

$(DEST): shim.c
	@mkdir -p $(dir $(DEST))
	$(CC) $(CFLAGS) -o $(DEST) shim.c

# Ad-hoc codesign with hardened runtime. macOS's linker already produces
# an ad-hoc linker signature on each build; this target replaces it with a
# hardened-runtime ad-hoc signature so AMFI enforces stricter integrity checks
# (no unsigned dynamic libraries, no DYLD_INSERT_LIBRARIES into us).
# CI path: if DEVELOPER_ID is set in the environment, sign with that Apple
# Developer ID Application identity instead, which adds authenticity (the
# Team ID is bound into the signature) on top of integrity.
codesign-adhoc: $(DEST)
	@if [ -n "$$DEVELOPER_ID" ]; then \
		echo "agentjail: signing $(DEST) with Developer ID: $$DEVELOPER_ID"; \
		codesign --force --sign "$$DEVELOPER_ID" --options runtime --timestamp $(DEST); \
	else \
		echo "agentjail: ad-hoc signing $(DEST) with hardened runtime"; \
		codesign --force --sign - --options runtime $(DEST); \
	fi
	@codesign --verify --strict --verbose=2 $(DEST)

codesign-verify: $(DEST)
	codesign --verify --strict --verbose=2 $(DEST)

# Integration test for self-verification. Builds, signs (ad-hoc with
# hardened runtime), then flips one byte in the text segment and confirms the
# tampered binary refuses to run (nonzero exit, no execv into the resolved
# target tool). Skips cleanly on non-Darwin hosts.
test-self-verify: $(DEST)
	@./test_self_verify.sh

test-fork-bomb-limiter: $(DEST)
	@./test_fork_bomb_limiter.sh

install-links: $(DEST)
	@dir=$${SHIM_DIR:-$$HOME/.agentjail/shims}; \
	mkdir -p $$dir; \
	for t in $(TOOLS); do ln -sf $(realpath $(DEST)) "$$dir/$$t"; done; \
	echo "agentjail: shims installed in $$dir"

clean:
	rm -f $(DEST)

.PHONY: build install-links clean codesign-adhoc codesign-verify test-self-verify test-fork-bomb-limiter
