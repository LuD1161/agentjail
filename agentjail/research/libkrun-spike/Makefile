# agentjail libkrun spike — Makefile 
#
# Reproduction:
#   make            # install deps, build, prepare rootfs, boot the microVM
#   make deps       # brew tap + install libkrun (idempotent)
#   make rootfs     # download + extract Alpine minirootfs
#   make hello      # build the host binary
#   make boot       # run the spike (assumes deps + rootfs ready)
#   make clean      # remove built artefacts (keeps rootfs cache)
#   make distclean  # also remove rootfs/ and cache/
#
# Tested on: macOS 26.2 / Darwin 25.2.0 / arm64.

PREFIX     := $(shell brew --prefix)
LIBKRUN    := $(PREFIX)/opt/libkrun
LIBKRUNFW  := $(PREFIX)/opt/libkrunfw

CC         ?= clang
CFLAGS     ?= -O2 -Wall -Wextra -Wno-unused-parameter
INCLUDE    := -I$(LIBKRUN)/include
# We link against libkrun; libkrunfw is dlopen'd by libkrun at runtime.
LDFLAGS    := -L$(LIBKRUN)/lib -L$(LIBKRUNFW)/lib -lkrun \
              -Wl,-rpath,$(LIBKRUN)/lib -Wl,-rpath,$(LIBKRUNFW)/lib

ROOTFS     := rootfs

.PHONY: all deps rootfs boot bench clean distclean

all: deps hello rootfs boot

deps:
	@if ! brew list --formula 2>/dev/null | grep -q '^libkrun$$'; then \
		echo "[deps] tapping slp/krun"; brew tap slp/krun; \
		echo "[deps] installing libkrun"; brew install libkrun; \
	else \
		echo "[deps] libkrun already installed: $$(brew list --versions libkrun)"; \
	fi

hello: hello.c hello.entitlements.plist
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $< $(LDFLAGS)
	# Apple Silicon requires com.apple.security.hypervisor on the host process
	# (Hypervisor.framework returns HV_ERROR otherwise). Ad-hoc sign with
	# the entitlements plist; no developer cert needed for local use.
	codesign --force --sign - --entitlements hello.entitlements.plist $@

rootfs: $(ROOTFS)/bin/busybox

$(ROOTFS)/bin/busybox: prepare-rootfs.sh
	./prepare-rootfs.sh

boot: hello $(ROOTFS)/bin/busybox
	./hello $(ROOTFS)

bench: hello $(ROOTFS)/bin/busybox
	./bench.sh 10

clean:
	rm -f hello

distclean: clean
	rm -rf rootfs cache
