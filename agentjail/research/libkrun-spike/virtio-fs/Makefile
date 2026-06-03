# agentjail libkrun spike — virtio-fs Makefile 
#
# Lives alongside the  Makefile (../Makefile) and  Makefile
# (../kernel/Makefile). Does NOT modify either — `make boot` in those
# directories continues to work unchanged.
#
# Reproduction:
#   make            # build host binary, run round-trip + isolation test
#   make hello-virtfs              # build the host binary
#   make boot                      # run a single boot + verify round-trip
#   make verify                    # run boot, then assert from-guest.txt
#                                  # exists on host with expected payload
#   make bench                     # 10 boots, print uptime + wall
#   make clean                     # remove built artefacts (keeps workdir)
#   make distclean                 # also remove the test workdir
#
# Tested on: macOS 26.2 / Darwin 25.2.0 / arm64, libkrun 1.18.1.

HERE       := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SPIKE      := $(abspath $(HERE)/..)
PREFIX     := $(shell brew --prefix)
LIBKRUN    := $(PREFIX)/opt/libkrun
LIBKRUNFW  := $(PREFIX)/opt/libkrunfw

CC         ?= clang
CFLAGS     ?= -O2 -Wall -Wextra -Wno-unused-parameter
INCLUDE    := -I$(LIBKRUN)/include
# Match parent Makefile's link flags so the binary loads exactly the
# same libkrun runtime as ../hello.
LDFLAGS    := -L$(LIBKRUN)/lib -L$(LIBKRUNFW)/lib -lkrun \
              -Wl,-rpath,$(LIBKRUN)/lib -Wl,-rpath,$(LIBKRUNFW)/lib

HOSTBIN    := $(HERE)/hello-virtfs
ROOTFS     := $(SPIKE)/rootfs
ENTITLE    := $(SPIKE)/hello.entitlements.plist
WORKDIR    ?= $(HERE)/workdir

.PHONY: all hello-virtfs boot verify bench clean distclean rootfs-check workdir

all: hello-virtfs workdir boot

# Build the host binary and ad-hoc codesign with 's entitlements
# (Hypervisor.framework still gates the host process regardless of which
# virtio-fs devices libkrun configures).
$(HOSTBIN): $(HERE)/hello-virtfs.c $(ENTITLE)
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $< $(LDFLAGS)
	codesign --force --sign - --entitlements $(ENTITLE) $@

hello-virtfs: $(HOSTBIN)

rootfs-check:
	@if [ ! -x $(ROOTFS)/bin/busybox ]; then \
		echo "rootfs not prepared — run: make -C $(SPIKE) rootfs" >&2; \
		exit 1; \
	fi

# Prepare a tiny host workdir with a fixture file the guest will read.
workdir:
	@mkdir -p $(WORKDIR)
	@printf 'hello from host pid=%s\n' "$$$$" > $(WORKDIR)/from-host.txt
	@rm -f $(WORKDIR)/from-guest.txt

boot: $(HOSTBIN) rootfs-check workdir
	$(HOSTBIN) $(ROOTFS) $(WORKDIR)

# Assertion harness: run the boot, capture stdout, then check
#   - guest printed from-host-payload= matching what host wrote
#   - guest_write=ok appeared
#   - isolation_exit != 0 (cat /opt/homebrew/Cellar must fail in-guest)
#   - host can now see /work/from-guest.txt with the guest's payload
verify: $(HOSTBIN) rootfs-check workdir
	@$(HERE)/verify.sh $(HOSTBIN) $(ROOTFS) $(WORKDIR)

bench: $(HOSTBIN) rootfs-check workdir
	$(HERE)/bench.sh 10

clean:
	rm -f $(HOSTBIN)

distclean: clean
	rm -rf $(WORKDIR)
