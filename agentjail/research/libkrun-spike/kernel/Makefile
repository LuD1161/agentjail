# agentjail libkrun spike — custom-kernel Makefile 
#
# Lives alongside the  Makefile (../Makefile). Does NOT modify
# 's targets — `make boot` in the parent directory still uses
# libkrunfw's bundled kernel. This file owns only the  add-ons.
#
# Reproduction:
#   make            # extract kernel + build hosts + boot once
#   make kernel     # extract Image from libkrunfw.dylib -> Image
#   make hello-custom-kernel        # build the custom-kernel host binary
#   make boot                       # one boot via krun_set_kernel
#   make bench                      # 10 boots, print uptime + wall
#   make clean                      # remove built artefacts (keeps Image)
#   make distclean                  # also remove Image
#
# Tested on: macOS 26.2 / Darwin 25.2.0 / arm64, libkrun 1.18.1, libkrunfw 5.3.0.

HERE       := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SPIKE      := $(abspath $(HERE)/..)
PREFIX     := $(shell brew --prefix)
LIBKRUN    := $(PREFIX)/opt/libkrun
LIBKRUNFW  := $(PREFIX)/opt/libkrunfw

CC         ?= clang
CFLAGS     ?= -O2 -Wall -Wextra -Wno-unused-parameter
INCLUDE    := -I$(LIBKRUN)/include
# Match parent Makefile's link flags so the binary loads exactly the
# same libkrun runtime as `hello`. -L for libkrunfw stays — even though
# we explicitly bypass libkrunfw, libkrun's lib.rs always tries to
# resolve KRUNFW_NAME during ctx setup (it just doesn't *use* it when
# external_kernel is set; see hello-custom-kernel.c for the citation).
LDFLAGS    := -L$(LIBKRUN)/lib -L$(LIBKRUNFW)/lib -lkrun \
              -Wl,-rpath,$(LIBKRUN)/lib -Wl,-rpath,$(LIBKRUNFW)/lib

KERNEL_IMG := $(HERE)/Image
EXTRACTOR  := $(HERE)/extract-libkrunfw-kernel
HOSTBIN    := $(HERE)/hello-custom-kernel
ROOTFS     := $(SPIKE)/rootfs
ENTITLE    := $(SPIKE)/hello.entitlements.plist

.PHONY: all kernel hello-custom-kernel boot bench clean distclean rootfs-check

all: hello-custom-kernel kernel boot

# Build the kernel extractor (dlopens libkrunfw at runtime).
$(EXTRACTOR): $(HERE)/extract-libkrunfw-kernel.c
	$(CC) $(CFLAGS) -o $@ $< -ldl -Wl,-rpath,$(LIBKRUNFW)/lib

# Extract the kernel Image from libkrunfw.dylib so we can pass it to
# krun_set_kernel as a "custom" external kernel. This is the simplest
# reproducible source of a libkrun-bootable aarch64 Image — see
# README.md and KERNEL_BUILD.md for how to drop in your own.
$(KERNEL_IMG): $(EXTRACTOR)
	$(EXTRACTOR) $(KERNEL_IMG)

kernel: $(KERNEL_IMG)

# Build the custom-kernel host binary. Reuses 's entitlement
# plist from the parent directory — Hypervisor.framework still gates
# the host process regardless of which kernel blob libkrun loads.
$(HOSTBIN): $(HERE)/hello-custom-kernel.c $(ENTITLE)
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $< $(LDFLAGS)
	codesign --force --sign - --entitlements $(ENTITLE) $@

hello-custom-kernel: $(HOSTBIN)

rootfs-check:
	@if [ ! -x $(ROOTFS)/bin/busybox ]; then \
		echo "rootfs not prepared — run: make -C $(SPIKE) rootfs" >&2; \
		exit 1; \
	fi

boot: $(HOSTBIN) $(KERNEL_IMG) rootfs-check
	$(HOSTBIN) $(ROOTFS) $(KERNEL_IMG)

bench: $(HOSTBIN) $(KERNEL_IMG) rootfs-check
	$(HERE)/bench.sh 10

clean:
	rm -f $(HOSTBIN) $(EXTRACTOR)

distclean: clean
	rm -f $(KERNEL_IMG)
