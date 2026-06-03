# agentjail libkrun spike — network Makefile 
#
# Lives alongside the  Makefile (../Makefile),  Makefile
# (../kernel/Makefile), and  Makefile (../virtio-fs/Makefile).
# Does NOT modify any of them — `make boot` in those directories
# continues to work unchanged.
#
# Reproduction:
#   make            # build host binary, start socket_vmnet if needed, boot
#   make hello-net               # build the host binary
#   make socket-vmnet-up         # start socket_vmnet (requires sudo on first run)
#   make socket-vmnet-down       # stop socket_vmnet (requires sudo)
#   make boot                    # run a single boot with HTTPS reach
#   make verify                  # run boot + tcpdump capture; assert
#                                # IPv4 + outbound packets on the host TAP
#   make bench                   # 10 boots, print uptime + wall
#   make clean                   # remove built artefacts
#
# Tested on: macOS 26.2 / Darwin 25.2.0 / arm64,
# libkrun 1.18.1, socket_vmnet 1.2.2.

HERE       := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SPIKE      := $(abspath $(HERE)/..)
PREFIX     := $(shell brew --prefix)
LIBKRUN    := $(PREFIX)/opt/libkrun
LIBKRUNFW  := $(PREFIX)/opt/libkrunfw
SOCKVMNET  := $(PREFIX)/opt/socket_vmnet
SOCK       := $(PREFIX)/var/run/socket_vmnet

CC         ?= clang
CFLAGS     ?= -O2 -Wall -Wextra -Wno-unused-parameter
INCLUDE    := -I$(LIBKRUN)/include
LDFLAGS    := -L$(LIBKRUN)/lib -L$(LIBKRUNFW)/lib -lkrun \
              -Wl,-rpath,$(LIBKRUN)/lib -Wl,-rpath,$(LIBKRUNFW)/lib

HOSTBIN    := $(HERE)/hello-net
ROOTFS     := $(SPIKE)/rootfs
ENTITLE    := $(SPIKE)/hello.entitlements.plist

.PHONY: all hello-net boot verify bench clean rootfs-check socket-vmnet-up socket-vmnet-down socket-vmnet-check

all: hello-net boot

# Build the host binary and ad-hoc codesign with the  entitlements
# (Hypervisor.framework still gates the host process; the network
# device's vmnet entitlement is held by socket_vmnet, not by us — that's
# the whole point of going through the unixstream proxy).
$(HOSTBIN): $(HERE)/hello-net.c $(ENTITLE)
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $< $(LDFLAGS)
	codesign --force --sign - --entitlements $(ENTITLE) $@

hello-net: $(HOSTBIN)

rootfs-check:
	@if [ ! -x $(ROOTFS)/bin/busybox ]; then \
		echo "rootfs not prepared — run: make -C $(SPIKE) rootfs" >&2; \
		exit 1; \
	fi

socket-vmnet-check:
	@if [ ! -x $(SOCKVMNET)/bin/socket_vmnet ]; then \
		echo "socket_vmnet not installed — run: brew install socket_vmnet" >&2; \
		exit 1; \
	fi

# Idempotent: starts socket_vmnet under sudo if not already running.
# Uses --vmnet-mode=shared so the guest can reach the public internet
# via NAT through the host's default route. Logs to /tmp/socket_vmnet.log.
socket-vmnet-up: socket-vmnet-check
	@if [ -S $(SOCK) ] && pgrep -f 'socket_vmnet.*$(SOCK)' >/dev/null; then \
		echo "[socket-vmnet] already running, socket=$(SOCK)"; \
	else \
		echo "[socket-vmnet] starting (sudo required for vmnet.framework)..."; \
		sudo install -d -m 0755 $(dir $(SOCK)); \
		sudo $(SOCKVMNET)/bin/socket_vmnet \
		    --vmnet-mode=shared \
		    --pidfile=/tmp/socket_vmnet.pid \
		    $(SOCK) >/tmp/socket_vmnet.log 2>&1 & \
		for i in 1 2 3 4 5 6 7 8 9 10; do \
		    [ -S $(SOCK) ] && break; \
		    sleep 0.2; \
		done; \
		[ -S $(SOCK) ] || { echo "socket_vmnet failed to start; see /tmp/socket_vmnet.log" >&2; exit 1; }; \
		sudo chmod 0666 $(SOCK); \
		echo "[socket-vmnet] up; socket=$(SOCK)"; \
	fi

socket-vmnet-down:
	@if [ -f /tmp/socket_vmnet.pid ]; then \
		PID=$$(cat /tmp/socket_vmnet.pid); \
		echo "[socket-vmnet] stopping pid=$$PID"; \
		sudo kill $$PID 2>/dev/null || true; \
		sudo rm -f /tmp/socket_vmnet.pid $(SOCK); \
	else \
		sudo pkill -f 'socket_vmnet.*$(SOCK)' 2>/dev/null || true; \
		sudo rm -f $(SOCK); \
	fi

boot: $(HOSTBIN) rootfs-check socket-vmnet-up
	$(HOSTBIN) $(ROOTFS) $(SOCK)

# Round-trip verification with host-side tcpdump on the vmnet bridge
# interface. Sudo required (BPF device access).
verify: $(HOSTBIN) rootfs-check socket-vmnet-up
	@$(HERE)/verify.sh $(HOSTBIN) $(ROOTFS) $(SOCK)

bench: $(HOSTBIN) rootfs-check socket-vmnet-up
	$(HERE)/bench.sh 10

clean:
	rm -f $(HOSTBIN)
