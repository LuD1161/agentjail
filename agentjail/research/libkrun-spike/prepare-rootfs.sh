#!/usr/bin/env bash
#  spike: prepare a minimal Linux aarch64 rootfs containing busybox
# (so /bin/sh works) that libkrun can mount via virtio-fs.
#
# KISS: download Alpine minirootfs (~3.7 MB), extract into ./rootfs/.
# Idempotent: re-running is a no-op if the rootfs already looks good.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOTFS="${HERE}/rootfs"
ALPINE_VER="3.20.3"
ALPINE_BASE="alpine-minirootfs-${ALPINE_VER}-aarch64"
ALPINE_URL="https:/dl-cdn.alpinelinux.org/alpine/v3.20/releases/aarch64/${ALPINE_BASE}.tar.gz"
ALPINE_SHA256="041fa34a81788242df9e78fa69b97ab45b8ec47ddbf88864755610414a7bf3de"

if [ -x "${ROOTFS}/bin/busybox" ] && [ -L "${ROOTFS}/bin/sh" ]; then
    echo "[prepare-rootfs] ${ROOTFS} already populated; skipping download"
    exit 0
fi

mkdir -p "${HERE}/cache" "${ROOTFS}"
TARBALL="${HERE}/cache/${ALPINE_BASE}.tar.gz"

if [ ! -f "${TARBALL}" ]; then
    echo "[prepare-rootfs] downloading ${ALPINE_URL}"
    curl -fL --retry 3 -o "${TARBALL}.part" "${ALPINE_URL}"
    mv "${TARBALL}.part" "${TARBALL}"
fi

echo "[prepare-rootfs] verifying sha256"
ACTUAL_SHA256="$(shasum -a 256 "${TARBALL}" | awk '{print $1}')"
if [ "${ACTUAL_SHA256}" != "${ALPINE_SHA256}" ]; then
    echo "[prepare-rootfs] sha256 mismatch:"
    echo "  expected: ${ALPINE_SHA256}"
    echo "  actual:   ${ACTUAL_SHA256}"
    exit 1
fi

echo "[prepare-rootfs] extracting into ${ROOTFS}"
tar -xzf "${TARBALL}" -C "${ROOTFS}"

# Sanity check: busybox binary present and /bin/sh is a symlink (resolves
# inside the guest to /bin/busybox, so we check the symlink + the target
# busybox binary on the host side).
if [ ! -x "${ROOTFS}/bin/busybox" ] || [ ! -L "${ROOTFS}/bin/sh" ]; then
    echo "[prepare-rootfs] ${ROOTFS} missing busybox or /bin/sh symlink" >&2
    exit 1
fi

echo "[prepare-rootfs] ready: ${ROOTFS}"
