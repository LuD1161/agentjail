/*
 * agentjail libkrun spike  — extract the bundled kernel image
 * from libkrunfw.dylib so we can boot it via krun_set_kernel as a
 * "custom" external kernel.
 *
 * Why this exists:  requires booting a *custom* kernel blob
 * through libkrun's external-kernel API (krun_set_kernel) instead of
 * the implicit libkrunfw-via-dlopen path. Building a fresh Linux
 * kernel from source is a multi-hour, multi-GB-toolchain detour that
 * the task itself flags as "prefer a pre-built minimal kernel + config
 * we can iterate on". The pragmatic seed is the already-vetted kernel
 * libkrunfw ships: same version, same config, known-good — but
 * extracted to a file and loaded explicitly so we own the bytes.
 * Anyone who wants to iterate on the config can follow
 * kernel/KERNEL_BUILD.md and drop in their own Image; the rest of the
 * spike doesn't care which Image is on disk.
 *
 * Usage:
 *   ./extract-libkrunfw-kernel <output-path>
 *
 * Mechanism: dlopen(libkrunfw.5.dylib), resolve krunfw_get_kernel
 * (declared in libkrunfw's generated kernel.c: returns the pointer
 * to KERNEL_BUNDLE[] and writes load_addr/entry_addr/size out-args),
 * write `size` bytes verbatim to <output-path>. The aarch64 bundle
 * format is the raw Image (linux/Documentation/arm64/booting.rst)
 * padded to 64 KiB; krun_set_kernel(..., KRUN_KERNEL_FORMAT_RAW, ...)
 * accepts exactly this shape on aarch64 and copies it to guest
 * physical 0x8000_0000.
 */

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* libkrunfw symbol signature (verified by `nm -gU` on the dylib and
 * by reading containers/libkrunfw bin2cbundle.py write_footer_kernel). */
typedef char *(*krunfw_get_kernel_fn)(size_t *load_addr, size_t *entry_addr,
                                       size_t *size);
typedef int (*krunfw_get_version_fn)(void);

int main(int argc, char *const argv[])
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <output-path>\n", argv[0]);
        return 2;
    }
    const char *out_path = argv[1];

    /* Use the same search the libkrun runtime uses (KRUNFW_NAME on macOS). */
    const char *candidates[] = {
        "libkrunfw.5.dylib",                                 /* RPATH search */
        "/opt/homebrew/opt/libkrunfw/lib/libkrunfw.5.dylib", /* brew default */
        "/usr/local/opt/libkrunfw/lib/libkrunfw.5.dylib",    /* intel brew   */
        NULL,
    };

    void *h = NULL;
    for (size_t i = 0; candidates[i] != NULL; i++) {
        h = dlopen(candidates[i], RTLD_LAZY | RTLD_LOCAL);
        if (h != NULL) {
            fprintf(stderr, "[extract] loaded %s\n", candidates[i]);
            break;
        }
    }
    if (h == NULL) {
        fprintf(stderr, "[extract] dlopen libkrunfw.5.dylib failed: %s\n",
                dlerror);
        fprintf(stderr, "          install with: brew install libkrunfw\n");
        return 1;
    }

    krunfw_get_kernel_fn get_kernel =
        (krunfw_get_kernel_fn)dlsym(h, "krunfw_get_kernel");
    if (get_kernel == NULL) {
        fprintf(stderr, "[extract] dlsym krunfw_get_kernel: %s\n", dlerror);
        return 1;
    }
    krunfw_get_version_fn get_version =
        (krunfw_get_version_fn)dlsym(h, "krunfw_get_version");

    size_t load_addr = 0, entry_addr = 0, size = 0;
    char *blob = get_kernel(&load_addr, &entry_addr, &size);
    if (blob == NULL || size == 0) {
        fprintf(stderr, "[extract] krunfw_get_kernel returned no payload\n");
        return 1;
    }

    fprintf(stderr,
            "[extract] libkrunfw ABI v%d, kernel %zu bytes, "
            "load=0x%zx entry=0x%zx\n",
            get_version ? get_version : -1, size, load_addr, entry_addr);

    FILE *f = fopen(out_path, "wb");
    if (f == NULL) {
        perror("[extract] fopen");
        return 1;
    }
    size_t wrote = fwrite(blob, 1, size, f);
    if (wrote != size) {
        fprintf(stderr,
                "[extract] short write: wanted %zu, got %zu (errno=%d)\n",
                size, wrote, errno);
        fclose(f);
        return 1;
    }
    if (fclose(f) != 0) {
        perror("[extract] fclose");
        return 1;
    }

    fprintf(stderr, "[extract] wrote %zu bytes to %s\n", size, out_path);
    return 0;
}
