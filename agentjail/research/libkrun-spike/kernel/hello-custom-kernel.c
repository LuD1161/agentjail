/*
 * agentjail libkrun spike 
 *
 * Same boot path as the parent directory's hello.c , but loads
 * a *custom* kernel blob from a file via krun_set_kernel(...) instead
 * of letting libkrun dlopen libkrunfw and grab its built-in
 * KERNEL_BUNDLE. Proves we control the kernel bytes end-to-end and
 * lives alongside the  binary — opt-in, no regression.
 *
 * Boot path:
 *   krun_create_ctx
 *   krun_set_vm_config(1 vCPU, 256 MiB)
 *   krun_set_root(rootfs)
 *   krun_set_workdir("/")
 *   krun_set_kernel(<kernel-path>, KRUN_KERNEL_FORMAT_RAW, NULL, NULL)
 *   krun_set_exec("/bin/sh", argv, envp)
 *   krun_start_enter/ calls exit; does not return
 *
 * KRUN_KERNEL_FORMAT_RAW on aarch64 = the kernel "Image" format from
 * arch/arm64/boot/Image (Documentation/arm64/booting.rst). libkrun
 * copies the file verbatim to guest physical 0x8000_0000 and jumps
 * there — confirmed by reading containers/libkrun
 * src/vmm/src/builder.rs load_external_kernel for the aarch64
 * Raw arm.
 *
 * Once external_kernel is set, libkrun does NOT load libkrunfw
 * (containers/libkrun src/libkrun/src/lib.rs ~line 2658:
 *   if external_kernel.is_none && kernel_bundle.is_none
 *      && firmware_config.is_none { load_krunfw_payload(...) }
 * ) — so the bytes from disk are the entirety of the guest kernel.
 *
 * Measurement: same as hello.c — guest /proc/uptime upper-bounds
 * krun_start_enter -> first userspace instruction.
 *
 * Usage:  ./hello-custom-kernel <rootfs-dir> <kernel-path>
 * Build:  see kernel/Makefile (target: hello-custom-kernel).
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <libkrun.h>

static double monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

int main(int argc, char *const argv[])
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <rootfs-dir> <kernel-path>\n", argv[0]);
        return 2;
    }
    const char *rootfs = argv[1];
    const char *kernel_path = argv[2];

    /* Sanity-check the kernel file is present + non-empty before we
     * burn libkrun startup time on it. Fail-loud — kernel-loading
     * failures from inside libkrun surface as opaque VmCreate errors. */
    struct stat st;
    if (stat(kernel_path, &st) != 0) {
        fprintf(stderr, "[spike] stat %s: %s\n", kernel_path, strerror(errno));
        return 1;
    }
    if (st.st_size < 4096) {
        fprintf(stderr,
                "[spike] kernel %s suspiciously small (%lld bytes); refusing\n",
                kernel_path, (long long)st.st_size);
        return 1;
    }
    fprintf(stderr, "[spike] custom kernel: %s (%lld bytes)\n", kernel_path,
            (long long)st.st_size);

    /* Bump RLIMIT_NOFILE — virtio-fs opens many fds. (Mirrors hello.c.) */
    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
        rlim.rlim_cur = rlim.rlim_max;
        (void)setrlimit(RLIMIT_NOFILE, &rlim);
    }

    int rc = krun_init_log(STDERR_FILENO, KRUN_LOG_LEVEL_WARN,
                           KRUN_LOG_STYLE_AUTO, 0);
    if (rc) {
        errno = -rc;
        perror("krun_init_log");
        return 1;
    }

    double t_ctx_start = monotonic_ms;

    int32_t ctx = krun_create_ctx;
    if (ctx < 0) {
        errno = -ctx;
        perror("krun_create_ctx");
        return 1;
    }

    if ((rc = krun_set_vm_config(ctx, 1, 256))) {
        errno = -rc;
        perror("krun_set_vm_config");
        return 1;
    }

    if ((rc = krun_set_root(ctx, rootfs))) {
        errno = -rc;
        perror("krun_set_root");
        return 1;
    }

    if ((rc = krun_set_workdir(ctx, "/"))) {
        errno = -rc;
        perror("krun_set_workdir");
        return 1;
    }

    /* The custom-kernel swap. NULL initramfs (rootfs is virtio-fs),
     * NULL cmdline (libkrun supplies a sane default for its
     * virtio-console + virtio-fs init path; this matches what the
     * default libkrunfw path uses, so the boot environment is the
     * same and the time delta isolates "kernel-loading code path"
     * rather than "different cmdline"). */
    if ((rc = krun_set_kernel(ctx, kernel_path, KRUN_KERNEL_FORMAT_RAW,
                              NULL, NULL))) {
        errno = -rc;
        perror("krun_set_kernel");
        return 1;
    }

    /* Same guest workload as hello.c so the timings are comparable. */
    const char *const argv_guest[] = {
        "-c",
        "read U _ < /proc/uptime; echo hello uptime=$U",
        NULL
    };
    const char *const envp_guest[] = {
        "PATH=/bin:/sbin:/usr/bin:/usr/sbin", NULL
    };
    if ((rc = krun_set_exec(ctx, "/bin/sh", argv_guest, envp_guest))) {
        errno = -rc;
        perror("krun_set_exec");
        return 1;
    }

    double t_ctx_done = monotonic_ms;
    fprintf(stderr, "[spike] krun_create_ctx + config: %.2f ms\n",
            t_ctx_done - t_ctx_start);
    fflush(stderr);

    fprintf(stderr,
            "[spike] entering guest at host_t=%.2f ms "
            "(krun_start_enter does not return)\n",
            monotonic_ms - t_ctx_start);
    fflush(stderr);

    rc = krun_start_enter(ctx);

    /* Only reached on failure. */
    errno = -rc;
    perror("krun_start_enter");
    return 1;
}
