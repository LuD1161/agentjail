/*
 * agentjail libkrun spike 
 *
 * Minimum-viable libkrun boot on macOS arm64 (Hypervisor.framework).
 *
 * Calls krun_create_ctx -> configures 1 vCPU / 256 MiB / virtio-fs rootfs ->
 * krun_start_enter, which transfers control into the guest where /bin/sh -c
 * "echo hello" runs and the process exits. We measure wall-clock time from
 * krun_create_ctx to just before krun_start_enter (config phase) and from
 * krun_start_enter return to wall-clock end (config+boot+guest exit).
 *
 * Inspired by upstream examples/chroot_vm.c (cited in findings).
 *
 * Build:  see Makefile in this directory.
 * Run:    ./hello <rootfs-dir>     (rootfs prepared by ./prepare-rootfs.sh)
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
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
    if (argc != 2) {
        fprintf(stderr, "usage: %s <rootfs-dir>\n", argv[0]);
        return 2;
    }
    const char *rootfs = argv[1];

    /* Bump RLIMIT_NOFILE — virtio-fs opens many fds. */
    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
        rlim.rlim_cur = rlim.rlim_max;
        (void)setrlimit(RLIMIT_NOFILE, &rlim);
    }

    /* Log to stderr at WARN so failures surface, but we don't drown in INFO. */
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

    /* The guest reads /proc/uptime (seconds since the guest kernel booted)
     * and prints it alongside "hello". Combined with the host-side timestamp
     * we recorded just before krun_start_enter, the uptime value bounds the
     * cold-boot time we care about: how long between "host asks libkrun to
     * boot" and "first userspace instruction inside the guest". */* libkrun's init does execv(exec_path, [exec_path] + argv) — so argv here
     * is "args after the program name". For `sh -c CMD` we therefore pass
     * argv = {"-c", CMD, NULL}. Reading /proc/uptime gives seconds since the
     * guest kernel booted; we print it alongside "hello" so we can bound the
     * cold boot wall time without holding a return from krun_start_enter. */
    const char *const argv_guest[] = {
        "-c",
        "read U _ < /proc/uptime; echo hello uptime=$U",
        NULL
    };
    const char *const envp_guest[] = { "PATH=/bin:/sbin:/usr/bin:/usr/sbin", NULL };
    if ((rc = krun_set_exec(ctx, "/bin/sh", argv_guest, envp_guest))) {
        errno = -rc;
        perror("krun_set_exec");
        return 1;
    }

    double t_ctx_done = monotonic_ms;
    fprintf(stderr, "[spike] krun_create_ctx + config: %.2f ms\n",
            t_ctx_done - t_ctx_start);
    fflush(stderr);

    /* krun_start_enter consumes the process: on success it calls exit with
     * the guest workload's exit code and does NOT return. So we cannot
     * measure boot time from after the call. Instead the guest itself prints
     * /proc/uptime alongside "hello"; combined with the host timestamp logged
     * here, the uptime upper-bounds the cold boot time (krun_start_enter ->
     * first guest userspace instruction). */
    fprintf(stderr, "[spike] entering guest at host_t=%.2f ms (krun_start_enter does not return)\n",
            monotonic_ms - t_ctx_start);
    fflush(stderr);

    rc = krun_start_enter(ctx);

    /* Only reached if krun_start_enter fails before booting. */
    errno = -rc;
    perror("krun_start_enter");
    return 1;
}
