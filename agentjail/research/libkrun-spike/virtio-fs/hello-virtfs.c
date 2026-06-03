/*
 * agentjail libkrun spike 
 *
 * Mounts a host directory inside the guest via virtio-fs and exercises
 * read+write from the guest side, plus negative-scope isolation:
 *   1. host pre-creates from-host.txt inside the shared workdir
 *   2. guest mounts the workdir under /work
 *   3. guest reads /work/from-host.txt and prints its contents
 *   4. guest writes /work/from-guest.txt
 *   5. guest attempts to read a path that exists on the host but is
 *      NOT shared (/opt/homebrew); expected: ENOENT
 *   6. host (caller of `make verify`) checks /work/from-guest.txt now
 *      exists on the host with the expected payload
 *
 * Calls krun_create_ctx -> 1 vCPU / 256 MiB / virtio-fs rootfs +
 * krun_add_virtiofs(ctx, "agentwork", workdir) -> krun_set_exec.
 *
 * Sibling of ../hello.c  and ../kernel/hello-custom-kernel.c
 * ; does not modify either.
 *
 * Inspired by upstream libkrun virtio-fs API documented in
 * /opt/homebrew/opt/libkrun/include/libkrun.h:303-315.
 *
 * Build:  see Makefile in this directory.
 * Run:    ./hello-virtfs <rootfs-dir> <host-workdir>
 *
 * The host-workdir is mounted in the guest at /work with tag "agentwork".
 * Reads + writes inside /work land on the host workdir; nothing outside
 * is visible. This is the convention codified in
 * agentjail/docs/DECISIONS.md (entry ): one RW project mount per
 * agentjail microVM, tagged "agentwork", at guest path /work.
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

#define WORK_TAG "agentwork"
#define GUEST_MOUNT "/work"

static double monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

int main(int argc, char *const argv[])
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <rootfs-dir> <host-workdir>\n", argv[0]);
        return 2;
    }
    const char *rootfs = argv[1];
    const char *workdir = argv[2];

    /* Fail fast with a clear error if the workdir does not exist on the
     * host. libkrun's failure mode for a missing virtio-fs path is an
     * opaque VmCreate error at krun_start_enter; better to surface it as
     * a normal stat error here.  */
    struct stat st;
    if (stat(workdir, &st) != 0) {
        fprintf(stderr, "stat(%s): %s\n", workdir, strerror(errno));
        return 1;
    }
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "%s: not a directory\n", workdir);
        return 1;
    }

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

    /* The crux of : add a second, independent virtio-fs device
     * exposing the host workdir to the guest. The guest will see it as a
     * filesystem with tag WORK_TAG that can be mounted at any guest path.
     * libkrun spins up an in-process virtiofsd thread for each device. */
    if ((rc = krun_add_virtiofs(ctx, WORK_TAG, workdir))) {
        errno = -rc;
        perror("krun_add_virtiofs(agentwork)");
        return 1;
    }

    if ((rc = krun_set_workdir(ctx, "/"))) {
        errno = -rc;
        perror("krun_set_workdir");
        return 1;
    }

    /* Guest workload (single shell line; chained with ; so the exit code
     * of the whole script is the exit code of the last command; we never
     * check it on the host since krun_start_enter does not return on
     * success — the host runs the round-trip verification via stat on
     * the workdir after the process exits):
     *
     *   mkdir -p /work; mount -t virtiofs agentwork /work
     *   read U _ < /proc/uptime; echo hello uptime=$U
     *   cat /work/from-host.txt              # RW: read
     *   echo "from guest pid=$$ uptime=$U" > /work/from-guest.txt   # RW: write
     *   cat /opt/homebrew/Cellar 2>&1 \      # isolation: must fail
     *     | head -1
     *   echo "isolation_exit=$?"
     *
     * The host inspects stdout for "hello uptime=", "from-host-payload=",
     * and "isolation_exit=2" (busybox cat returns 1 on ENOENT; we trap
     * via pipefail-style — but busybox sh has no pipefail, so we check
     * the printed isolation_exit which is the exit of `head -1` reading
     * cat's piped stderr-then-stdout — see verify.sh for the actual
     * assertion logic).
     *
     * To keep the assertion robust on busybox we use a small shell
     * function that returns the exit code of the cat directly.
     */
    const char *const argv_guest[] = {
        "-c",
        "set +e; "
        "mkdir -p " GUEST_MOUNT "; "
        "mount -t virtiofs " WORK_TAG " " GUEST_MOUNT " "
        "  || { echo MOUNT_FAILED=$?; exit 1; }; "
        "read U _ < /proc/uptime; "
        "echo hello uptime=$U; "
        "echo from-host-payload=$(cat " GUEST_MOUNT "/from-host.txt 2>/dev/null); "
        "echo from guest uptime=$U > " GUEST_MOUNT "/from-guest.txt "
        "  && echo guest_write=ok || echo guest_write=fail; "
        "cat /opt/homebrew/Cellar >/dev/null 2>&1; echo isolation_exit=$?; "
        "ls /opt/homebrew >/dev/null 2>&1; echo isolation_ls_exit=$?; ",
        NULL
    };
    const char *const envp_guest[] = { "PATH=/bin:/sbin:/usr/bin:/usr/sbin", NULL };
    if ((rc = krun_set_exec(ctx, "/bin/sh", argv_guest, envp_guest))) {
        errno = -rc;
        perror("krun_set_exec");
        return 1;
    }

    double t_ctx_done = monotonic_ms;
    fprintf(stderr, "[spike] virtio-fs tag=%s -> host:%s mounted at guest:%s\n",
            WORK_TAG, workdir, GUEST_MOUNT);
    fprintf(stderr, "[spike] krun_create_ctx + config: %.2f ms\n",
            t_ctx_done - t_ctx_start);
    fflush(stderr);

    fprintf(stderr, "[spike] entering guest at host_t=%.2f ms\n",
            monotonic_ms - t_ctx_start);
    fflush(stderr);

    rc = krun_start_enter(ctx);

    /* Only reached if krun_start_enter fails before booting. */
    errno = -rc;
    perror("krun_start_enter");
    return 1;
}
