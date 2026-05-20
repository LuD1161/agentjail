// agentjail PATH shim.
// Hard-linked under each tool name (rm, git, npm, sh, ...). Behavior:
//   1. Read $AGENTJAIL_SOCK, $AGENTJAIL_SESSION_ID, $AGENTJAIL_SHIM_DIR.
//   2. Resolve the *real* binary by walking $PATH and skipping our shim dir.
//   3. Best-effort fire-and-forget an exec event to the daemon over Unix socket.
//   4. If $AGENTJAIL_ENFORCE=1 is set, also send a `req_id` on the frame, read
//      back the JSON-line sync verdict, and block (exit 126) on `deny`/`ask`.
//      Fail-closed: any socket/connect/read/timeout error -> block.
//   5. execv the real binary with original argv, preserving stdin/stdout/stderr.
//
// No allocations on the hot path beyond what's needed. ~3ms overhead per spawn
// in audit mode; ~5-10ms in enforce mode (one socket round-trip).

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <stdlib.h> // arc4random
#endif

#if defined(__APPLE__)
#include <mach-o/dyld.h>  // _NSGetExecutablePath
#include <sys/wait.h>     // waitpid for fork+exec of /usr/bin/codesign
#include <spawn.h>        // posix_spawn for the verify shellout
extern char **environ;
#endif

// Total budget for the sync RPC. The daemon side enforces a 50ms write
// deadline and LRU-hit eval is sub-ms, so 150ms is generous head-room.
#define SYNC_TIMEOUT_MS 150

// Optional inherited limits. Defaults are off to preserve today's behavior:
// unset/0 = no extra RLIMIT_NPROC cap and no wall-clock alarm.
#define DEFAULT_RLIMIT_NPROC 0ULL
#define DEFAULT_WALLCLOCK_SECS 0U

// Enforcement verdict from do_emit_and_maybe_wait().
typedef enum {
    EV_AUDIT_ONLY = 0, // not in enforce mode, fall through
    EV_ALLOW      = 1, // enforce mode + daemon said allow
    EV_DENY       = 2, // enforce mode + daemon said deny (or ask)
    EV_FAIL       = 3, // enforce mode + socket/parse error (fail-closed)
} enforce_verdict_t;

static const char *getenv_or(const char *k, const char *fallback) {
    const char *v = getenv(k);
    return (v && *v) ? v : fallback;
}

static int env_truthy(const char *k) {
    const char *v = getenv(k);
    if (!v || !*v) return 0;
    return (v[0] == '1' || v[0] == 't' || v[0] == 'T' || v[0] == 'y' || v[0] == 'Y');
}

static int parse_env_u64(const char *key, unsigned long long fallback, unsigned long long *out) {
    const char *v = getenv(key);
    char *end = NULL;
    unsigned long long parsed = 0;

    if (!out) return -1;
    if (!v || !*v) {
        *out = fallback;
        return 0;
    }
    errno = 0;
    parsed = strtoull(v, &end, 10);
    if (errno != 0 || !end || *end != '\0') return -1;
    *out = parsed;
    return 0;
}

static int apply_exec_limits(void) {
    unsigned long long nproc = DEFAULT_RLIMIT_NPROC;
    unsigned long long wallclock = DEFAULT_WALLCLOCK_SECS;

    if (parse_env_u64("AGENTJAIL_SHIM_RLIMIT_NPROC", DEFAULT_RLIMIT_NPROC, &nproc) != 0) {
        fprintf(stderr,
                "agentjail shim: invalid AGENTJAIL_SHIM_RLIMIT_NPROC=%s\n",
                getenv("AGENTJAIL_SHIM_RLIMIT_NPROC"));
        return -1;
    }
    if (parse_env_u64("AGENTJAIL_SHIM_WALLCLOCK_SECS", DEFAULT_WALLCLOCK_SECS, &wallclock) != 0) {
        fprintf(stderr,
                "agentjail shim: invalid AGENTJAIL_SHIM_WALLCLOCK_SECS=%s\n",
                getenv("AGENTJAIL_SHIM_WALLCLOCK_SECS"));
        return -1;
    }

    if (nproc > 0) {
        struct rlimit lim;
        if (nproc > (unsigned long long)RLIM_INFINITY) {
            fprintf(stderr,
                    "agentjail shim: AGENTJAIL_SHIM_RLIMIT_NPROC too large: %llu\n",
                    nproc);
            return -1;
        }
        lim.rlim_cur = (rlim_t)nproc;
        lim.rlim_max = (rlim_t)nproc;
        if (setrlimit(RLIMIT_NPROC, &lim) != 0) {
            fprintf(stderr, "agentjail shim: setrlimit RLIMIT_NPROC=%llu: %s\n",
                    nproc, strerror(errno));
            return -1;
        }
    }

    if (wallclock > 0) {
        if (wallclock > (unsigned long long)UINT_MAX) {
            fprintf(stderr,
                    "agentjail shim: AGENTJAIL_SHIM_WALLCLOCK_SECS too large: %llu\n",
                    wallclock);
            return -1;
        }
        alarm((unsigned int)wallclock);
    }
    return 0;
}

static int starts_with(const char *s, const char *prefix) {
    while (*prefix) {
        if (*s++ != *prefix++) return 0;
    }
    return 1;
}

// Resolve `tool` against $PATH, skipping any path == shim_dir.
// Writes the resolved absolute path to `out` (size out_sz). Returns 0 on success.
static int resolve_real(const char *tool, const char *shim_dir, char *out, size_t out_sz) {
    const char *path = getenv("PATH");
    if (!path) path = "/usr/bin:/bin:/usr/sbin:/sbin";

    char buf[8192];
    strncpy(buf, path, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *saveptr = NULL;
    for (char *dir = strtok_r(buf, ":", &saveptr); dir; dir = strtok_r(NULL, ":", &saveptr)) {
        if (shim_dir && *shim_dir && strcmp(dir, shim_dir) == 0) continue;
        char candidate[4096];
        int n = snprintf(candidate, sizeof(candidate), "%s/%s", dir, tool);
        if (n <= 0 || (size_t)n >= sizeof(candidate)) continue;
        if (access(candidate, X_OK) == 0) {
            struct stat st;
            if (stat(candidate, &st) != 0) continue;
            // Safety: refuse if it resolves back into a shim dir entry (broken install).
            // We don't follow symlinks here; broken setups produce ENOENT later, not a loop.
            if (strlen(candidate) >= out_sz) return -1;
            strcpy(out, candidate);
            return 0;
        }
    }
    return -1;
}

// JSON-escape: append byte to buf, expanding control chars and quotes.
static void json_escape(char *dst, size_t dst_sz, size_t *off, const char *src) {
    for (; *src; ++src) {
        unsigned char c = (unsigned char)*src;
        const char *esc = NULL;
        char unicode[8];
        switch (c) {
            case '"':  esc = "\\\""; break;
            case '\\': esc = "\\\\"; break;
            case '\n': esc = "\\n";  break;
            case '\r': esc = "\\r";  break;
            case '\t': esc = "\\t";  break;
            default:
                if (c < 0x20) { snprintf(unicode, sizeof(unicode), "\\u%04x", c); esc = unicode; }
        }
        if (esc) {
            size_t l = strlen(esc);
            if (*off + l + 1 >= dst_sz) return;
            memcpy(dst + *off, esc, l);
            *off += l;
        } else {
            if (*off + 2 >= dst_sz) return;
            dst[(*off)++] = (char)c;
        }
    }
}

// Generate a short random hex req_id (16 hex chars = 64 bits of entropy).
// Uses arc4random on macOS/BSD; falls back to /dev/urandom elsewhere.
static void gen_req_id(char *out, size_t out_sz) {
    if (out_sz < 17) { if (out_sz) out[0] = '\0'; return; }
#if defined(__APPLE__) || defined(__FreeBSD__)
    uint32_t a = arc4random();
    uint32_t b = arc4random();
    snprintf(out, out_sz, "%08x%08x", a, b);
#else
    unsigned char raw[8] = {0};
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t r = read(fd, raw, sizeof(raw));
        (void)r;
        close(fd);
    } else {
        for (size_t i = 0; i < sizeof(raw); i++) raw[i] = (unsigned char)(rand() & 0xff);
    }
    for (int i = 0; i < 8; i++) snprintf(out + i*2, out_sz - i*2, "%02x", raw[i]);
#endif
}

// Tiny JSON scanner: find the string value of key `"action"` in `line`.
// Writes up to out_sz-1 bytes to `out` and NUL-terminates. Returns 0 on
// success, -1 on malformed input. Does NOT handle escape sequences inside
// the value (the daemon only emits allow/deny/ask, no escapes needed).
static int parse_string_field(const char *line, const char *key, char *out, size_t out_sz) {
    if (!line || !key || !out || out_sz == 0) return -1;
    char needle[64];
    int n = snprintf(needle, sizeof(needle), "\"%s\"", key);
    if (n <= 0 || (size_t)n >= sizeof(needle)) return -1;
    const char *p = strstr(line, needle);
    if (!p) return -1;
    p += n; // past the key
    // skip whitespace + colon + whitespace
    while (*p == ' ' || *p == '\t') p++;
    if (*p != ':') return -1;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < out_sz) {
        // crude: if we see a backslash, copy next char verbatim. Good enough
        // for action/rule_id/reason which never contain quotes in practice.
        if (*p == '\\' && *(p + 1)) {
            out[i++] = *(p + 1);
            p += 2;
        } else {
            out[i++] = *p++;
        }
    }
    out[i] = '\0';
    if (*p != '"') return -1;
    return 0;
}

// Emit the exec frame and, if req_id is non-NULL/non-empty, also wait for the
// sync response and write the parsed action/rule_id/reason into the out params.
// Returns:
//   0  on success (response parsed or fire-and-forget OK)
//  -1  on any failure when req_id is set (fail-closed for caller)
//  -1  on connect failure when req_id is NULL is treated as 0 (audit best-effort)
static int emit_event(int argc, char **argv, const char *real_path,
                      const char *req_id,
                      char *action_out, size_t action_sz,
                      char *rule_out, size_t rule_sz,
                      char *reason_out, size_t reason_sz) {
    const char *sock = getenv("AGENTJAIL_SOCK");
    const char *sid  = getenv("AGENTJAIL_SESSION_ID");
    if (!sock || !*sock || !sid || !*sid) {
        // No daemon configured: audit best-effort succeeds, but a sync caller
        // must fail-closed.
        return req_id && *req_id ? -1 : 0;
    }

    char cwd[4096] = {0};
    (void)getcwd(cwd, sizeof(cwd));

    char buf[16384];
    size_t off = 0;
    off += snprintf(buf + off, sizeof(buf) - off,
                    "{\"hook\":\"exec\",\"op\":\"shim\",\"track\":\"native\",\"pid\":%d,\"ppid\":%d",
                    (int)getpid(), (int)getppid());
    if (req_id && *req_id) {
        off += snprintf(buf + off, sizeof(buf) - off, ",\"req_id\":\"");
        json_escape(buf, sizeof(buf), &off, req_id);
        off += snprintf(buf + off, sizeof(buf) - off, "\"");
    }
    off += snprintf(buf + off, sizeof(buf) - off, ",\"attrs\":{\"program\":\"");
    json_escape(buf, sizeof(buf), &off, argv[0] ? argv[0] : "");
    off += snprintf(buf + off, sizeof(buf) - off, "\",\"real_program\":\"");
    json_escape(buf, sizeof(buf), &off, real_path ? real_path : "");
    off += snprintf(buf + off, sizeof(buf) - off, "\",\"cwd\":\"");
    json_escape(buf, sizeof(buf), &off, cwd);
    off += snprintf(buf + off, sizeof(buf) - off, "\",\"argv\":[");
    for (int i = 0; i < argc; ++i) {
        if (i) {
            if (off + 1 >= sizeof(buf)) return req_id && *req_id ? -1 : 0;
            buf[off++] = ',';
        }
        if (off + 1 >= sizeof(buf)) return req_id && *req_id ? -1 : 0;
        buf[off++] = '"';
        json_escape(buf, sizeof(buf), &off, argv[i] ? argv[i] : "");
        if (off + 1 >= sizeof(buf)) return req_id && *req_id ? -1 : 0;
        buf[off++] = '"';
    }
    if (off + 4 >= sizeof(buf)) return req_id && *req_id ? -1 : 0;
    buf[off++] = ']';
    buf[off++] = '}';
    buf[off++] = '}';
    buf[off++] = '\n';

    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return req_id && *req_id ? -1 : 0;

    // Conservative socket timeouts so a wedged daemon cannot stall a tool.
    // Same SYNC_TIMEOUT_MS for send + recv; both directions get a fresh budget.
    struct timeval tv;
    tv.tv_sec  = SYNC_TIMEOUT_MS / 1000;
    tv.tv_usec = (SYNC_TIMEOUT_MS % 1000) * 1000;
    (void)setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    (void)setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, sock, sizeof(sa.sun_path) - 1);
    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(s);
        return req_id && *req_id ? -1 : 0;
    }
    // Best-effort write; ignore short writes in audit mode.
    ssize_t w = 0;
    while ((size_t)w < off) {
        ssize_t n = write(s, buf + w, off - w);
        if (n <= 0) { close(s); return req_id && *req_id ? -1 : 0; }
        w += n;
    }

    if (!(req_id && *req_id)) {
        close(s);
        return 0;
    }

    // Sync path: read exactly one JSON line back.
    char resp[2048];
    size_t rlen = 0;
    int got_newline = 0;
    while (rlen < sizeof(resp) - 1) {
        ssize_t n = read(s, resp + rlen, sizeof(resp) - 1 - rlen);
        if (n <= 0) break;
        rlen += (size_t)n;
        if (memchr(resp, '\n', rlen)) { got_newline = 1; break; }
    }
    close(s);
    if (!got_newline || rlen == 0) return -1;
    resp[rlen] = '\0';

    if (action_out && action_sz) action_out[0] = '\0';
    if (rule_out   && rule_sz)   rule_out[0]   = '\0';
    if (reason_out && reason_sz) reason_out[0] = '\0';

    if (parse_string_field(resp, "action", action_out, action_sz) != 0) return -1;
    (void)parse_string_field(resp, "rule_id", rule_out, rule_sz);
    (void)parse_string_field(resp, "reason", reason_out, reason_sz);

    // Sanity: the daemon should echo our req_id. We don't enforce match (one
    // connection = one in-flight request today) but a missing field is suspect.
    char echoed[64];
    if (parse_string_field(resp, "req_id", echoed, sizeof(echoed)) != 0) return -1;
    return 0;
}

// Self-verification: on macOS, shell out to /usr/bin/codesign --verify against
// our own executable path. This is the KISS spike — it avoids
// pulling Security.framework into the build for what is effectively a fork+exec
// gate. Three outcomes:
//   0  -> signed and valid, OR unsigned dev build, OR not macOS (allow)
//   -1 -> signed but tampered (refuse)
// We treat "unsigned" (codesign exit 1 with "code object is not signed at all"
// on stderr) as a dev-mode allow so this code does not break local `make build`
// workflows. A real production shim is *always* signed by `make codesign-adhoc`
// or `make codesign-release` and ad-hoc is enough for the linker-signed default;
// any binary that successfully launched `codesign --verify` once and then was
// rewritten in place will fail this check.
//
// Override with `AGENTJAIL_SHIM_VERIFY=0` for offline diagnosis only.
static int verify_self(void) {
#if !defined(__APPLE__)
    return 0; // Linux/BSD: no equivalent in scope for this spike
#else
    const char *off = getenv("AGENTJAIL_SHIM_VERIFY");
    if (off && (off[0] == '0' || off[0] == 'n' || off[0] == 'N')) return 0;

    char exe_path[4096];
    uint32_t sz = sizeof(exe_path);
    if (_NSGetExecutablePath(exe_path, &sz) != 0) {
        // Buffer too small. Refuse: an attacker should not be able to produce
        // an unreasonable path to make us skip the check.
        fprintf(stderr, "agentjail shim: verify_self: cannot resolve own path\n");
        return -1;
    }
    exe_path[sizeof(exe_path) - 1] = '\0';

    // Capture codesign's stderr so we can distinguish "unsigned" from "tampered".
    int err_pipe[2];
    if (pipe(err_pipe) != 0) {
        fprintf(stderr, "agentjail shim: verify_self: pipe: %s\n", strerror(errno));
        return -1;
    }

    posix_spawn_file_actions_t fa;
    if (posix_spawn_file_actions_init(&fa) != 0) {
        close(err_pipe[0]); close(err_pipe[1]);
        return -1;
    }
    // codesign stdout -> /dev/null; stderr -> our pipe
    (void)posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    (void)posix_spawn_file_actions_adddup2(&fa, err_pipe[1], STDERR_FILENO);
    (void)posix_spawn_file_actions_addclose(&fa, err_pipe[0]);
    (void)posix_spawn_file_actions_addclose(&fa, err_pipe[1]);

    char *const argv_cs[] = {
        (char *)"/usr/bin/codesign",
        (char *)"--verify",
        (char *)"--strict",
        exe_path,
        NULL,
    };

    pid_t pid = 0;
    int rc = posix_spawn(&pid, "/usr/bin/codesign", &fa, NULL, argv_cs, environ);
    posix_spawn_file_actions_destroy(&fa);
    close(err_pipe[1]);
    if (rc != 0) {
        close(err_pipe[0]);
        fprintf(stderr, "agentjail shim: verify_self: posix_spawn codesign: %s\n", strerror(rc));
        return -1; // fail-closed: if we cannot run codesign, do not run.
    }

    char err_buf[2048];
    size_t err_len = 0;
    for (;;) {
        ssize_t n = read(err_pipe[0], err_buf + err_len, sizeof(err_buf) - 1 - err_len);
        if (n <= 0) break;
        err_len += (size_t)n;
        if (err_len >= sizeof(err_buf) - 1) break;
    }
    err_buf[err_len] = '\0';
    close(err_pipe[0]);

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        fprintf(stderr, "agentjail shim: verify_self: waitpid: %s\n", strerror(errno));
        return -1;
    }
    int exited = WIFEXITED(status);
    int exit_code = exited ? WEXITSTATUS(status) : -1;

    if (exit_code == 0) {
        return 0; // valid signature
    }
    // codesign emits "code object is not signed at all" (or "...is not signed")
    // for an unsigned binary. Allow that single dev-mode shape; refuse anything
    // else (invalid signature, tampered, bad architecture, etc.).
    if (exit_code == 1 && strstr(err_buf, "not signed") != NULL) {
        return 0; // unsigned dev build
    }
    fprintf(stderr,
            "agentjail shim: refusing to run: codesign --verify failed (exit %d): %s",
            exit_code, err_buf[0] ? err_buf : "(no detail)\n");
    return -1;
#endif
}

int main(int argc, char **argv) {
    // Refuse to run if our own signature is invalid (tampered). This
    // happens before any other side effect so an attacker who rewrites the
    // shim cannot exfiltrate argv or env via our event emitter.
    if (verify_self() != 0) {
        return 126;
    }

    // argv[0] could be "/path/to/.agentjail/shims/git" or just "git" (basename via PATH).
    const char *invoked = argv[0] ? argv[0] : "";
    char tool_buf[256];
    {
        char tmp[1024];
        strncpy(tmp, invoked, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = '\0';
        const char *b = basename(tmp);
        strncpy(tool_buf, b, sizeof(tool_buf) - 1);
        tool_buf[sizeof(tool_buf) - 1] = '\0';
    }
    const char *tool = tool_buf;

    const char *shim_dir = getenv_or("AGENTJAIL_SHIM_DIR", "");
    char real_path[4096];
    if (resolve_real(tool, shim_dir, real_path, sizeof(real_path)) != 0) {
        fprintf(stderr, "agentjail shim: %s: cannot find real binary on PATH\n", tool);
        return 127;
    }
    // Recursion guard: if resolved path is inside our shim_dir, refuse.
    if (shim_dir && *shim_dir && starts_with(real_path, shim_dir)) {
        fprintf(stderr, "agentjail shim: %s: resolved into shim_dir (%s); refusing to exec\n",
                tool, real_path);
        return 127;
    }

    if (apply_exec_limits() != 0) {
        return 126;
    }

    int enforce = env_truthy("AGENTJAIL_ENFORCE");
    const char *sock = getenv("AGENTJAIL_SOCK");
    const char *sid  = getenv("AGENTJAIL_SESSION_ID");
    int daemon_configured = (sock && *sock && sid && *sid);

    if (enforce && daemon_configured) {
        // Enforce path: send req_id, await verdict, gate exec.
        char req_id[32];
        gen_req_id(req_id, sizeof(req_id));
        char action[32], rule[128], reason[256];
        action[0] = rule[0] = reason[0] = '\0';
        int rc = emit_event(argc, argv, real_path, req_id,
                            action, sizeof(action),
                            rule,   sizeof(rule),
                            reason, sizeof(reason));
        if (rc != 0) {
            fprintf(stderr, "agentjail: blocked: daemon unreachable (fail-closed)\n");
            return 126;
        }
        if (strcmp(action, "deny") == 0) {
            fprintf(stderr, "agentjail: blocked: %s: %s\n",
                    rule[0] ? rule : "(no rule_id)",
                    reason[0] ? reason : "(no reason)");
            return 126;
        }
        if (strcmp(action, "ask") == 0) {
            // ASK-mode TUI is not wired yet. Treat as deny so we never silently
            // allow an action that the policy wanted a human to confirm.
            fprintf(stderr,
                    "agentjail: blocked: %s: %s (ask-mode TUI not yet wired; treating as deny)\n",
                    rule[0] ? rule : "(no rule_id)",
                    reason[0] ? reason : "policy requested confirmation");
            return 126;
        }
        // action == "allow" or anything else benign -> fall through.
    } else {
        // Audit-only path: fire-and-forget, never gate.
        (void)emit_event(argc, argv, real_path, NULL, NULL, 0, NULL, 0, NULL, 0);
    }

    execv(real_path, argv);
    fprintf(stderr, "agentjail shim: execv %s: %s\n", real_path, strerror(errno));
    return 126;
}
