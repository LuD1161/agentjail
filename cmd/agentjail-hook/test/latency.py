#!/usr/bin/env python3
"""Measure real hook processes using one monotonic clock; never time fail-open."""

import concurrent.futures
import json
import math
import os
import statistics
import subprocess
import sys
import time


def measure(hook, env, payload):
    started = time.perf_counter_ns()
    result = subprocess.run(
        [hook], input=payload, capture_output=True, env=env, timeout=5
    )
    elapsed = (time.perf_counter_ns() - started) / 1_000_000
    if result.returncode != 0:
        raise RuntimeError(f"hook exited {result.returncode}")
    response = json.loads(result.stdout)
    if response.get("hookSpecificOutput", {}).get("permissionDecision") != "allow":
        raise RuntimeError("missing explicit allow: a fail-open is not a latency sample")
    if response.get("systemMessage"):
        raise RuntimeError("unexpected hook notice in latency sample")
    return elapsed


def run(hook, socket, cwd):
    env = {**os.environ, "AGENTJAIL_SOCKET": socket}
    samples = 100
    for name, body_size, workers, vary_path in [
        ("warm-small", 5, 1, False),
        ("uncached-small", 5, 1, True),
        ("warm-512KiB", 512 * 1024, 1, False),
        ("concurrent-small", 5, 4, False),
    ]:
        def payload(index):
            return json.dumps({
                "hook_event_name": "PreToolUse",
                "tool_name": "Write",
                "tool_input": {
                    "file_path": os.path.join(cwd, f"bench-{name}-{index if vary_path else 0}.txt"),
                    "content": "x" * body_size,
                },
                "session_id": "latency-bench",
                "cwd": cwd,
            }).encode()

        for index in range(-10, 0):
            measure(hook, env, payload(index))
        inputs = [payload(index) for index in range(samples)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            timings = sorted(pool.map(lambda data: measure(hook, env, data), inputs))
        p95 = timings[math.ceil(samples * 0.95) - 1]
        print(f"  {name}: n={samples}, median={statistics.median(timings):.2f}ms, "
              f"p95={p95:.2f}ms, max={max(timings):.2f}ms", flush=True)
        # ADR 0002 gates the warm, serial end-to-end hook budget.
        if name == "warm-small" and p95 >= 50:
            raise RuntimeError(f"warm hook p95 {p95:.2f}ms exceeds the 50ms budget")


if __name__ == "__main__":
    try:
        run(*sys.argv[1:])
    except (RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"latency benchmark failed: {exc}", file=sys.stderr)
        sys.exit(1)
