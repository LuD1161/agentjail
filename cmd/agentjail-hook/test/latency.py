#!/usr/bin/env python3
"""End-to-end hook regression gate. See ADR 0002-latency-as-engineering-metric."""

import argparse
import concurrent.futures
import json
import math
import os
import statistics
import subprocess
import sys
import time


def configuration():
    budget = float(os.environ.get("AGENTJAIL_SMOKE_P95_MS", "50"))
    samples = int(os.environ.get("AGENTJAIL_SMOKE_SAMPLES", "50"))
    if not math.isfinite(budget) or budget <= 0 or samples < 20:
        raise ValueError("p95 budget must be finite and positive; samples must be >= 20")
    ci = any(os.environ.get(key, "").lower() not in ("", "false", "0")
             for key in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "CIRCLECI"))
    if ci and (budget != 50 or samples < 50):
        raise ValueError("CI requires the 50ms p95 budget and at least 50 samples")
    return budget, samples


def measure(hook, socket, payload, expected):
    encoded = json.dumps(payload).encode()
    env = dict(os.environ, AGENTJAIL_SOCKET=socket)
    start = time.perf_counter_ns()
    result = subprocess.run([hook], input=encoded, capture_output=True, env=env, timeout=5)
    elapsed = (time.perf_counter_ns() - start) / 1_000_000
    if expected == "deny":
        valid = result.returncode == 2 and bool(result.stderr.strip())
    else:
        response = json.loads(result.stdout)
        valid = (result.returncode == 0 and
                 response.get("hookSpecificOutput", {}).get("permissionDecision") == expected and
                 not response.get("systemMessage"))
    if not valid:
        raise ValueError(f"expected {expected}, got exit {result.returncode}: "
                         f"{result.stdout!r} {result.stderr!r}")
    return elapsed


def payload(case, cwd, key):
    tool, tool_input = {
        "file-allow": ("Write", {"file_path": f"{cwd}/latency-{key}.txt", "content": "fixture"}),
        "file-deny": ("Read", {"file_path": f"/etc/agentjail-latency-{key}"}),
        "shell-ask": ("Bash", {"command": f"npm publish --tag latency-{key}"}),
        "mcp-deny": ("mcp__stripe__charge", {"fixture": key}),
    }[case]
    return {"hook_event_name": "PreToolUse", "tool_name": tool,
            "tool_input": tool_input, "session_id": "latency", "cwd": cwd}


def run_diagnostics(hook, socket, cwd, budget=50):
    samples = 100
    for name, body_size, workers, vary_path in (
        ("warm-small", 5, 1, False),
        ("uncached-small", 5, 1, True),
        ("warm-512KiB", 512 * 1024, 1, False),
        ("concurrent-small", 5, 4, False),
    ):
        def diagnostic_payload(index):
            key = index if vary_path else 0
            return {
                "hook_event_name": "PreToolUse", "tool_name": "Write",
                "tool_input": {"file_path": os.path.join(cwd, f"bench-{name}-{key}.txt"),
                               "content": "x" * body_size},
                "session_id": "latency-bench", "cwd": cwd,
            }

        for index in range(-10, 0):
            measure(hook, socket, diagnostic_payload(index), "allow")
        inputs = [diagnostic_payload(index) for index in range(samples)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            timings = sorted(pool.map(lambda data: measure(hook, socket, data, "allow"), inputs))
        p95 = timings[math.ceil(samples * 0.95) - 1]
        print(f"  {name}: n={samples}, median={statistics.median(timings):.2f}ms, "
              f"p95={p95:.2f}ms, max={max(timings):.2f}ms", flush=True)
        if name == "warm-small" and p95 >= budget:
            raise ValueError(f"warm hook p95 {p95:.2f}ms exceeds the {budget:g}ms budget")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hook", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--cwd", required=True)
    args = parser.parse_args()
    budget, samples = configuration()
    print(f"Latency gate: p95 < {budget:g}ms, {samples} samples per case/mode", flush=True)
    failed = False
    cases = (("file-allow", "allow"), ("file-deny", "deny"),
             ("shell-ask", "ask"), ("mcp-deny", "deny"))
    for case, expected in cases:
        for mode in ("repeated", "unique"):
            for i in range(5):
                key = "repeated" if mode == "repeated" else f"warmup-{i}"
                measure(args.hook, args.socket, payload(case, args.cwd, key), expected)
            timings = []
            for i in range(samples):
                key = "repeated" if mode == "repeated" else f"unique-{i}"
                timings.append(measure(args.hook, args.socket,
                                       payload(case, args.cwd, key), expected))
            p95 = sorted(timings)[math.ceil(len(timings) * 0.95) - 1]
            passed = p95 < budget
            failed |= not passed
            print(f"  {case}/{mode}: median={statistics.median(timings):.2f}ms "
                  f"p95={p95:.2f}ms max={max(timings):.2f}ms "
                  f"{'PASS' if passed else 'FAIL'}", flush=True)
    run_diagnostics(args.hook, args.socket, args.cwd, budget)
    return int(failed)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"Latency gate failed: {exc}", file=sys.stderr)
        sys.exit(1)
