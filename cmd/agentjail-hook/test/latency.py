#!/usr/bin/env python3
"""End-to-end hook regression gate. See ADR 0002-latency-as-engineering-metric."""

import argparse
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
        valid = result.returncode == 0 and json.loads(result.stdout).get(
            "hookSpecificOutput", {}).get("permissionDecision") == expected
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
    return int(failed)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"Latency gate failed: {exc}", file=sys.stderr)
        sys.exit(1)
