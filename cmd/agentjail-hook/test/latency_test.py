#!/usr/bin/env python3
"""Deterministic checks for the latency gate's failure paths."""
import contextlib
import io
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

import latency


class LatencyGateTests(unittest.TestCase):
    def test_ci_rejects_weakened_budget_or_sampling(self):
        for override in ({"AGENTJAIL_SMOKE_P95_MS": "100"},
                         {"AGENTJAIL_SMOKE_SAMPLES": "20"}):
            with self.subTest(override=override), patch.dict(os.environ, {"CI": "true", **override}, clear=True):
                with self.assertRaises(ValueError):
                    latency.configuration()

    def test_invalid_budget_is_not_a_bypass(self):
        for value in ("nan", "inf", "0", "-1", "disabled"):
            with self.subTest(value=value), patch.dict(os.environ, {"AGENTJAIL_SMOKE_P95_MS": value}, clear=True):
                with self.assertRaises(ValueError):
                    latency.configuration()

    def test_local_budget_override(self):
        with patch.dict(os.environ, {"AGENTJAIL_SMOKE_P95_MS": "100"}, clear=True):
            self.assertEqual(latency.configuration(), (100, 50))

    def test_missing_decision_is_not_a_fast_pass(self):
        result = subprocess.CompletedProcess([], 0, b"{}", b"")
        with patch.object(latency.subprocess, "run", return_value=result):
            with self.assertRaises(ValueError):
                latency.measure("hook", "socket", {}, "allow")

    def test_unexpected_notice_is_not_a_sample(self):
        result = subprocess.CompletedProcess([], 0, stdout=b'{"hookSpecificOutput":{"permissionDecision":"allow"},"systemMessage":"degraded"}', stderr=b"")
        with patch.object(latency.subprocess, "run", return_value=result):
            with self.assertRaises(ValueError):
                latency.measure("hook", "socket", {}, "allow")

    def test_slow_warm_requests_fail_the_gate(self):
        with patch.object(latency, "measure", return_value=60), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, "exceeds the 50ms budget"):
                latency.run_diagnostics("hook", "socket", "/project")

    def test_diagnostic_fail_open_fails_the_run(self):
        with patch.object(latency, "measure", side_effect=ValueError("missing decision")):
            with self.assertRaises(ValueError):
                latency.run_diagnostics("hook", "socket", "/project")

    def test_deny_requires_exit_and_reason(self):
        for code, reason in ((0, b"denied"), (2, b"")):
            result = subprocess.CompletedProcess([], code, b"", reason)
            with patch.object(latency.subprocess, "run", return_value=result):
                with self.assertRaises(ValueError):
                    latency.measure("hook", "socket", {}, "deny")

    def test_p95_tail_failure_reaches_exit_status(self):
        args = ["latency.py", "--hook", "unused", "--socket", "unused", "--cwd", "/tmp"]
        for tail, expected in ((49, 0), (50, 1)):
            # Five warmups then 50 samples; three slow samples define nearest-rank p95.
            values = ([1] * 5 + [1] * 47 + [tail] * 3) * 8
            with patch.object(sys, "argv", args), patch.dict(os.environ, {}, clear=True), \
                 patch.object(latency, "measure", side_effect=values), \
                 patch.object(latency, "run_diagnostics"), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(latency.main(), expected)


if __name__ == "__main__":
    unittest.main()
