import contextlib
import io
import subprocess
import unittest
from unittest.mock import patch

import latency


class LatencyGateTest(unittest.TestCase):
    def test_slow_warm_requests_fail_the_gate(self):
        with patch.object(latency, "measure", return_value=60), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "exceeds the 50ms budget"):
                latency.run("hook", "socket", "/project")

    def test_fast_fail_open_is_not_a_sample(self):
        result = subprocess.CompletedProcess([], 0, stdout=b"{}", stderr=b"")
        with patch.object(subprocess, "run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "missing explicit allow"):
                latency.measure("hook", {}, b"{}")

    def test_unexpected_notice_is_not_a_sample(self):
        result = subprocess.CompletedProcess([], 0, stdout=b'{"hookSpecificOutput":{"permissionDecision":"allow"},"systemMessage":"degraded"}', stderr=b"")
        with patch.object(subprocess, "run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "unexpected hook notice"):
                latency.measure("hook", {}, b"{}")


if __name__ == "__main__":
    unittest.main()
