#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("scan-secret-artifacts.py")


class SecretArtifactScanTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.auth = self.root / "auth.json"
        self.output = self.root / "result.json"
        self.token = "auth-scan-token-value-20260815"
        self.auth.write_text(json.dumps({"tokens": {"access_token": self.token}}), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def run_scan(self):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--secret-file", str(self.auth), "--output", str(self.output), "--exclude", str(self.auth), str(self.root)],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_passes_with_positive_control_and_no_retained_secret(self):
        (self.root / "safe.log").write_text("no credential here\n", encoding="utf-8")
        completed = self.run_scan()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(result["status"], "pass")
        self.assertGreater(result["positive_control_hits"], 0)
        self.assertEqual(result["matches"], [])
        self.assertNotIn(self.token, self.output.read_text(encoding="utf-8"))

    def test_fails_and_reports_only_fingerprint_for_retained_secret(self):
        (self.root / "leak.log").write_text(self.token, encoding="utf-8")
        completed = self.run_scan()
        self.assertNotEqual(completed.returncode, 0)
        result_text = self.output.read_text(encoding="utf-8")
        result = json.loads(result_text)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(len(result["matches"]), 1)
        self.assertNotIn(self.token, result_text)

    def test_inventories_noncredential_strings_without_treating_identity_as_secret(self):
        account_value = "account-identifier-20260815"
        self.auth.write_text(json.dumps({
            "tokens": {"access_token": self.token},
            "account": {"id": account_value},
        }), encoding="utf-8")
        (self.root / "leak.log").write_text(account_value, encoding="utf-8")
        completed = self.run_scan()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result_text = self.output.read_text(encoding="utf-8")
        result = json.loads(result_text)
        self.assertEqual(result["schema_version"], 3)
        self.assertEqual(result["credential_string_count"], 1)
        self.assertEqual(result["credential_key_paths"], ["tokens.access_token"])
        self.assertEqual(result["noncredential_long_string_paths"], ["account.id"])
        self.assertNotIn(account_value, result_text)


if __name__ == "__main__":
    unittest.main()
