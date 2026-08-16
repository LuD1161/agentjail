#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("evidence-manifest.py")


class EvidenceManifestTest(unittest.TestCase):
    def test_binds_uncommitted_source_and_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            evidence = root / "evidence"
            repo.mkdir()
            evidence.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "tracked.txt").write_text("tracked\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
            subprocess.run(
                [
                    "git", "-C", str(repo), "-c", "user.name=Test", "-c",
                    "user.email=test@example.invalid", "commit", "-qm", "base",
                ],
                check=True,
            )
            (repo / "untracked.txt").write_text("working tree\n", encoding="utf-8")
            (evidence / "raw.txt").write_text("proof\n", encoding="utf-8")
            (evidence / "independent-review-prompt.md").write_text(
                "Review the evidence without assuming the claims are true.\n",
                encoding="utf-8",
            )

            subprocess.run(
                [
                    sys.executable, str(SCRIPT), "--evidence-dir", str(evidence),
                    "--worktree", str(repo), "--driver", "tart", "--guest", "gate",
                    "--scenario", "tunnel-agent",
                ],
                check=True,
            )
            manifest = json.loads((evidence / "run-manifest.json").read_text())
            source_paths = {item["path"] for item in manifest["source"]["files"]}
            evidence_paths = {item["path"] for item in manifest["evidence_files"]}
            self.assertEqual({"tracked.txt", "untracked.txt"}, source_paths)
            self.assertEqual({"independent-review-prompt.md", "raw.txt"}, evidence_paths)
            self.assertEqual(["tunnel-agent"], manifest["scenarios"])
            self.assertEqual("independent-review-prompt.md", manifest["review_prompt"])
            self.assertTrue((evidence / "SHA256SUMS").read_text().endswith("  run-manifest.json\n"))


if __name__ == "__main__":
    unittest.main()
