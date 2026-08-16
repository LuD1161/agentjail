#!/usr/bin/env python3
"""Bind raw testbed evidence to the exact source tree and collected artifacts."""

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git_output(worktree, *args):
    return subprocess.check_output(
        ["git", "-C", str(worktree), *args], stderr=subprocess.DEVNULL
    ).decode("utf-8", errors="strict").strip()


def source_manifest(worktree):
    raw = subprocess.check_output(
        ["git", "-C", str(worktree), "ls-files", "-co", "--exclude-standard", "-z"]
    )
    files = []
    for encoded in sorted(item for item in raw.split(b"\0") if item):
        relative = encoded.decode("utf-8", errors="strict")
        path = worktree / relative
        if not path.is_file() or path.is_symlink():
            continue
        files.append({
            "path": relative,
            "mode": oct(path.stat().st_mode & 0o777),
            "sha256": sha256(path),
        })
    tree_digest = hashlib.sha256(
        "".join(
            f"{item['mode']} {item['sha256']} {item['path']}\n" for item in files
        ).encode("utf-8")
    ).hexdigest()
    return files, tree_digest


def evidence_manifest(evidence_dir, output):
    files = []
    for path in sorted(evidence_dir.rglob("*")):
        if not path.is_file() or path.is_symlink() or path == output:
            continue
        relative = path.relative_to(evidence_dir).as_posix()
        if relative == "SHA256SUMS":
            continue
        files.append({
            "path": relative,
            "size": path.stat().st_size,
            "sha256": sha256(path),
        })
    return files


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--worktree", required=True)
    parser.add_argument("--driver", required=True)
    parser.add_argument("--guest", required=True)
    parser.add_argument("--scenario", action="append", default=[])
    args = parser.parse_args()

    evidence_dir = Path(args.evidence_dir).resolve()
    worktree = Path(args.worktree).resolve()
    output = evidence_dir / "run-manifest.json"
    review_prompt = evidence_dir / "independent-review-prompt.md"
    if not review_prompt.is_file():
        raise SystemExit("independent review prompt is missing")
    source_files, source_tree_sha256 = source_manifest(worktree)
    manifest = {
        "schema_version": 1,
        "driver": args.driver,
        "guest": args.guest,
        "scenarios": args.scenario,
        "review_prompt": review_prompt.name,
        "source": {
            "head": git_output(worktree, "rev-parse", "HEAD"),
            "branch": git_output(worktree, "branch", "--show-current"),
            "tree_sha256": source_tree_sha256,
            "files": source_files,
        },
        "evidence_files": evidence_manifest(evidence_dir, output),
    }
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(output, 0o600)
    (evidence_dir / "SHA256SUMS").write_text(
        f"{sha256(output)}  run-manifest.json\n", encoding="utf-8"
    )
    os.chmod(evidence_dir / "SHA256SUMS", 0o600)


if __name__ == "__main__":
    main()
