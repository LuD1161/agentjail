#!/usr/bin/env python3
import hashlib
import json
import os
import re
import sys
from pathlib import Path


PROHIBITED = re.compile(
    rb"/Users/|/home/|/var/folders/|ASIA[A-Z0-9]{16}|AKIA[A-Z0-9]{16}|"
    rb"AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|BEGIN [A-Z ]*PRIVATE KEY|mcp__"
)


def sanitize(value):
    if isinstance(value, str):
        value = re.sub(r"/Users/[^/\s\"]+", "$GUEST_HOME", value)
        value = re.sub(
            r"/var/folders/[A-Za-z0-9_./-]*/agentjail-credentials-[A-Za-z0-9_-]+",
            "$CREDENTIAL_SESSION",
            value,
        )
        return value
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, dict):
        return {key: sanitize(item) for key, item in value.items()}
    return value


def rewrite_json(path: Path):
    value = json.loads(path.read_text(encoding="utf-8"))
    if path.name.endswith("audit.json"):
        for row in value:
            if isinstance(row.get("detail"), str) and row["detail"]:
                row["detail"] = json.loads(row["detail"])
    path.write_text(json.dumps(sanitize(value), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    root = Path(sys.argv[1]).resolve()
    scenario_paths = [Path(item).resolve() for item in sys.argv[2:]]
    for path in root.glob("*.json"):
        rewrite_json(path)
    for path in root.glob("*.txt"):
        path.write_text(sanitize(path.read_text(encoding="utf-8")), encoding="utf-8")
    definitions = []
    for path in scenario_paths:
        definitions.append({"name": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    (root / "scenario-definitions.json").write_text(json.dumps(definitions, indent=2) + "\n", encoding="utf-8")
    review = """# Independent AWS STS evidence review

Review only this directory and the scenario hashes. Determine which claims are conclusively proven, whether the identified Codex process discovered and requested the exact broker credential, whether the separate direct broker session used the issued STS values through the observed AWS binary, whether ambient fallback was excluded, whether positive and negative AWS outcomes executed, whether any SKIP was treated as success, whether leakage checks are sufficiently bounded, and what evidence is missing. Do not assume the desired conclusion.
"""
    (root / "review-prompt.md").write_text(review, encoding="utf-8")
    for path in root.iterdir():
        if path.is_file() and path.name != "SHA256SUMS":
            data = path.read_bytes()
            if PROHIBITED.search(data):
                print(f"prohibited evidence content: {path.name}", file=sys.stderr)
                return 1
    files = sorted(path for path in root.iterdir() if path.is_file() and path.name != "SHA256SUMS")
    sums = "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files)
    (root / "SHA256SUMS").write_text(sums, encoding="utf-8")
    for path in root.iterdir():
        if path.is_file():
            os.chmod(path, 0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
