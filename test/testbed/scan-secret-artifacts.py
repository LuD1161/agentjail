#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path


SECRET_KEY_PARTS = ("token", "secret", "password", "passwd", "api_key", "apikey")


def collect_string_inventory(value, path=()):
    found = []
    if isinstance(value, dict):
        for key, child in value.items():
            found.extend(collect_string_inventory(child, (*path, str(key))))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(collect_string_inventory(child, (*path, str(index))))
    elif isinstance(value, str) and len(value) >= 12:
        found.append((".".join(path), value.encode()))
    return found


def iter_files(roots, excluded):
    seen = set()
    for root in roots:
        root_path = Path(root)
        if not root_path.exists():
            continue
        candidates = [root_path] if root_path.is_file() else root_path.rglob("*")
        for path in candidates:
            try:
                resolved = path.resolve()
                if resolved in excluded or resolved in seen:
                    continue
                seen.add(resolved)
                mode = path.lstat().st_mode
                if stat.S_ISREG(mode) and not path.is_symlink():
                    yield path
            except OSError:
                yield path


def file_matches(path, secrets):
    matches = set()
    with path.open("rb") as handle:
        tail = b""
        overlap = max(len(secret) for secret in secrets) - 1
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            data = tail + block
            for index, secret in enumerate(secrets):
                if secret in data:
                    matches.add(index)
            tail = data[-overlap:] if overlap > 0 else b""
    return matches


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--secret-file", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--exclude", action="append", default=[])
    parser.add_argument("roots", nargs="+")
    args = parser.parse_args()

    secret_file = Path(args.secret_file).resolve()
    output = Path(args.output).resolve()
    value = json.loads(secret_file.read_text(encoding="utf-8"))
    inventory = collect_string_inventory(value)
    secret_entries = [
        (path, raw) for path, raw in inventory
        if any(part in path.lower().split(".")[-1] for part in SECRET_KEY_PARTS)
    ]
    secrets = list(dict.fromkeys(raw for _, raw in secret_entries))
    excluded = {secret_file, output, *(Path(item).resolve() for item in args.exclude)}
    errors = []
    matches = []
    files_scanned = 0
    bytes_scanned = 0
    positive_control_hits = 0

    if secrets:
        fd, positive_name = tempfile.mkstemp(prefix="agentjail-auth-scan-positive.")
        positive = Path(positive_name)
        try:
            os.write(fd, secrets[0])
            os.close(fd)
            positive_control_hits = len(file_matches(positive, secrets))
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            positive.unlink(missing_ok=True)

        for path in iter_files(args.roots, excluded):
            try:
                hit_indexes = file_matches(path, secrets)
                files_scanned += 1
                bytes_scanned += path.stat().st_size
                if hit_indexes:
                    matches.append({
                        "path": str(path),
                        "secret_fingerprints": [hashlib.sha256(secrets[index]).hexdigest() for index in sorted(hit_indexes)],
                    })
            except OSError as exc:
                errors.append({"path": str(path), "error": exc.__class__.__name__})

    status = "pass" if secrets and positive_control_hits > 0 and not matches and not errors else "fail"
    result = {
        "schema_version": 3,
        "status": status,
        "credential_string_count": len(secrets),
        "credential_key_paths": sorted({path for path, _ in secret_entries}),
        "credential_fingerprints": [hashlib.sha256(secret).hexdigest() for secret in secrets],
        "noncredential_long_string_paths": sorted({
            path for path, raw in inventory if raw not in secrets
        }),
        "positive_control_hits": positive_control_hits,
        "files_scanned": files_scanned,
        "bytes_scanned": bytes_scanned,
        "matches": matches,
        "errors": errors,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(output, 0o600)
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
