#!/usr/bin/env python3
import os
import subprocess
import sys


def main() -> int:
    fields = sys.stdin.buffer.read().split(b"\0")
    if len(fields) != 5 or fields[-1] != b"" or not all(fields[:4]):
        print("guest_import=invalid_stream", file=sys.stderr)
        return 2
    access_key, secret_key, session_token, region = fields[:4]
    env = os.environ.copy()
    env.update(
        AWS_ACCESS_KEY_ID=access_key.decode("ascii"),
        AWS_SECRET_ACCESS_KEY=secret_key.decode("ascii"),
        AWS_SESSION_TOKEN=session_token.decode("ascii"),
        AWS_REGION=region.decode("ascii"),
        AWS_DEFAULT_REGION=region.decode("ascii"),
    )
    command = [
        os.path.expanduser("~/.agentjail/bin/agentjail"),
        "credential", "set", os.environ["AGENTJAIL_IMPORT_NAME"],
        "--from-env", "AWS_ACCESS_KEY_ID",
        "--from-env", "AWS_SECRET_ACCESS_KEY",
        "--from-env", "AWS_SESSION_TOKEN",
        "--from-env", "AWS_DEFAULT_REGION",
        "--label", "Temporary AWS STS role for account " + os.environ["AGENTJAIL_IMPORT_ACCOUNT"],
        "--tag", "aws", "--tag", "temporary", "--tag", "sts",
    ]
    result = subprocess.run(
        command, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, check=False,
    )
    if result.returncode:
        print("guest_import=failed", file=sys.stderr)
        return result.returncode
    print("guest_import=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
