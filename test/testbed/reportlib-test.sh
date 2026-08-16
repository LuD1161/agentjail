#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$ROOT/reportlib.sh"
WORK="$(mktemp -d /tmp/agentjail-reportlib-test.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

printf '%s\n' '{"result":"pass","counts":{"pass":2,"fail":0,"skip":0}}' >"$WORK/pass.json"
printf '%s\n' '{"result":"pass","counts":{"pass":1,"fail":0,"skip":1}}' >"$WORK/mixed.json"
printf '%s\n' '{"result":"skip","counts":{"pass":0,"fail":0,"skip":1}}' >"$WORK/skip.json"
printf '%s\n' '{"result":"fail","counts":{"pass":1,"fail":1,"skip":0}}' >"$WORK/fail.json"

scn_release_result_valid "$WORK/pass.json"

assert_release_rejected() {
	if scn_release_result_valid "$1"; then
		printf 'FAIL release result unexpectedly accepted: %s\n' "$1" >&2
		exit 1
	fi
}

assert_release_rejected "$WORK/mixed.json"
assert_release_rejected "$WORK/skip.json"
assert_release_rejected "$WORK/fail.json"

printf 'PASS reportlib release result contract\n'
