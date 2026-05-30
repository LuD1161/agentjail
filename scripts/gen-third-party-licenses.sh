#!/bin/sh
# gen-third-party-licenses.sh — regenerate THIRD_PARTY_LICENSES.
#
# Concatenates the verbatim license (and NOTICE) text of every third-party Go
# module compiled into the shipped binaries (./cmd/...), unioned across all
# release target platforms so the file is complete regardless of build-tag
# differences. This satisfies the attribution requirements of the permissive
# licenses we depend on (Apache-2.0 §4(d) NOTICE reproduction; MIT/BSD/ISC
# copyright-notice preservation in binary distributions).
#
# Dependency-free: uses only `go list` + the local module cache. No go-licenses,
# no network. Run from anywhere; it operates on the repo root.
#
# Usage:
#   scripts/gen-third-party-licenses.sh [output-file]   # default: THIRD_PARTY_LICENSES
#   scripts/gen-third-party-licenses.sh --check         # fail if out of date (CI)
set -eu

unset CDPATH 2>/dev/null || true
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

CHECK=0
OUT="THIRD_PARTY_LICENSES"
case "${1:-}" in
    --check) CHECK=1 ;;
    "") : ;;
    *) OUT="$1" ;;
esac

MAIN_MODULE=$(go list -m)
CMDS="./cmd/..."
PLATFORMS="darwin/arm64 darwin/amd64 linux/amd64 linux/arm64"

mods=$(mktemp)
trap 'rm -f "$mods" "$mods.out"' EXIT

# Collect "path\tversion\tdir" for every module backing a compiled package,
# across every release platform, then dedupe and drop our own module + stdlib.
for p in $PLATFORMS; do
    GOOS=${p%/*} GOARCH=${p#*/} CGO_ENABLED=0 \
        go list -deps -f '{{with .Module}}{{.Path}}	{{.Version}}	{{.Dir}}{{end}}' $CMDS 2>/dev/null
done | sort -u | grep -v "^${MAIN_MODULE}	" | grep -v '^	' > "$mods"

{
    echo "THIRD-PARTY SOFTWARE LICENSES"
    echo "============================="
    echo
    echo "The agentjail binaries (agentjail, agentjail-hook, agentjail-daemon,"
    echo "agentjail-shield, agentjail-netproxy) statically link the third-party Go"
    echo "modules listed below. Their license texts are reproduced verbatim to"
    echo "satisfy attribution requirements. agentjail itself is Apache-2.0 (see"
    echo "LICENSE). Regenerate with scripts/gen-third-party-licenses.sh."
    echo
    echo "Modules:"
    while IFS='	' read -r path version dir; do
        [ -n "$path" ] && echo "  - ${path} ${version}"
    done < "$mods"
    echo

    while IFS='	' read -r path version dir; do
        [ -z "$path" ] && continue
        echo
        echo "================================================================================"
        echo "${path} ${version}"
        echo "================================================================================"
        echo
        found=0
        # Case-insensitive find (GOMODCACHE on macOS is case-insensitive; find
        # returns each file once) catches LICENSE, License.txt, LICENCE,
        # LICENSE-APACHE-2.0.txt, COPYING, NOTICE, etc. without double-emitting.
        for lf in $(find "$dir" -maxdepth 1 -type f \
                      \( -iname 'LICENSE*' -o -iname 'LICENCE*' \
                         -o -iname 'COPYING*' -o -iname 'NOTICE*' \) | sort); do
            echo "----- $(basename "$lf") -----"
            cat "$lf"
            echo
            found=1
        done
        [ "$found" -eq 0 ] && echo "(no license file found in module cache — review manually)"
    done < "$mods"
} > "$mods.out"

if [ "$CHECK" -eq 1 ]; then
    if [ ! -f "$OUT" ] || ! cmp -s "$mods.out" "$OUT"; then
        echo "THIRD_PARTY_LICENSES is out of date — run scripts/gen-third-party-licenses.sh" >&2
        exit 1
    fi
    echo "THIRD_PARTY_LICENSES is up to date."
else
    mv "$mods.out" "$OUT"
    echo "wrote $OUT ($(grep -c '^  - ' "$OUT") modules)"
fi
