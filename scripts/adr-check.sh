#!/usr/bin/env sh
# Enforce the ADR filename scheme (ADR 0083-adr-numbering-scheme).
#
# Two branches allocating the same number is invisible at author time and only
# hurts at merge time, when a bare "ADR 0049" in prose no longer identifies one
# document. This gate makes that a CI failure instead of archaeology.
#
# Usage: scripts/adr-check.sh [adr-dir]
set -eu

ADR_DIR="${1:-docs/adr}"
# Numbers below this predate the scheme; their long slugs are grandfathered.
SLUG_RULE_FROM=80
MAX_SLUG_WORDS=3

fail=0
note() { printf '  %s\n' "$1"; fail=1; }

[ -d "$ADR_DIR" ] || { echo "adr-check: no such directory: $ADR_DIR" >&2; exit 2; }

# 1. Every ADR must be NNNN-slug.md.
echo "adr-check: filename shape"
for f in "$ADR_DIR"/*.md; do
	b=$(basename "$f")
	case "$b" in
	README.md | TEMPLATE.md) continue ;;
	esac
	# Dots are allowed inside a word so version-ish slugs work
	# (0006-license-apache-2.0).
	if ! echo "$b" | grep -qE '^[0-9]{4}-[a-z0-9.]+(-[a-z0-9.]+)*\.md$'; then
		note "$b: want NNNN-slug.md (lowercase, hyphenated)"
	fi
done

# 2. No two ADRs may share a number -- the whole point of the gate.
echo "adr-check: duplicate numbers"
dupes=$(ls "$ADR_DIR" | grep -oE '^[0-9]{4}' | sort | uniq -d || true)
if [ -n "$dupes" ]; then
	for n in $dupes; do
		note "number $n is claimed by more than one ADR:"
		for f in "$ADR_DIR/$n"-*.md; do note "    $(basename "$f")"; done
		note "    -> renumber the less-referenced one to the next free number,"
		note "       and repoint its references BY CONTEXT (a bare 'ADR $n' is ambiguous)"
	done
fi

# 3. New ADRs keep slugs short enough to cite inline: NNNN-three-word-slug.
echo "adr-check: slug length (ADRs >= $SLUG_RULE_FROM)"
for f in "$ADR_DIR"/*.md; do
	b=$(basename "$f")
	n=$(echo "$b" | grep -oE '^[0-9]{4}') || continue
	# Strip leading zeros so this compares as a number, not a string.
	num=$(echo "$n" | sed 's/^0*//')
	[ -n "$num" ] || num=0
	[ "$num" -ge "$SLUG_RULE_FROM" ] || continue
	slug=$(echo "$b" | sed -E 's/^[0-9]{4}-//; s/\.md$//')
	words=$(echo "$slug" | tr '-' '\n' | grep -c .)
	if [ "$words" -gt "$MAX_SLUG_WORDS" ]; then
		note "$b: slug has $words words, max $MAX_SLUG_WORDS (cite as 'ADR $n-$slug')"
	fi
done

if [ "$fail" -ne 0 ]; then
	echo "adr-check: FAILED -- see docs/adr/0083-adr-numbering-scheme.md" >&2
	exit 1
fi
echo "adr-check: ok ($(ls "$ADR_DIR"/[0-9]*.md | wc -l | tr -d ' ') ADRs, no duplicate numbers)"
