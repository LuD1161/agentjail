# Vendored asset provenance

`asciinema-player.min.js` and `asciinema-player.css` are vendored from
[asciinema-player](https://github.com/asciinema/asciinema-player) **v3.17.0**,
licensed under **Apache-2.0**.

Used only by `test/testbed/gen-report.sh` to build a self-contained
`report.html` (inlined, no external requests). Test tooling only — not shipped
in any agentjail release binary, so it is intentionally outside the Go
`THIRD_PARTY_LICENSES` set (that file tracks compiled-in Go deps).

To update: download the two files from a newer release's assets and replace
them here; bump the version in this file.
