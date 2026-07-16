// static_embed.go — embeds the static/ directory into the binary.
//
// NOT in v0.1.0-alpha release. Local dev tool only.
package ui

import "embed"

//go:embed static/index.html
var staticFS embed.FS

// Pattern must always match or a clean clone fails to compile before npm ever
// runs; static/dist/.gitkeep is tracked to guarantee it. Real assets are built
// into static/dist/ by `make ui`; when absent the server serves staticFS.
//
//go:embed all:static/dist
var spaFS embed.FS
