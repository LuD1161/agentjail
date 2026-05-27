// static_embed.go — embeds the static/ directory into the binary.
//
// NOT in v0.1.0-alpha release. Local dev tool only.
package ui

import "embed"

//go:embed static/index.html
var staticFS embed.FS
