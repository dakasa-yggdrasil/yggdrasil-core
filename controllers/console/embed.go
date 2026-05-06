// Package console serves the Yggdrasil web console as a static SPA bundled
// into the binary via go:embed. The bundle is produced by the Vite build
// in the upstream yggdrasil-console repository and copied into this
// directory by the multi-stage Dockerfile (see "console-build" stage).
//
// In local/dev builds the embedded files are a placeholder index.html
// committed alongside this package; the Go compiler requires the embed
// target to exist at build time.
package console

import "embed"

// consoleAssets contains the SPA bundle. The "all:" prefix instructs
// go:embed to include dotfiles (Vite emits some, e.g. .vite/manifest.json
// in certain plugin setups) so the served tree exactly mirrors `dist/`.
//
//go:embed all:yggdrasil-console-dist
var consoleAssets embed.FS
