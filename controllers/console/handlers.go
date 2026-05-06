package console

import (
	"errors"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// distRoot is the embed sub-tree that contains the actual SPA files.
// We strip this prefix when resolving requests so a URL like /console/foo
// maps to yggdrasil-console-dist/foo inside the embedded FS.
const distRoot = "yggdrasil-console-dist"

// indexFile is served on SPA fallback (any path that doesn't match a
// static asset). Vite SPAs use client-side routing for everything except
// the asset paths under /assets/, so a missing path is almost always a
// route the client will resolve.
const indexFile = "index.html"

// Handler returns an http.Handler that serves the embedded SPA bundle.
//
// pathPrefix is the URL prefix under which the SPA is mounted (e.g. "/console").
// It is trimmed from the request path before resolution and must NOT end
// in a slash. The handler itself accepts both the prefix-with-slash and
// without (e.g. /console and /console/ both serve index.html).
//
// SPA fallback semantics:
//   - "/console" or "/console/"          → index.html (200)
//   - "/console/assets/main.js"          → embedded asset (200) or 404 if missing
//   - "/console/some/route"              → index.html (200) — SPA route
//
// To keep this distinct from "real" 404s we ONLY fall back to index.html
// when the requested path looks like a route (no file extension). Asset
// requests with extensions that don't exist return 404 — otherwise broken
// asset URLs would silently mask as HTML responses, which breaks both
// browser caching and developer debugging.
func Handler(pathPrefix string) http.Handler {
	pathPrefix = strings.TrimSuffix(pathPrefix, "/")
	subFS, err := fs.Sub(consoleAssets, distRoot)
	if err != nil {
		// Sub on a known-good const path can only fail if the build was
		// produced without the embed directive resolving — in that case
		// we want a clear startup failure, not a silent serve-nothing.
		panic("console: fs.Sub failed for embedded dist: " + err.Error())
	}
	fileServer := http.FileServerFS(subFS)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Trim the mount prefix; remaining path is what we look up in the FS.
		rel := strings.TrimPrefix(r.URL.Path, pathPrefix)
		rel = strings.TrimPrefix(rel, "/")
		if rel == "" {
			serveIndex(w, r, subFS)
			return
		}

		// Probe the embedded FS. If the file exists, delegate to the
		// stdlib FileServer (handles content-type, byte ranges, etc.).
		if _, err := fs.Stat(subFS, rel); err == nil {
			http.StripPrefix(pathPrefix, fileServer).ServeHTTP(w, r)
			return
		} else if !errors.Is(err, fs.ErrNotExist) {
			http.Error(w, "console asset error", http.StatusInternalServerError)
			return
		}

		// Path doesn't exist. SPA fallback — but only for routes (no
		// file extension); asset 404s stay as 404s so broken links are
		// visible.
		if path.Ext(rel) != "" {
			http.NotFound(w, r)
			return
		}
		serveIndex(w, r, subFS)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request, subFS fs.FS) {
	// SPA index must not be cached aggressively; it embeds hashed asset
	// references that change with each build. Tell intermediaries to
	// re-validate on every request.
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFileFS(w, r, subFS, indexFile)
}
