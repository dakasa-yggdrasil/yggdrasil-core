package console

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandler_RootServesIndex(t *testing.T) {
	srv := httptest.NewServer(Handler("/console"))
	defer srv.Close()

	for _, target := range []string{"/console", "/console/"} {
		resp, err := http.Get(srv.URL + target)
		if err != nil {
			t.Fatalf("GET %s: %v", target, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s status: got %d, want 200", target, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("%s content-type: got %q", target, ct)
		}
		if !strings.Contains(string(body), "Yggdrasil Console") {
			t.Errorf("%s body missing console marker: %s", target, body)
		}
	}
}

func TestHandler_SPAFallbackForUnknownRoute(t *testing.T) {
	// Routes (no extension) that don't exist as files should fall back
	// to index.html so client-side routing works.
	srv := httptest.NewServer(Handler("/console"))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/console/some/client/route")
	if err != nil {
		t.Fatalf("GET fallback: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200 (SPA fallback)", resp.StatusCode)
	}
	if !strings.Contains(string(body), "Yggdrasil Console") {
		t.Errorf("body missing console marker: %s", body)
	}
}

func TestHandler_MissingAssetReturns404(t *testing.T) {
	// Asset-shaped paths (with file extension) that don't exist should
	// return a real 404, not the SPA index. This keeps broken asset
	// links visible in browser devtools instead of masking as HTML.
	srv := httptest.NewServer(Handler("/console"))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/console/assets/nonexistent.js")
	if err != nil {
		t.Fatalf("GET missing asset: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status: got %d, want 404 for missing asset", resp.StatusCode)
	}
}

func TestHandler_PrefixWithTrailingSlashTolerated(t *testing.T) {
	// Callers may pass "/console/" or "/console" — both should produce
	// equivalent handlers. We do this by trimming inside Handler.
	a := Handler("/console")
	b := Handler("/console/")

	r := httptest.NewRequest(http.MethodGet, "/console/", nil)

	wA := httptest.NewRecorder()
	a.ServeHTTP(wA, r)
	wB := httptest.NewRecorder()
	b.ServeHTTP(wB, r)

	if wA.Code != wB.Code {
		t.Errorf("inconsistent status: trim=%d notrim=%d", wA.Code, wB.Code)
	}
}
