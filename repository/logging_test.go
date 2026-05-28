package repository

import (
	"bytes"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

// captureStderr swaps os.Stderr for a pipe and returns whatever was
// written between setup and teardown. Single test per process to avoid
// the global swap racing.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	var buf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&buf, r)
	}()
	fn()
	_ = w.Close()
	wg.Wait()
	_ = r.Close()
	return buf.String()
}

// TestStructuredLog_EmitsKeyValueFormat verifies the format includes
// event=<event> and kv pairs without spaces collapse to bare values.
//
// Audit ref: B4/B8/G2 (replace fmt.Printf with structured log).
func TestStructuredLog_EmitsKeyValueFormat(t *testing.T) {
	out := captureStderr(t, func() {
		structuredLog("auth.password.verify_failed",
			"collaborator_id", "f926cc6d-0696-4359-a68b-d2f886377349",
			"scheme", "pbkdf2_sha256",
		)
	})
	if !strings.HasPrefix(out, "repo ts=") {
		t.Fatalf("expected prefix 'repo ts='; got %q", out)
	}
	if !strings.Contains(out, "event=auth.password.verify_failed") {
		t.Fatalf("missing event field: %q", out)
	}
	if !strings.Contains(out, "collaborator_id=f926cc6d-0696-4359-a68b-d2f886377349") {
		t.Fatalf("missing collaborator_id: %q", out)
	}
	if !strings.Contains(out, "scheme=pbkdf2_sha256") {
		t.Fatalf("missing scheme: %q", out)
	}
}

// TestStructuredLog_QuotesValuesWithSpaces ensures values containing
// spaces are JSON-quoted so the aggregator can parse cleanly.
func TestStructuredLog_QuotesValuesWithSpaces(t *testing.T) {
	out := captureStderr(t, func() {
		structuredLog("test.event",
			"error", "connection refused on 5432",
		)
	})
	if !strings.Contains(out, `error="connection refused on 5432"`) {
		t.Fatalf("expected quoted error value: %q", out)
	}
}
