package reqcache

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

func TestSetGet_RoundTrip(t *testing.T) {
	ctx := Install(context.Background())

	Set(ctx, "collaborator", "abc", "alice")

	v, ok := Get(ctx, "collaborator", "abc")
	if !ok {
		t.Fatal("expected hit")
	}
	if v.(string) != "alice" {
		t.Errorf("got %v, want alice", v)
	}
}

func TestGet_NoCacheInstalled_ReturnsMiss(t *testing.T) {
	ctx := context.Background()
	v, ok := Get(ctx, "collaborator", "abc")
	if ok || v != nil {
		t.Errorf("expected (nil,false), got (%v,%v)", v, ok)
	}
}

func TestInstall_Idempotent(t *testing.T) {
	ctx := Install(context.Background())
	Set(ctx, "k", "id", 42)

	// Re-install: existing cache must be preserved.
	ctx2 := Install(ctx)

	v, ok := Get(ctx2, "k", "id")
	if !ok || v.(int) != 42 {
		t.Errorf("re-Install lost the cache: got (%v,%v)", v, ok)
	}
}

func TestDelete(t *testing.T) {
	ctx := Install(context.Background())
	Set(ctx, "k", "id", "v")

	Delete(ctx, "k", "id")
	if _, ok := Get(ctx, "k", "id"); ok {
		t.Error("expected miss after delete")
	}
}

func TestGetOrLoad_LoaderCalledOnce(t *testing.T) {
	ctx := Install(context.Background())

	var calls atomic.Int32
	loader := func(_ context.Context) (string, error) {
		calls.Add(1)
		return "loaded", nil
	}

	for range 5 {
		v, err := GetOrLoad(ctx, "collab", "alice", loader)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if v != "loaded" {
			t.Errorf("got %q, want loaded", v)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("loader called %d times, want 1", calls.Load())
	}
}

func TestGetOrLoad_ErrorNotCached(t *testing.T) {
	ctx := Install(context.Background())

	var calls atomic.Int32
	loader := func(_ context.Context) (string, error) {
		calls.Add(1)
		return "", errors.New("boom")
	}

	for range 3 {
		_, err := GetOrLoad(ctx, "collab", "id", loader)
		if err == nil {
			t.Fatal("expected error")
		}
	}
	if calls.Load() != 3 {
		t.Errorf("loader called %d times, want 3 (errors not cached)", calls.Load())
	}
}

func TestGetOrLoad_NoCacheInstalled_StillLoads(t *testing.T) {
	ctx := context.Background()
	loader := func(_ context.Context) (string, error) { return "ok", nil }

	v, err := GetOrLoad(ctx, "k", "id", loader)
	if err != nil || v != "ok" {
		t.Errorf("got (%v,%v), want (ok,<nil>)", v, err)
	}
}

func TestConcurrentSetGet(t *testing.T) {
	ctx := Install(context.Background())
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			Set(ctx, "k", "v", n)
			_, _ = Get(ctx, "k", "v")
		}(i)
	}
	wg.Wait()
}

func TestMiddleware_InstallsCache(t *testing.T) {
	var hit bool
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Set(r.Context(), "k", "id", "v")
		if _, ok := Get(r.Context(), "k", "id"); ok {
			hit = true
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !hit {
		t.Fatal("middleware did not install a cache the handler could write/read")
	}
}

func TestSize(t *testing.T) {
	ctx := Install(context.Background())
	if Size(ctx) != 0 {
		t.Errorf("Size=%d, want 0", Size(ctx))
	}
	Set(ctx, "a", "1", "x")
	Set(ctx, "a", "2", "y")
	Set(ctx, "b", "1", "z")
	if Size(ctx) != 3 {
		t.Errorf("Size=%d, want 3", Size(ctx))
	}
}
