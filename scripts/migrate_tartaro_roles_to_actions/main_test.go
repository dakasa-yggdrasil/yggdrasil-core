package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchRoleActions_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/admin/roles/moderator/actions" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Fatalf("expected bearer auth, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"role":"moderator","actions":["tartaro:moderate_post","tartaro:decide_report"]}`))
	}))
	defer srv.Close()
	cfg := config{tartaroOpsBaseURL: srv.URL, tartaroOpsToken: "secret"}
	actions, err := fetchRoleActions(context.Background(), cfg, "moderator")
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 2 || actions[0] != "tartaro:moderate_post" {
		t.Fatalf("unexpected: %v", actions)
	}
}

func TestFetchRoleActions_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	cfg := config{tartaroOpsBaseURL: srv.URL}
	_, err := fetchRoleActions(context.Background(), cfg, "ghost")
	if err == nil || !contains(err.Error(), "not in tartaro-ops catalog") {
		t.Fatalf("expected catalog-miss error, got %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || (len(sub) > 0 && (indexOf(s, sub) >= 0)))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
