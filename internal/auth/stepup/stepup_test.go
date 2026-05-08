package stepup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestIsFresh_TimingWindow(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		when *time.Time
		want bool
	}{
		{"never authed", nil, false},
		{"now", &now, true},
	}
	old := now.Add(-10 * time.Minute)
	cases = append(cases, struct {
		name string
		when *time.Time
		want bool
	}{"stale", &old, false})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsFresh(SessionInfo{StepUpAuthenticatedAt: tc.when}, DefaultFreshnessWindow)
			if got != tc.want {
				t.Fatalf("IsFresh: want=%v got=%v", tc.want, got)
			}
		})
	}
}

func TestRequireMiddleware_BlocksWithoutFreshAuth(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/danger", nil)
	req = req.WithContext(WithSession(context.Background(), SessionInfo{SessionID: uuid.New()}))

	Require(DefaultFreshnessWindow)(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: want 401 got %d", rec.Code)
	}
	if called {
		t.Fatal("inner handler must not be called")
	}
	if got := rec.Header().Get("WWW-Authenticate"); got == "" {
		t.Fatal("WWW-Authenticate must be set")
	}
}

func TestRequireMiddleware_PassesWithFreshAuth(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/danger", nil)
	now := time.Now()
	req = req.WithContext(WithSession(context.Background(), SessionInfo{
		SessionID:             uuid.New(),
		StepUpAuthenticatedAt: &now,
	}))

	Require(DefaultFreshnessWindow)(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200 got %d", rec.Code)
	}
	if !called {
		t.Fatal("inner handler must be called")
	}
}
