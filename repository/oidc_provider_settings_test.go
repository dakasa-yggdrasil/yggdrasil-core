package repository

import (
	"context"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestGetOIDCProviderSettings_Defaults(t *testing.T) {
	db := dbForOIDCTest(t)
	defer db.Close()
	s, err := GetOIDCProviderSettings(context.Background(), db)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(s.AllowedEmailDomains) == 0 {
		t.Errorf("expected default domains, got empty")
	}
	if s.DefaultTeamSlug != "dakasa-internal" {
		t.Errorf("default team slug: want dakasa-internal, got %q", s.DefaultTeamSlug)
	}
	if !s.AutoProvision {
		t.Errorf("expected auto_provision=true by default")
	}
}

func TestUpdateOIDCProviderSettingsRoundTrip(t *testing.T) {
	db := dbForOIDCTest(t)
	// Register Close FIRST so restore-state cleanup (registered next)
	// runs while db is still open (cleanups are LIFO).
	t.Cleanup(func() { db.Close() })
	// Save original
	orig, err := GetOIDCProviderSettings(context.Background(), db)
	if err != nil {
		t.Fatalf("get original: %v", err)
	}
	t.Cleanup(func() {
		if err := UpdateOIDCProviderSettings(context.Background(), db, orig); err != nil {
			t.Errorf("restore original settings: %v", err)
		}
	})

	// Update
	updated := model.OIDCProviderSettings{
		AllowedEmailDomains: []string{"dakasa.me", "test.com"},
		DefaultTeamSlug:     "different-team",
		AutoProvision:       false,
	}
	if err := UpdateOIDCProviderSettings(context.Background(), db, updated); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err := GetOIDCProviderSettings(context.Background(), db)
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	if len(got.AllowedEmailDomains) != 2 || got.DefaultTeamSlug != "different-team" || got.AutoProvision {
		t.Errorf("update lost data: %+v", got)
	}
}
