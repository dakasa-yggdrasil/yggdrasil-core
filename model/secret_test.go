package model

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBuildManagedSecretViewRedactsValuesByDefault(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	view := BuildManagedSecretView(ManagedSecret{
		ID:            uuid.New(),
		Namespace:     "global",
		Name:          "github-app",
		Status:        "active",
		Version:       3,
		Data:          map[string]string{"token": "ghp_secret_token", "app_id": "12345"},
		LastRotatedAt: now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}, false)

	if view.Data != nil {
		t.Fatalf("expected redacted view to omit raw data, got %#v", view.Data)
	}
	if view.MaskedData["token"] == "ghp_secret_token" {
		t.Fatalf("expected token to be masked, got %#v", view.MaskedData["token"])
	}
	if len(view.Keys) != 2 {
		t.Fatalf("expected keys to be preserved, got %#v", view.Keys)
	}
}

func TestBuildManagedSecretViewIncludesValuesWhenRequested(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	view := BuildManagedSecretView(ManagedSecret{
		ID:            uuid.New(),
		Namespace:     "global",
		Name:          "github-app",
		Status:        "active",
		Version:       1,
		Data:          map[string]string{"token": "ghp_secret_token"},
		LastRotatedAt: now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}, true)

	if view.Data["token"] != "ghp_secret_token" {
		t.Fatalf("expected raw token when includeValues is true, got %#v", view.Data)
	}
	if view.MaskedData["token"] == "" {
		t.Fatalf("expected masked value to remain present")
	}
}
