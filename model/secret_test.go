package model

import (
	"encoding/json"
	"strings"
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
	})

	if len(view.Keys) != 2 {
		t.Fatalf("expected keys to be preserved, got %#v", view.Keys)
	}
	payload, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(payload)
	for _, forbidden := range []string{"ghp_secret_token", "12345", "masked_data", `"data"`} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("metadata-only view leaked %q in %s", forbidden, encoded)
		}
	}
}
