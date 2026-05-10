package httpapi

import (
	"encoding/base64"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestPatchUserPreferencesStoresProfileAndVisualSettings(t *testing.T) {
	name := "Gio"
	avatar := "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("avatar image"))
	accent := "#72B7FF"

	personalData, err := patchUserPreferences(model.Collaborator{
		ID: uuid.New(),
		PersonalData: map[string]any{
			"other": "preserved",
			"profile": map[string]any{
				"title": "Engineer",
			},
		},
	}, model.UpdateUserPreferencesRequest{
		PreferredName: &name,
		AvatarDataURL: &avatar,
		AccentColor:   &accent,
	})
	if err != nil {
		t.Fatalf("patchUserPreferences returned error: %v", err)
	}

	if got := personalData["preferred_name"]; got != "Gio" {
		t.Fatalf("preferred_name = %v, want Gio", got)
	}
	if got := personalData["other"]; got != "preserved" {
		t.Fatalf("other = %v, want preserved", got)
	}
	profile := personalData["profile"].(map[string]any)
	if got := profile["avatar_data_url"]; got != avatar {
		t.Fatalf("profile.avatar_data_url = %v, want %s", got, avatar)
	}
	if _, ok := profile["avatar_url"]; ok {
		t.Fatalf("profile.avatar_url should be cleared")
	}
	if got := profile["title"]; got != "Engineer" {
		t.Fatalf("profile.title = %v, want Engineer", got)
	}
	preferences := personalData["preferences"].(map[string]any)
	if got := preferences["accent_color"]; got != "#72b7ff" {
		t.Fatalf("preferences.accent_color = %v, want #72b7ff", got)
	}
}

func TestPatchUserPreferencesClearsEmptyValues(t *testing.T) {
	empty := ""

	personalData, err := patchUserPreferences(model.Collaborator{
		ID: uuid.New(),
		PersonalData: map[string]any{
			"preferred_name": "Gio",
			"avatar_url":     "https://cdn.example.test/legacy.png",
			"profile":        map[string]any{"avatar_data_url": "data:image/png;base64,YXZhdGFy", "avatar_url": "https://cdn.example.test/gio.png"},
			"preferences":    map[string]any{"accent_color": "#72b7ff"},
		},
	}, model.UpdateUserPreferencesRequest{
		PreferredName: &empty,
		AvatarDataURL: &empty,
		AccentColor:   &empty,
	})
	if err != nil {
		t.Fatalf("patchUserPreferences returned error: %v", err)
	}

	if _, ok := personalData["preferred_name"]; ok {
		t.Fatalf("preferred_name should be cleared")
	}
	if _, ok := personalData["profile"]; ok {
		t.Fatalf("empty profile should be removed")
	}
	if _, ok := personalData["preferences"]; ok {
		t.Fatalf("empty preferences should be removed")
	}
}

func TestPatchUserPreferencesRejectsInvalidPresentationValues(t *testing.T) {
	badAvatar := "https://cdn.example.test/gio.png"
	if _, err := patchUserPreferences(model.Collaborator{}, model.UpdateUserPreferencesRequest{AvatarDataURL: &badAvatar}); err == nil {
		t.Fatalf("expected invalid avatar data URL error")
	}

	badAccent := "blue"
	if _, err := patchUserPreferences(model.Collaborator{}, model.UpdateUserPreferencesRequest{AccentColor: &badAccent}); err == nil {
		t.Fatalf("expected invalid accent color error")
	}
}

func TestApplyYggdrasilIdentityDesiredState(t *testing.T) {
	desired := map[string]any{
		"teams": []any{"people"},
		"profile": map[string]any{
			"title": "Engineer",
		},
	}
	avatar := "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("avatar"))

	applyYggdrasilIdentityDesiredState(desired, model.Collaborator{
		ID:           uuid.New(),
		PrimaryEmail: "giovanni@example.test",
		DisplayName:  "Giovanni Martins",
		PersonalData: map[string]any{
			"preferred_name": "Gio Martins",
			"profile":        map[string]any{"avatar_data_url": avatar},
		},
	})

	if got := desired["identity_source"]; got != "yggdrasil" {
		t.Fatalf("identity_source = %v, want yggdrasil", got)
	}
	if got := desired["primary_email"]; got != "giovanni@example.test" {
		t.Fatalf("primary_email = %v", got)
	}
	if got := desired["full_name"]; got != "Gio Martins" {
		t.Fatalf("full_name = %v, want Gio Martins", got)
	}
	if got := desired["avatar_data_url"]; got != avatar {
		t.Fatalf("avatar_data_url = %v, want %s", got, avatar)
	}
	if _, ok := desired["teams"]; !ok {
		t.Fatalf("existing desired state should be preserved")
	}
	profile := desired["profile"].(map[string]any)
	if got := profile["source"]; got != "yggdrasil" {
		t.Fatalf("profile.source = %v, want yggdrasil", got)
	}
	if got := profile["title"]; got != "Engineer" {
		t.Fatalf("profile.title = %v, want Engineer", got)
	}
}
