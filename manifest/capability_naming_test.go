package manifest

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCapabilityNamingAllowlist_Exact(t *testing.T) {
	path := filepath.Join("..", "config", "capability_naming_allowlist.yaml")
	al, err := LoadCapabilityNamingAllowlist(path)
	if err != nil {
		t.Fatalf("LoadCapabilityNamingAllowlist failed: %v", err)
	}
	for _, want := range []string{"verify_webhook_signature", "publish_message", "create_refund"} {
		if !al.Allowed(want, "capability") {
			t.Errorf("expected %q to be allowed (exact match)", want)
		}
	}
}

func TestLoadCapabilityNamingAllowlist_Prefix(t *testing.T) {
	path := filepath.Join("..", "config", "capability_naming_allowlist.yaml")
	al, err := LoadCapabilityNamingAllowlist(path)
	if err != nil {
		t.Fatalf("LoadCapabilityNamingAllowlist failed: %v", err)
	}
	if !al.Allowed("calculate_iss", "capability") {
		t.Error("expected calculate_iss to be prefix-allowed")
	}
	if !al.Allowed("calculate_anything_else", "capability") {
		t.Error("expected calculate_* prefix to match any suffix")
	}
}

func TestLoadCapabilityNamingAllowlist_RejectsUnknown(t *testing.T) {
	path := filepath.Join("..", "config", "capability_naming_allowlist.yaml")
	al, err := LoadCapabilityNamingAllowlist(path)
	if err != nil {
		t.Fatalf("LoadCapabilityNamingAllowlist failed: %v", err)
	}
	if al.Allowed("create_user", "capability") {
		t.Error("expected create_user to NOT be allowed (must be ensure_user)")
	}
}

func TestLoadCapabilityNamingAllowlist_ReactorAlwaysAllowed(t *testing.T) {
	path := filepath.Join("..", "config", "capability_naming_allowlist.yaml")
	al, err := LoadCapabilityNamingAllowlist(path)
	if err != nil {
		t.Fatalf("LoadCapabilityNamingAllowlist failed: %v", err)
	}
	if !al.Allowed("zz_not_in_allowlist_at_all", "reactor") {
		t.Error("expected any name to be allowed when category=reactor")
	}
}

func TestValidateCapabilityName_Conformant(t *testing.T) {
	al, _ := LoadCapabilityNamingAllowlist(filepath.Join("..", "config", "capability_naming_allowlist.yaml"))
	cases := []string{
		"ensure_user", "observe_users", "destroy_user",
		"discover_s3_buckets", "on_member_joined_channel",
		"ensure_s3_bucket_v2_thing",
	}
	for _, name := range cases {
		warnings := ValidateCapabilityName(name, "capability", al)
		if len(warnings) != 0 {
			t.Errorf("expected zero warnings for conformant %q, got %v", name, warnings)
		}
	}
}

func TestValidateCapabilityName_NonConformantEmitsWarning(t *testing.T) {
	al, _ := LoadCapabilityNamingAllowlist(filepath.Join("..", "config", "capability_naming_allowlist.yaml"))
	warnings := ValidateCapabilityName("create_user", "capability", al)
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning for create_user, got %d (%v)", len(warnings), warnings)
	}
	w := warnings[0]
	if w.Code != "CAPABILITY_NAME_NONCONFORMANT" {
		t.Errorf("expected code CAPABILITY_NAME_NONCONFORMANT, got %q", w.Code)
	}
	if w.Value != "create_user" {
		t.Errorf("expected Value=create_user, got %q", w.Value)
	}
	if !strings.Contains(w.Message, "ensure_user") {
		t.Errorf("expected suggested rename to mention 'ensure_user', got %q", w.Message)
	}
}

func TestValidateCapabilityName_AllowlistedNotWarned(t *testing.T) {
	al, _ := LoadCapabilityNamingAllowlist(filepath.Join("..", "config", "capability_naming_allowlist.yaml"))
	for _, name := range []string{"publish_message", "verify_webhook_signature", "calculate_iss"} {
		warnings := ValidateCapabilityName(name, "capability", al)
		if len(warnings) != 0 {
			t.Errorf("expected zero warnings for allowlisted %q, got %v", name, warnings)
		}
	}
}

func TestValidateCapabilityName_ReactorCategoryExempt(t *testing.T) {
	al, _ := LoadCapabilityNamingAllowlist(filepath.Join("..", "config", "capability_naming_allowlist.yaml"))
	warnings := ValidateCapabilityName("totally_made_up_name", "reactor", al)
	if len(warnings) != 0 {
		t.Errorf("expected reactor category to be exempt, got warnings %v", warnings)
	}
}
