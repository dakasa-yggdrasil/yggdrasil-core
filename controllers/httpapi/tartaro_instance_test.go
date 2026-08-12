package httpapi

import "testing"

// TestTartaroInstanceDefaults guards the 403-for-everyone regression: the
// effective-tartaro-actions computation only counts team_grants whose
// integration instance matches these values. The default MUST be the live
// registered instance (tartaro-dakasa-validation); the old hardcoded
// "integration-tartaro-dakasa" does not exist, so every grant was discarded
// and every collaborator resolved to an empty action set.
func TestTartaroInstanceDefaults(t *testing.T) {
	if tartaroInstanceNamespace != "dakasa" {
		t.Fatalf("default namespace = %q, want dakasa", tartaroInstanceNamespace)
	}
	if tartaroInstanceName != "tartaro-dakasa-validation" {
		t.Fatalf("default instance name = %q, want tartaro-dakasa-validation (the live instance); a wrong name zeroes every effective set", tartaroInstanceName)
	}
	if tartaroInstanceName == "integration-tartaro-dakasa" {
		t.Fatal("instance name reverted to the non-existent integration-tartaro-dakasa; this is the 403-for-everyone bug")
	}
}

func TestTartaroInstanceEnvOverride(t *testing.T) {
	t.Setenv("YGGDRASIL_TARTARO_INSTANCE_NAME", "tartaro-dakasa-production")
	if got := tartaroInstanceEnvOr("YGGDRASIL_TARTARO_INSTANCE_NAME", "tartaro-dakasa-validation"); got != "tartaro-dakasa-production" {
		t.Fatalf("env override = %q, want tartaro-dakasa-production", got)
	}
	t.Setenv("YGGDRASIL_TARTARO_INSTANCE_NAME", "   ")
	if got := tartaroInstanceEnvOr("YGGDRASIL_TARTARO_INSTANCE_NAME", "tartaro-dakasa-validation"); got != "tartaro-dakasa-validation" {
		t.Fatalf("blank env should fall back to default, got %q", got)
	}
}
