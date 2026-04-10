package main

import "testing"

func TestResolveAddonsAddsDependenciesFirst(t *testing.T) {
	got, err := resolveAddons("goose")
	if err != nil {
		t.Fatalf("resolveAddons(goose) error: %v", err)
	}

	want := []string{"postgres", "goose"}
	if len(got) != len(want) {
		t.Fatalf("unexpected addon count: got %v want %v", got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected addon order: got %v want %v", got, want)
		}
	}
}

func TestResolveAddonsOutboxDependencies(t *testing.T) {
	got, err := resolveAddons("outbox")
	if err != nil {
		t.Fatalf("resolveAddons(outbox) error: %v", err)
	}

	want := []string{"postgres", "rabbitmq", "redis", "outbox"}
	if len(got) != len(want) {
		t.Fatalf("unexpected addon count: got %v want %v", got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected addon order: got %v want %v", got, want)
		}
	}
}

func TestRenderTemplateReplacesKnownTokens(t *testing.T) {
	ctx := templateContext{
		ModulePath:  "github.com/dakasa-yggdrasil/yggdrasil-core",
		ServiceName: "yggdrasil-core",
		ServiceSlug: "yggdrasil_core",
	}

	got := string(renderTemplate([]byte("{{MODULE_PATH}} {{SERVICE_NAME}} {{SERVICE_SLUG}}"), ctx))
	want := "github.com/dakasa-yggdrasil/yggdrasil-core yggdrasil-core yggdrasil_core"
	if got != want {
		t.Fatalf("unexpected render result: got %q want %q", got, want)
	}
}
