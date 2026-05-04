package httpapi

import (
	"reflect"
	"strings"
	"testing"
)

func samplePushEvent() githubPushEvent {
	p := githubPushEvent{Ref: "refs/heads/main"}
	p.Repository.FullName = "acme/widget"
	p.Repository.CloneURL = "https://github.com/acme/widget.git"
	p.HeadCommit.ID = "abcdef1234567890"
	p.HeadCommit.Message = "fix: bug"
	p.HeadCommit.Modified = []string{"deploy/overlays/validation/file.yaml"}
	p.Pusher.Name = "alice"
	return p
}

func TestBuildInputsFromPushSubstitutesPlaceholders(t *testing.T) {
	in := map[string]any{
		"git_url":   "{{ push.repository.clone_url }}",
		"namespace": "dakasa",
		"ref":       "{{ push.ref }}",
		"revision":  "{{ push.head_commit.id }}",
		"who":       "{{ push.pusher.name }}",
	}
	out, err := buildInputsFromPush(in, samplePushEvent())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := out["git_url"]; got != "https://github.com/acme/widget.git" {
		t.Fatalf("git_url: got %v", got)
	}
	if got := out["ref"]; got != "refs/heads/main" {
		t.Fatalf("ref: got %v", got)
	}
	if got := out["revision"]; got != "abcdef1234567890" {
		t.Fatalf("revision: got %v", got)
	}
	if got := out["who"]; got != "alice" {
		t.Fatalf("who: got %v", got)
	}
	if got := out["namespace"]; got != "dakasa" {
		t.Fatalf("namespace: got %v", got)
	}
}

func TestBuildInputsFromPushPassesThroughNonStrings(t *testing.T) {
	in := map[string]any{
		"timeout_seconds": 120,
		"tags":            []string{"a", "b"},
		"nested":          map[string]any{"k": "v"},
	}
	out, err := buildInputsFromPush(in, samplePushEvent())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got, ok := out["timeout_seconds"].(int); !ok || got != 120 {
		t.Fatalf("timeout_seconds: got %v (%T)", out["timeout_seconds"], out["timeout_seconds"])
	}
	if !reflect.DeepEqual(out["tags"], []string{"a", "b"}) {
		t.Fatalf("tags: got %v", out["tags"])
	}
	if !reflect.DeepEqual(out["nested"], map[string]any{"k": "v"}) {
		t.Fatalf("nested: got %v", out["nested"])
	}
}

func TestBuildInputsFromPushUnknownPlaceholderErrors(t *testing.T) {
	_, err := buildInputsFromPush(map[string]any{"x": "{{ push.unknown }}"}, samplePushEvent())
	if err == nil || !strings.Contains(err.Error(), "unknown placeholder") {
		t.Fatalf("expected unknown placeholder error, got %v", err)
	}
}

func TestBuildInputsFromPushIgnoresOtherNamespaces(t *testing.T) {
	out, err := buildInputsFromPush(map[string]any{"x": "{{ env.HOME }}"}, samplePushEvent())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out["x"] != "{{ env.HOME }}" {
		t.Fatalf("non-push placeholders should pass through, got %v", out["x"])
	}
}

func TestBuildInputsFromPushMultiplePlaceholdersInOneValue(t *testing.T) {
	in := map[string]any{
		"image_tag": "{{ push.repository.full_name }}@{{ push.head_commit.id }}",
	}
	out, err := buildInputsFromPush(in, samplePushEvent())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	want := "acme/widget@abcdef1234567890"
	if got := out["image_tag"]; got != want {
		t.Fatalf("image_tag: got %v, want %s", got, want)
	}
}
