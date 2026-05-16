package reactors

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestBuildReactorPayload(t *testing.T) {
	eventPayload := json.RawMessage(`{"id":"abc","slug":"alice","primary_email":"alice@x.io"}`)
	eventID := uuid.MustParse("12345678-1234-1234-1234-123456789abc")
	emittedAt := time.Date(2026, 5, 15, 10, 0, 0, 0, time.UTC)
	actor := &model.EventActor{Type: "collaborator", ID: "actor-uuid"}

	out, err := BuildReactorPayload(eventID, "collaborator.created", "v1", eventPayload, emittedAt, actor, 1)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["id"] != "abc" {
		t.Errorf("event field missing: %+v", got)
	}
	ctx, ok := got["_context"].(map[string]any)
	if !ok {
		t.Fatalf("_context missing or wrong type")
	}
	if ctx["event_type"] != "collaborator.created" {
		t.Errorf("_context.event_type wrong: %v", ctx["event_type"])
	}
	if int(ctx["attempt"].(float64)) != 1 {
		t.Errorf("_context.attempt wrong: %v", ctx["attempt"])
	}
}

func TestBuildReactorPayload_NoActor(t *testing.T) {
	out, err := BuildReactorPayload(uuid.New(), "team.created", "v1", json.RawMessage(`{"id":"x"}`), time.Now(), nil, 1)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(out, &got)
	ctx := got["_context"].(map[string]any)
	if _, ok := ctx["actor"]; ok {
		t.Errorf("actor key should be omitted when nil, got %v", ctx["actor"])
	}
}
