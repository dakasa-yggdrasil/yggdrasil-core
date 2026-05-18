package integrationsurfaces_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/integrationsurfaces"
)

// fakeEmitter captures emitted events without DB or schema validation
// (the schema validation is exercised by the standalone smoke in Task 5).
type fakeEmitter struct {
	calls []emittedEvent
}

type emittedEvent struct {
	EventType   string
	AggregateID string
	Payload     map[string]any
}

func (f *fakeEmitter) Emit(_ context.Context, eventType, aggregateID string, payload map[string]any) error {
	f.calls = append(f.calls, emittedEvent{eventType, aggregateID, payload})
	return nil
}

// fakeStore is an in-memory replacement for the Repository — keyed by manifest name.
type fakeStore struct {
	store map[string]*integrationsurfaces.Manifest
}

func newFakeStore() *fakeStore {
	return &fakeStore{store: map[string]*integrationsurfaces.Manifest{}}
}

func (s *fakeStore) Upsert(_ context.Context, m *integrationsurfaces.Manifest) error {
	cp := *m
	cp.ID = "fake-id"
	s.store[m.Name] = &cp
	m.ID = cp.ID
	return nil
}

func (s *fakeStore) GetByName(_ context.Context, name string) (*integrationsurfaces.Manifest, error) {
	if m, ok := s.store[name]; ok {
		return m, nil
	}
	return nil, integrationsurfaces.ErrNotFound
}

func TestSyncer_ReconcileFromBytes_Insert(t *testing.T) {
	store := newFakeStore()
	em := &fakeEmitter{}
	syncer := integrationsurfaces.NewSyncer(store, em)

	body, _ := json.Marshal(map[string]any{
		"apiVersion": "yggdrasil.io/v1alpha1",
		"kind":       "integration_surface",
		"metadata":   map[string]any{"name": "surface-slack", "integration_type": "slack"},
		"spec": map[string]any{
			"category": "integration",
			"runtime":  map[string]any{"kind": "spa", "base_path": "/s/slack"},
			"display":  map[string]any{"title": "Slack", "appears_on": []any{"ops-integrations"}},
		},
	})

	report, err := syncer.ReconcileFromBytes(context.Background(), body)
	if err != nil {
		t.Fatalf("ReconcileFromBytes: %v", err)
	}
	if report.Action != "inserted" {
		t.Errorf("action = %q, want inserted", report.Action)
	}
	if got := store.store["surface-slack"]; got == nil || got.Spec.Runtime.Kind != "spa" {
		t.Errorf("not persisted as expected: %+v", got)
	}
	if len(em.calls) != 1 || em.calls[0].EventType != "integration_surface.registered" {
		t.Errorf("expected 1 registered emit; got %+v", em.calls)
	}
}

func TestSyncer_ReconcileFromBytes_NoopOnSecondApply(t *testing.T) {
	store := newFakeStore()
	em := &fakeEmitter{}
	syncer := integrationsurfaces.NewSyncer(store, em)

	body, _ := json.Marshal(map[string]any{
		"apiVersion": "yggdrasil.io/v1alpha1",
		"kind":       "integration_surface",
		"metadata":   map[string]any{"name": "surface-x"},
		"spec": map[string]any{
			"category": "integration",
			"runtime":  map[string]any{"kind": "spa", "base_path": "/s/x"},
			"display":  map[string]any{"title": "X"},
		},
	})

	if _, err := syncer.ReconcileFromBytes(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	em.calls = nil

	r, err := syncer.ReconcileFromBytes(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	if r.Action != "noop" {
		t.Errorf("second apply should be noop; got %q", r.Action)
	}
	if len(em.calls) != 0 {
		t.Error("noop should not emit")
	}
}

func TestSyncer_RejectsWrongKind(t *testing.T) {
	syncer := integrationsurfaces.NewSyncer(newFakeStore(), &fakeEmitter{})
	body, _ := json.Marshal(map[string]any{
		"apiVersion": "yggdrasil.io/v1alpha1",
		"kind":       "surface", // old/legacy kind — should be rejected
		"metadata":   map[string]any{"name": "x"},
		"spec":       map[string]any{"category": "integration"},
	})
	if _, err := syncer.ReconcileFromBytes(context.Background(), body); err == nil {
		t.Fatal("expected error for kind=surface")
	}
}
