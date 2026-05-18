package integrationsurfaces

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Emitter abstracts event emission so tests don't need a real DB / schema
// validator. In production, wire it to a function that wraps
// repository.EmitEvent in a transaction (see addons/integration_surface_sync.go).
type Emitter interface {
	Emit(ctx context.Context, eventType, aggregateID string, payload map[string]any) error
}

// Store is the minimal slice of *Repository the syncer uses; tests can fake.
type Store interface {
	Upsert(ctx context.Context, m *Manifest) error
	GetByName(ctx context.Context, name string) (*Manifest, error)
}

type SyncReport struct {
	SurfaceName string
	Action      string // "inserted" | "updated" | "noop"
	NewHash     string
	PrevHash    string
}

type Syncer struct {
	store Store
	bus   Emitter
}

func NewSyncer(s Store, bus Emitter) *Syncer { return &Syncer{store: s, bus: bus} }

type rawManifest struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name            string  `json:"name"`
		IntegrationType *string `json:"integration_type,omitempty"`
	} `json:"metadata"`
	Spec ManifestSpec `json:"spec"`
}

func (s *Syncer) ReconcileFromBytes(ctx context.Context, raw []byte) (SyncReport, error) {
	var rm rawManifest
	if err := json.Unmarshal(raw, &rm); err != nil {
		return SyncReport{}, fmt.Errorf("parse manifest: %w", err)
	}
	if rm.Kind != "integration_surface" {
		return SyncReport{}, fmt.Errorf("unexpected kind %q (must be integration_surface)", rm.Kind)
	}
	if rm.Metadata.Name == "" {
		return SyncReport{}, errors.New("metadata.name required")
	}

	specBytes, err := json.Marshal(rm.Spec)
	if err != nil {
		return SyncReport{}, err
	}
	sum := sha256.Sum256(specBytes)
	newHash := hex.EncodeToString(sum[:])

	existing, err := s.store.GetByName(ctx, rm.Metadata.Name)
	if errors.Is(err, ErrNotFound) {
		m := Manifest{
			Name:            rm.Metadata.Name,
			IntegrationType: rm.Metadata.IntegrationType,
			Category:        rm.Spec.Category,
			Spec:            rm.Spec,
			Active:          true,
		}
		if err := s.store.Upsert(ctx, &m); err != nil {
			return SyncReport{}, err
		}
		_ = s.bus.Emit(ctx, "integration_surface.registered", m.ID, map[string]any{
			"surface_name":     m.Name,
			"integration_type": m.IntegrationType,
			"category":         string(m.Category),
			"registered_at":    time.Now().UTC().Format(time.RFC3339),
			"spec":             unmarshalToMap(specBytes),
		})
		return SyncReport{SurfaceName: m.Name, Action: "inserted", NewHash: newHash}, nil
	}
	if err != nil {
		return SyncReport{}, err
	}

	prevBytes, _ := json.Marshal(existing.Spec)
	prevSum := sha256.Sum256(prevBytes)
	prevHash := hex.EncodeToString(prevSum[:])
	if prevHash == newHash {
		return SyncReport{SurfaceName: existing.Name, Action: "noop", NewHash: newHash, PrevHash: prevHash}, nil
	}

	existing.IntegrationType = rm.Metadata.IntegrationType
	existing.Category = rm.Spec.Category
	existing.Spec = rm.Spec
	if err := s.store.Upsert(ctx, existing); err != nil {
		return SyncReport{}, err
	}
	prevHashCopy := prevHash
	_ = s.bus.Emit(ctx, "integration_surface.updated", existing.ID, map[string]any{
		"surface_name":     existing.Name,
		"integration_type": existing.IntegrationType,
		"prev_spec_hash":   prevHashCopy,
		"new_spec_hash":    newHash,
		"updated_at":       time.Now().UTC().Format(time.RFC3339),
	})
	return SyncReport{SurfaceName: existing.Name, Action: "updated", NewHash: newHash, PrevHash: prevHash}, nil
}

func unmarshalToMap(b []byte) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}
