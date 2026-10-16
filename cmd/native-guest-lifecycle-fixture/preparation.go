//go:build linux && nativequalification

package main

import (
	"context"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"path/filepath"
	"time"
)

// The owning frontend's source-only preparation precedes the FIRST native
// context. Core independently rereads its manifest and every compiled/static
// input before it emits a credential, reserves a preregistration or grants.
func verifyOriginalPreparation(ctx context.Context, private string, request q.SourceRequest) error {
	var raw map[string]json.RawMessage
	wire, err := q.ReadPrivate(ctx, filepath.Join(private, "original-source-preparation.json"), &raw)
	if err != nil || capacity.BusinessCreationSHA256(wire) != request.OriginalSourcePreparationSHA256 {
		return q.ErrOriginalUnknown
	}
	var header struct {
		Schema                string    `json:"schema"`
		Scope                 string    `json:"scope"`
		SourceCommit          string    `json:"source_commit"`
		CreatorSourceSHA256   string    `json:"creator_source_sha256"`
		Status                string    `json:"status"`
		PreparationStartedAt  time.Time `json:"preparation_started_at"`
		PreparationReturnedAt time.Time `json:"preparation_returned_at"`
		SourceFiles           map[string]struct {
			SHA256 string `json:"sha256"`
			Bytes  int64  `json:"bytes"`
		} `json:"source_files"`
	}
	if json.Unmarshal(wire, &header) != nil || header.Schema != "original_native_guest_source_preparation_v1" || header.Scope != "source_only_no_core_create_reservation_grant_admission" || header.SourceCommit != request.SourceCommit || header.CreatorSourceSHA256 != request.CreatorSourceSHA256 || header.Status != "SOURCE_PREPARED_NO_NATIVE_CAPACITY_QUALIFICATION" || header.PreparationStartedAt.IsZero() || header.PreparationReturnedAt.Before(header.PreparationStartedAt) || !header.PreparationReturnedAt.Before(request.OriginalStepStartedAt) {
		return q.ErrOriginalUnknown
	}
	required := []string{"approved-profile.json", "official-base.img", "static-user-data", "compiled-source/runtime-owner", "compiled-source/retirement-actor", "compiled-source/retirement-client", "compiled-source/bootstrap", "compiled-source/payload"}
	if len(header.SourceFiles) != len(required) {
		return q.ErrOriginalUnknown
	}
	for _, relative := range required {
		fact, ok := header.SourceFiles[relative]
		if !ok || !capacity.ValidDigest(fact.SHA256) || fact.Bytes < 1 {
			return q.ErrOriginalUnknown
		}
		limit := int64(128 << 20)
		if relative == "official-base.img" {
			limit = 2 << 30
		}
		hash, err := q.FileSHA(ctx, filepath.Join(private, relative), limit)
		if err != nil || hash != fact.SHA256 {
			return q.ErrOriginalUnknown
		}
	}
	return nil
}
