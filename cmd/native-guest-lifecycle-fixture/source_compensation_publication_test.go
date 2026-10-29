//go:build linux && nativequalification

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
)

func TestOriginalSourceCleanupPublication(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	body := q.SourceFailureCleanupBody{
		NativeCase:              "compensation_unprotected_failed_create",
		CoreSource:              "core-source",
		GuestSource:             "guest-source",
		ParentGrantID:           "parent",
		AuthorityID:             "authority",
		Slot:                    2,
		IssuedAt:                now.Add(-time.Second),
		CleanupDeadline:         now.Add(time.Minute),
		OriginalContextDeadline: now.Add(2 * time.Minute),
	}
	wire := []byte(`{"body":"e30=","signature":"AA=="}`)
	dir := t.TempDir()
	if err := publishOriginalSourceCleanupAuthority(context.Background(), dir, wire, body, private); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "source-failure-cleanup-authority.json"))
	if err != nil || string(got) != string(wire) {
		t.Fatal("original authority bytes changed", err)
	}
	markerWire, err := os.ReadFile(filepath.Join(dir, "source-failure-cleanup-authority-publication.json"))
	if err != nil {
		t.Fatal(err)
	}
	var signed q.SourceFailureCleanupAuthority
	if err := json.Unmarshal(markerWire, &signed); err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(public, signed.Body, signature) {
		t.Fatal("publication marker is not signed by the source owner")
	}
	var marker originalSourceCleanupPublication
	if err := json.Unmarshal(signed.Body, &marker); err != nil {
		t.Fatal(err)
	}
	if marker.Schema != "original_source_cleanup_authority_publication_v1" || marker.Scope != "same_original_source_authority_publication_return_only" || marker.NativeCase != body.NativeCase || marker.CoreSource != body.CoreSource || marker.GuestSource != body.GuestSource || marker.ParentGrantID != body.ParentGrantID || marker.AuthorityID != body.AuthorityID || marker.AuthoritySHA256 != capacity.BusinessCreationSHA256(wire) || marker.Slot != 2 || marker.AuthorityPublishedAt.Before(now) || !marker.AuthorityPublishedAt.Before(body.CleanupDeadline) || !marker.CleanupDeadline.Equal(body.CleanupDeadline) || !marker.OriginalContextDeadline.Equal(body.OriginalContextDeadline) {
		t.Fatal("publication marker does not bind the original return")
	}
	blocked := t.TempDir()
	if err := os.WriteFile(filepath.Join(blocked, "source-failure-cleanup-authority.json"), wire, 0600); err != nil {
		t.Fatal(err)
	}
	if err := publishOriginalSourceCleanupAuthority(context.Background(), blocked, wire, body, private); err == nil {
		t.Fatal("replaced existing original authority")
	}
	if _, err := os.Stat(filepath.Join(blocked, "source-failure-cleanup-authority-publication.json")); !os.IsNotExist(err) {
		t.Fatal("marker created after failed authority publication")
	}
	canonical := t.TempDir()
	body.NativeCase = "canonical_compensation_unprotected_failed_create"
	if err := publishOriginalSourceCleanupAuthority(context.Background(), canonical, wire, body, private); err == nil {
		t.Fatal("canonical flow used noncanonical marker")
	}
	if _, err := os.Stat(filepath.Join(canonical, "source-failure-cleanup-authority.json")); !os.IsNotExist(err) {
		t.Fatal("canonical flow unexpectedly published authority")
	}
}
