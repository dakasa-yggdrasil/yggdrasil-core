package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// seedPaginationTestManifests creates N valid product manifests under a given
// namespace for pagination tests. Cleans existing manifests in the namespace
// first so tests are repeatable.
func seedPaginationTestManifests(t *testing.T, db interface {
	Exec(query string, args ...any) (any, error)
}, namespace string, count int) {
	t.Helper()
}

func TestListManifestsPaginated_DefaultSort_ReturnsPageAndCursor(t *testing.T) {
	db := dbForEventTest(t)
	defer db.Close()

	ctx := context.Background()
	namespace := "pagination-test-default"

	// Clean and seed 5 manifests
	if _, err := db.Exec(`DELETE FROM public.manifests WHERE namespace = $1`, namespace); err != nil {
		t.Fatalf("clean manifests: %v", err)
	}

	for i := 0; i < 5; i++ {
		doc := model.ManifestDocument{
			APIVersion: "yggdrasil.io/v1alpha1",
			Kind:       "product",
			Metadata: model.ManifestMetadataInput{
				Namespace: namespace,
				Name:      fmt.Sprintf("product-%d", i),
			},
			Spec: json.RawMessage(`{"category":"application","class":"platform","lifecycle":{},"components":[]}`),
		}
		if _, err := CreateManifestVersion(ctx, db, doc, "sha256:aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999"); err != nil {
			t.Fatalf("seed manifest %d: %v", i, err)
		}
	}

	filters := model.ListManifestFilters{Namespace: namespace}

	// First page: limit 2
	manifests, pag, err := ListManifestsPaginated(ctx, db, filters, model.PaginationRequest{Limit: 2})
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(manifests) != 2 {
		t.Errorf("expected 2 in first page, got %d", len(manifests))
	}
	if !pag.HasMore {
		t.Error("expected has_more=true in first page")
	}
	if pag.NextCursor == "" {
		t.Error("expected non-empty next_cursor")
	}

	// Second page
	manifests2, pag2, err := ListManifestsPaginated(ctx, db, filters, model.PaginationRequest{Cursor: pag.NextCursor, Limit: 2})
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if len(manifests2) != 2 {
		t.Errorf("expected 2 in second page, got %d", len(manifests2))
	}
	if !pag2.HasMore {
		t.Error("expected has_more=true in second page")
	}

	// Third (last) page
	manifests3, pag3, err := ListManifestsPaginated(ctx, db, filters, model.PaginationRequest{Cursor: pag2.NextCursor, Limit: 2})
	if err != nil {
		t.Fatalf("third page: %v", err)
	}
	if len(manifests3) != 1 {
		t.Errorf("expected 1 in third page, got %d", len(manifests3))
	}
	if pag3.HasMore {
		t.Error("expected has_more=false in last page")
	}

	// Verify no duplicates across pages
	seen := map[string]bool{}
	for _, m := range append(append(manifests, manifests2...), manifests3...) {
		if seen[m.ID.String()] {
			t.Errorf("duplicate manifest id across pages: %s", m.ID)
		}
		seen[m.ID.String()] = true
	}
	if len(seen) != 5 {
		t.Errorf("expected 5 unique manifests, got %d", len(seen))
	}
}

func TestListManifestsPaginated_NameAscSort_ReturnsAlphabetical(t *testing.T) {
	db := dbForEventTest(t)
	defer db.Close()

	ctx := context.Background()
	namespace := "pagination-test-name"

	if _, err := db.Exec(`DELETE FROM public.manifests WHERE namespace = $1`, namespace); err != nil {
		t.Fatalf("clean: %v", err)
	}

	// Seed in unsorted order
	names := []string{"charlie", "alpha", "delta", "bravo"}
	for _, name := range names {
		doc := model.ManifestDocument{
			APIVersion: "yggdrasil.io/v1alpha1",
			Kind:       "product",
			Metadata: model.ManifestMetadataInput{
				Namespace: namespace,
				Name:      name,
			},
			Spec: json.RawMessage(`{"category":"application","class":"platform","lifecycle":{},"components":[]}`),
		}
		if _, err := CreateManifestVersion(ctx, db, doc, "sha256:aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999"); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	filters := model.ListManifestFilters{Namespace: namespace}

	// Pull all 4 in one page, name_asc
	manifests, _, err := ListManifestsPaginated(ctx, db, filters, model.PaginationRequest{Limit: 100, Sort: "name_asc"})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if len(manifests) != 4 {
		t.Fatalf("expected 4, got %d", len(manifests))
	}

	expected := []string{"alpha", "bravo", "charlie", "delta"}
	for i, m := range manifests {
		if m.Metadata.Name != expected[i] {
			t.Errorf("index %d: expected %q, got %q", i, expected[i], m.Metadata.Name)
		}
	}
}

func TestListManifestsPaginated_InvalidCursor_ReturnsError(t *testing.T) {
	db := dbForEventTest(t)
	defer db.Close()

	ctx := context.Background()
	_, _, err := ListManifestsPaginated(ctx, db, model.ListManifestFilters{}, model.PaginationRequest{
		Cursor: "not-a-valid-cursor-!@#",
		Limit:  10,
	})
	if err == nil {
		t.Fatal("expected error for invalid cursor")
	}
}

func TestListManifestsPaginated_EmptyResult_NoHasMore(t *testing.T) {
	db := dbForEventTest(t)
	defer db.Close()

	ctx := context.Background()
	namespace := "pagination-test-empty-nonexistent-12345"

	manifests, pag, err := ListManifestsPaginated(ctx, db, model.ListManifestFilters{Namespace: namespace}, model.PaginationRequest{Limit: 10})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if len(manifests) != 0 {
		t.Errorf("expected 0 manifests, got %d", len(manifests))
	}
	if pag.HasMore {
		t.Error("expected has_more=false")
	}
}
