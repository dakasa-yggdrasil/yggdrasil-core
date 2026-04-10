package repository

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestEncodeDecodeCursor_RoundTrip(t *testing.T) {
	original := Cursor{
		LastID:        "018f2b4a-1234-7abc-def0-123456789012",
		LastSortValue: "2026-04-10T12:34:56Z",
		SortKey:       "created_at_desc",
	}

	encoded := EncodeCursor(original)
	if encoded == "" {
		t.Fatal("expected non-empty encoded cursor")
	}

	decoded, err := DecodeCursor(encoded)
	if err != nil {
		t.Fatalf("DecodeCursor: %v", err)
	}

	if decoded.LastID != original.LastID {
		t.Errorf("LastID mismatch: got %q, want %q", decoded.LastID, original.LastID)
	}
	if decoded.SortKey != original.SortKey {
		t.Errorf("SortKey mismatch: got %q, want %q", decoded.SortKey, original.SortKey)
	}
	if decoded.LastSortValue != original.LastSortValue {
		t.Errorf("LastSortValue mismatch: got %v, want %v", decoded.LastSortValue, original.LastSortValue)
	}
}

func TestEncodeCursor_EmptyReturnsEmptyString(t *testing.T) {
	if encoded := EncodeCursor(Cursor{}); encoded != "" {
		t.Errorf("expected empty string, got %q", encoded)
	}
}

func TestDecodeCursor_EmptyReturnsZeroValue(t *testing.T) {
	c, err := DecodeCursor("")
	if err != nil {
		t.Fatalf("DecodeCursor: %v", err)
	}
	if c.LastID != "" || c.LastSortValue != nil || c.SortKey != "" {
		t.Errorf("expected zero-value Cursor, got %+v", c)
	}
}

func TestDecodeCursor_InvalidBase64_ReturnsError(t *testing.T) {
	_, err := DecodeCursor("not-valid-base64!@#$")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestDecodeCursor_InvalidJSON_ReturnsError(t *testing.T) {
	// base64("not json at all")
	_, err := DecodeCursor("bm90IGpzb24gYXQgYWxs")
	if err == nil {
		t.Fatal("expected error for invalid JSON payload")
	}
}

func TestNormalizePagination_ZeroLimit_UsesDefault(t *testing.T) {
	req := model.PaginationRequest{Limit: 0}
	normalized := NormalizePagination(req)
	if normalized.Limit != model.DefaultPaginationLimit {
		t.Errorf("expected default limit %d, got %d", model.DefaultPaginationLimit, normalized.Limit)
	}
}

func TestNormalizePagination_NegativeLimit_UsesDefault(t *testing.T) {
	req := model.PaginationRequest{Limit: -5}
	normalized := NormalizePagination(req)
	if normalized.Limit != model.DefaultPaginationLimit {
		t.Errorf("expected default limit %d, got %d", model.DefaultPaginationLimit, normalized.Limit)
	}
}

func TestNormalizePagination_HugeLimit_Capped(t *testing.T) {
	req := model.PaginationRequest{Limit: 999999}
	normalized := NormalizePagination(req)
	if normalized.Limit != model.MaxPaginationLimit {
		t.Errorf("expected max limit %d, got %d", model.MaxPaginationLimit, normalized.Limit)
	}
}

func TestNormalizePagination_ValidLimit_Preserved(t *testing.T) {
	req := model.PaginationRequest{Limit: 250, Cursor: "abc", Sort: "name_asc"}
	normalized := NormalizePagination(req)
	if normalized.Limit != 250 {
		t.Errorf("expected limit 250, got %d", normalized.Limit)
	}
	if normalized.Cursor != "abc" {
		t.Errorf("cursor not preserved")
	}
	if normalized.Sort != "name_asc" {
		t.Errorf("sort not preserved")
	}
}
