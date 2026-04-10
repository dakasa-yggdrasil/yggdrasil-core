package repository

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Cursor is the internal (not-opaque) representation of a pagination cursor.
// Consumers should never construct or parse this directly — only pass the
// opaque string from PaginationResponse.NextCursor back in the next call.
type Cursor struct {
	// LastID is the last returned item's primary key (UUID).
	LastID string `json:"last_id"`

	// LastSortValue is the last returned item's value for the sort key.
	// May be any JSON-serializable type (string, number, timestamp as RFC3339).
	LastSortValue interface{} `json:"last_sort_value,omitempty"`

	// SortKey is the sort key active for this paginated query (matches the
	// PaginationRequest.Sort field used when encoding this cursor).
	SortKey string `json:"sort_key,omitempty"`
}

// EncodeCursor serializes a Cursor to an opaque base64 string for transport
// to callers. An empty Cursor (no LastID) returns an empty string.
func EncodeCursor(c Cursor) string {
	if c.LastID == "" && c.LastSortValue == nil {
		return ""
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// DecodeCursor parses an opaque cursor string back to a Cursor. Empty cursor
// strings decode to a zero-value Cursor (indicating "start from the beginning").
func DecodeCursor(s string) (Cursor, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Cursor{}, nil
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Cursor{}, fmt.Errorf("invalid cursor encoding: %w", err)
	}
	var c Cursor
	if err := json.Unmarshal(raw, &c); err != nil {
		return Cursor{}, fmt.Errorf("invalid cursor payload: %w", err)
	}
	return c, nil
}

// NormalizePagination applies default limit and caps the maximum limit
// for a PaginationRequest. Returns a copy with Limit guaranteed to be
// in [1, MaxPaginationLimit].
func NormalizePagination(req model.PaginationRequest) model.PaginationRequest {
	if req.Limit <= 0 {
		req.Limit = model.DefaultPaginationLimit
	}
	if req.Limit > model.MaxPaginationLimit {
		req.Limit = model.MaxPaginationLimit
	}
	return req
}
