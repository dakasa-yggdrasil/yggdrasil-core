package model

// PaginationRequest is the optional input for paginated list RPCs.
// A zero-value request (empty cursor, zero limit) is valid and returns
// the first DefaultPullLimit items.
type PaginationRequest struct {
	// Cursor is an opaque string returned by a previous list call.
	// Empty string means "start from the beginning".
	Cursor string `json:"cursor,omitempty"`

	// Limit caps the number of items returned in this call. Values <= 0
	// are normalized to DefaultPaginationLimit; values > MaxPaginationLimit
	// are capped at MaxPaginationLimit.
	Limit int `json:"limit,omitempty"`

	// Sort selects one of the alternative sort orders the specific list
	// RPC supports. Empty string uses the default sort for that RPC.
	Sort string `json:"sort,omitempty"`
}

// PaginationResponse is included in every paginated list response.
// Callers pass NextCursor back in the following call and stop when
// HasMore is false.
type PaginationResponse struct {
	// NextCursor is the opaque cursor to pass in the next call to
	// continue from where this one left off. When HasMore is false,
	// NextCursor may be empty or equal to the input cursor.
	NextCursor string `json:"next_cursor"`

	// HasMore is true if there are more items available beyond NextCursor.
	// When false, this batch is the last one.
	HasMore bool `json:"has_more"`

	// TotalEstimate is an optional hint for UIs that want to show
	// "Showing 50 of ~400". When the RPC does not support a cheap
	// estimate, this field is omitted (left at zero).
	TotalEstimate int64 `json:"total_estimate,omitempty"`
}

// DefaultPaginationLimit is applied when the caller does not specify Limit
// in a list request.
const DefaultPaginationLimit = 100

// MaxPaginationLimit is the server-side cap for Limit in list requests.
// Values above this are normalized down.
const MaxPaginationLimit = 1000
