package message

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// TestReconcileProviderStateRequest_JSONRoundTrip verifies the model
// serialises and deserialises correctly with all optional fields.
func TestReconcileProviderStateRequest_JSONRoundTrip(t *testing.T) {
	req := model.ReconcileProviderStateRequest{
		Provider: "github",
		Users: []model.ReconcileProviderStateUser{
			{
				ExternalID:  "u-1",
				Email:       "alice@example.com",
				DisplayName: "Alice",
				ObservedState: map[string]any{
					"login":  "alice",
					"active": true,
				},
			},
			{
				ExternalID: "u-2",
				Email:      "bob@example.com",
			},
		},
	}

	encoded, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded model.ReconcileProviderStateRequest
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Provider != "github" {
		t.Errorf("provider = %q, want github", decoded.Provider)
	}
	if len(decoded.Users) != 2 {
		t.Fatalf("users len = %d, want 2", len(decoded.Users))
	}
	if decoded.Users[0].ExternalID != "u-1" {
		t.Errorf("users[0].external_id = %q, want u-1", decoded.Users[0].ExternalID)
	}
	if decoded.Users[0].Email != "alice@example.com" {
		t.Errorf("users[0].email = %q, want alice@example.com", decoded.Users[0].Email)
	}
	if decoded.Users[0].DisplayName != "Alice" {
		t.Errorf("users[0].display_name = %q, want Alice", decoded.Users[0].DisplayName)
	}
	observedLogin, _ := decoded.Users[0].ObservedState["login"].(string)
	if observedLogin != "alice" {
		t.Errorf("users[0].observed_state.login = %q, want alice", observedLogin)
	}
	if decoded.Users[1].DisplayName != "" {
		t.Errorf("users[1].display_name should be empty, got %q", decoded.Users[1].DisplayName)
	}
}

// TestReconcileProviderStateResponse_JSONRoundTrip verifies the response
// shape including the optional unmatched_emails slice.
func TestReconcileProviderStateResponse_JSONRoundTrip(t *testing.T) {
	resp := model.ReconcileProviderStateResponse{
		Provider:        "github",
		Matched:         3,
		UnmatchedEmails: []string{"orphan@provider.com"},
	}

	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded model.ReconcileProviderStateResponse
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Provider != "github" {
		t.Errorf("provider = %q, want github", decoded.Provider)
	}
	if decoded.Matched != 3 {
		t.Errorf("matched = %d, want 3", decoded.Matched)
	}
	if len(decoded.UnmatchedEmails) != 1 || decoded.UnmatchedEmails[0] != "orphan@provider.com" {
		t.Errorf("unmatched_emails = %v, want [orphan@provider.com]", decoded.UnmatchedEmails)
	}
}

// TestReconcileProviderStateResponse_NoUnmatched verifies the
// unmatched_emails field is omitted from JSON when empty (omitempty).
func TestReconcileProviderStateResponse_NoUnmatched(t *testing.T) {
	resp := model.ReconcileProviderStateResponse{
		Provider: "github",
		Matched:  5,
	}

	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}

	if _, exists := raw["unmatched_emails"]; exists {
		t.Error("unmatched_emails should be omitted when nil, but was present in JSON")
	}
}

// TestReconcileProviderStateRequest_EmptyUsersStillValid verifies that
// an empty users slice is accepted by the model (the handler returns
// matched=0 and no unmatched emails).
func TestReconcileProviderStateRequest_EmptyUsersStillValid(t *testing.T) {
	raw := `{"provider":"github","users":[]}`
	var req model.ReconcileProviderStateRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.Provider != "github" {
		t.Errorf("provider = %q, want github", req.Provider)
	}
	if len(req.Users) != 0 {
		t.Errorf("users len = %d, want 0", len(req.Users))
	}
}
