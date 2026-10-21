package capacity

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestOriginalHetznerActualTLSCrossImport(t *testing.T) {
	path := os.Getenv("ORIGINAL_CREATE_RETURN_CROSS_IMPORT")
	if path == "" {
		t.Skip("owning CI may provide actual adapter TLS unit return; no production or SQL authority")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, 65537))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || len(raw) > 65536 {
		t.Fatal("bounded cross fixture read failed", readErr, closeErr)
	}
	var input struct {
		Scope      string                                     `json:"scope"`
		Return     model.CapacityOriginalProviderCreateReturn `json:"return"`
		ReservedAt string                                     `json:"reserved_at"`
	}
	if err = json.Unmarshal(raw, &input); err != nil || input.Scope != "unit_actual_tls_original_only_no_SQL_authority" {
		t.Fatal("actual TLS cross fixture invalid", err)
	}
	o := input.Return
	reserved, err := time.Parse(time.RFC3339Nano, input.ReservedAt)
	if err != nil {
		t.Fatal(err)
	}
	expires, err := time.Parse(time.RFC3339Nano, o.ContextDeadline)
	if err != nil {
		t.Fatal(err)
	}
	instance := uuid.NewString()
	b := model.CapacityMutationBinding{OriginalProviderSourceCommit: o.AdapterSourceCommit, Name: "unit-binding", IntegrationInstanceID: instance, ScopeChecksum: strings.Repeat("f", 64), ProfileName: "unit-profile", EnsureCapability: "ensure_server"}
	g := model.CapacityMutationGrant{GrantID: o.GrantID, BindingName: b.Name, IntegrationInstanceID: instance, ScopeChecksum: b.ScopeChecksum, ProfileName: b.ProfileName, Capability: b.EnsureCapability, RequestSHA256: o.RequestSHA256, State: "redeemed", Slot: 1, ExpiresAt: expires}
	now := time.Now().UTC()
	r := model.CapacityMutationSettleRequest{OriginalProviderCreateReturn: &o, GrantID: o.GrantID, AttemptID: o.AttemptID, RequestSHA256: o.RequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: o.ResourceID, ResourceCreatedAt: o.ResourceCreatedAt, ActionID: o.ActionID, NextActionIDs: o.NextActionIDs, ObservedAt: now.Format(time.RFC3339Nano)}
	if _, err = ValidateOriginalHetznerCreateReturn(b, g, o.AttemptID, r, reserved, now); err != nil {
		t.Fatal("actual standalone adapter TLS return failed Core wire validation", err)
	}
}

// This pure envelope validation is not an authenticated callback or SQL grant.
// The separate adapter TLS test produces a return from its actual Do/Read/Close.
func originalProviderEnvelopeFixture() (model.CapacityMutationBinding, model.CapacityMutationGrant, model.CapacityMutationSettleRequest, time.Time, time.Time) {
	now := time.Now().UTC()
	reserved := now.Add(-time.Second)
	b := model.CapacityMutationBinding{OriginalProviderSourceCommit: strings.Repeat("a", 40), Name: "servers", IntegrationInstanceID: uuid.NewString(), ScopeChecksum: strings.Repeat("b", 64), ProfileName: "worker", EnsureCapability: "ensure_server"}
	g := model.CapacityMutationGrant{GrantID: uuid.NewString(), BindingName: b.Name, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileName: b.ProfileName, Capability: b.EnsureCapability, Slot: 1, RequestSHA256: strings.Repeat("c", 64), State: "redeemed", ExpiresAt: now.Add(time.Minute)}
	r := model.CapacityMutationSettleRequest{GrantID: g.GrantID, AttemptID: uuid.NewString(), RequestSHA256: g.RequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: "100", ResourceCreatedAt: reserved.Format(time.RFC3339Nano), ActionID: "500", NextActionIDs: []string{"501"}, ObservedAt: now.Format(time.RFC3339Nano)}
	r.OriginalProviderCreateReturn = &model.CapacityOriginalProviderCreateReturn{Schema: "hetzner_original_create_return_v1", Provider: "hetzner", AdapterSourceCommit: b.OriginalProviderSourceCommit, GrantID: g.GrantID, AttemptID: r.AttemptID, RequestSHA256: g.RequestSHA256, ResourceID: r.ResourceID, ResourceCreatedAt: r.ResourceCreatedAt, ActionID: r.ActionID, NextActionIDs: []string{"501"}, CalledAt: reserved.Add(time.Millisecond).Format(time.RFC3339Nano), ReturnedAt: reserved.Add(2 * time.Millisecond).Format(time.RFC3339Nano), ContextDeadline: g.ExpiresAt.Format(time.RFC3339Nano), ResponseStatus: 201, ResponseBodySHA256: strings.Repeat("d", 64), ResponseBytes: 100}
	return b, g, r, reserved, now
}

func TestOriginalHetznerCreateReturnEnvelope(t *testing.T) {
	for _, name := range []string{"original", "missing", "source", "no_pin", "grant", "attempt", "request", "resource", "actions", "schema", "provider", "uncertain", "incomplete", "early_call", "inverted_return", "late_return", "renewed_deadline", "body_limit", "body_hash", "status", "compensation"} {
		t.Run(name, func(t *testing.T) {
			b, g, r, reserved, now := originalProviderEnvelopeFixture()
			o := r.OriginalProviderCreateReturn
			switch name {
			case "missing":
				r.OriginalProviderCreateReturn = nil
			case "source":
				o.AdapterSourceCommit = strings.Repeat("e", 40)
			case "no_pin":
				b.OriginalProviderSourceCommit = ""
			case "grant":
				o.GrantID = uuid.NewString()
			case "attempt":
				o.AttemptID = uuid.NewString()
			case "request":
				o.RequestSHA256 = strings.Repeat("e", 64)
			case "resource":
				o.ResourceCreatedAt = reserved.Add(-time.Hour).Format(time.RFC3339Nano)
			case "actions":
				o.NextActionIDs = []string{"500"}
			case "schema":
				o.Schema = "observation"
			case "provider":
				o.Provider = "aws"
			case "uncertain":
				r.Outcome = "uncertain"
			case "incomplete":
				r.TransportCompleted = false
			case "early_call":
				o.CalledAt = reserved.Add(-time.Nanosecond).Format(time.RFC3339Nano)
			case "inverted_return":
				o.ReturnedAt = reserved.Format(time.RFC3339Nano)
			case "late_return":
				o.ReturnedAt = g.ExpiresAt.Format(time.RFC3339Nano)
			case "renewed_deadline":
				o.ContextDeadline = g.ExpiresAt.Add(time.Second).Format(time.RFC3339Nano)
			case "body_limit":
				o.ResponseBytes = (2 << 20) + 1
			case "body_hash":
				o.ResponseBodySHA256 = "unbound"
			case "status":
				o.ResponseStatus = 200
			case "compensation":
				g.CompensationOf = uuid.NewString()
			}
			returned, err := ValidateOriginalHetznerCreateReturn(b, g, r.AttemptID, r, reserved, now)
			if (err == nil) != (name == "original") {
				t.Fatalf("unexpected original return admission for %s: %v", name, err)
			}
			if err == nil && returned.UTC().Format(time.RFC3339Nano) != o.ReturnedAt {
				t.Fatal("original timestamp was restamped")
			}
		})
	}
}

func TestOriginalProviderReturnClosedJSON(t *testing.T) {
	_, _, r, _, _ := originalProviderEnvelopeFixture()
	raw, err := json.Marshal(r.OriginalProviderCreateReturn)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"original", "duplicate", "case_folded", "unknown", "missing", "null", "oversized"} {
		t.Run(name, func(t *testing.T) {
			body := string(raw)
			switch name {
			case "duplicate":
				body = strings.Replace(body, `"provider":"hetzner"`, `"provider":"hetzner","provider":"hetzner"`, 1)
			case "case_folded":
				body = strings.Replace(body, `"provider"`, `"Provider"`, 1)
			case "unknown":
				body = strings.TrimSuffix(body, "}") + `,"admission_opened":true}`
			case "missing":
				body = strings.Replace(body, `"provider":"hetzner",`, "", 1)
			case "null":
				body = strings.Replace(body, `"next_action_ids":["501"]`, `"next_action_ids":null`, 1)
			case "oversized":
				body = strings.Repeat(" ", 16385)
			}
			var parsed model.CapacityOriginalProviderCreateReturn
			if (json.Unmarshal([]byte(body), &parsed) == nil) != (name == "original") {
				t.Fatal("closed original return shape mismatch")
			}
		})
	}
}
