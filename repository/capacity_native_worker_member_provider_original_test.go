package repository

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Independent copies of the concrete publisher DTOs, not the parser's types.
// HCloud has no nested permit_id/action; authenticated Receive joins the permit.
type nativeMemberProviderAWSPublisherFixture struct {
	Schema             string `json:"schema"`
	AttemptID          string `json:"attempt_id"`
	PermitID           string `json:"permit_id"`
	Action             string `json:"action"`
	HTTPStatus         int    `json:"http_status"`
	RequestID          string `json:"request_id"`
	TransportCompleted bool   `json:"transport_completed"`
	Body               []byte `json:"body"`
}

type nativeMemberProviderHCloudPublisherFixture struct {
	Schema             string `json:"schema"`
	AttemptID          string `json:"attempt_id"`
	HTTPStatus         int    `json:"http_status"`
	RequestID          string `json:"request_id"`
	RequestIDObserved  bool   `json:"request_id_observed"`
	TransportCompleted bool   `json:"transport_completed"`
	Body               []byte `json:"body"`
}

func nativeMemberProviderFixtureJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("publisher fixture cannot encode")
	}
	return raw
}

func nativeMemberProviderFixture(t *testing.T, provider string) (nativeWorkerAbortRecord, map[string]any) {
	t.Helper()
	p := model.CapacityNativeWorkerPhysical{
		ResourceID: "i-0123456789abcdef0", ProviderID: "aws:///us-east-1a/i-0123456789abcdef0",
		AccountID: "153828470928", InstanceType: "t3.small", NetworkID: "subnet-0123456789abcdef0",
		CreatedAt: time.Date(2026, 11, 28, 1, 2, 3, 0, time.UTC), ImageID: "ami-0123456789abcdef0",
		Region: "us-east-1", Zone: "us-east-1a", NativeIPv4: "10.0.0.12", MACAddress: "02:00:00:00:00:12",
		PhysicalSpecSHA256: strings.Repeat("d", 64), PhysicalBindingSHA256: strings.Repeat("e", 64), LaunchSHA256: strings.Repeat("f", 64),
	}
	prefix := "aws:///"
	if provider == "hetzner" {
		p.ResourceID, p.ProviderID, p.AccountID = "123456789", "hcloud://123456789", ""
		p.InstanceType, p.NetworkID, p.ImageID = "cax11", "12345", "123456"
		p.Region, p.Zone, prefix = "hel1", "hel1", "hcloud://"
	}
	a := model.CapacityNativeWorkerAttempt{
		ID: uuid.MustParse("6f305c12-bb9d-4c51-84b5-9fcf52485029"), Provider: provider,
		Region: p.Region, ProviderIDPrefix: prefix, SourceCommit: strings.Repeat("a", 40), PoolUID: "70000000-0000-4000-8000-000000000001", PoolEpoch: 7,
		Registry: model.CapacityNativePoolRegistryRef{Kind: "Lease", Namespace: "native-workers", Name: "native-registry", UID: "70000000-0000-4000-8000-000000000002"},
		Execution: model.CapacityNativeWorkerExecutionProfile{
			BindingName: "source-native-worker", SDKSourceCommit: strings.Repeat("b", 40),
			ScopeSHA256: strings.Repeat("c", 64), DestroyCapability: "destroy_native_worker",
		},
		Physical: &p, PhysicalSpecSHA256: p.PhysicalSpecSHA256, LaunchSHA256: p.LaunchSHA256,
	}
	c := model.CapacityNativeWorkerAbortPermit{
		Schema: model.CapacityNativeWorkerAbortSchema, PermitID: uuid.MustParse("9a374b75-2d63-44ed-b0bb-8b080a62b5fd"),
		AttemptID: a.ID, State: "received", BindingName: a.Execution.BindingName,
		SDKSourceCommit: a.Execution.SDKSourceCommit, ExecutionScopeSHA256: a.Execution.ScopeSHA256,
		Capability: a.Execution.DestroyCapability, PoolUID: a.PoolUID, PoolEpoch: a.PoolEpoch, Registry: a.Registry, Physical: p,
		// Historical custody after expiry grants no new provider send.
		ExpiresAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	tokenSHA := sha256.Sum256([]byte("fixture-consumed-once-private-bearer"))
	r := nativeWorkerAbortRecord{Context: c, Attempt: a, SourceCommit: a.SourceCommit, TokenSHA256: hex.EncodeToString(tokenSHA[:])}
	r.Original = &model.CapacityNativeWorkerAbortReceive{PermitID: c.PermitID, BindingName: c.BindingName, CaptureComplete: true}
	var published any = nativeMemberProviderAWSPublisherFixture{
		Schema: "aws_native_worker_delete_original_return_v1", AttemptID: a.ID.String(), PermitID: c.PermitID.String(), Action: "TerminateInstances",
		HTTPStatus: 200, RequestID: "aws-request-12", TransportCompleted: true, Body: []byte("<private-provider-return/>"),
	}
	if provider == "hetzner" {
		published = nativeMemberProviderHCloudPublisherFixture{
			Schema: "hcloud_native_worker_delete_original_return_v1", AttemptID: a.ID.String(), HTTPStatus: 200,
			RequestID: "hcloud.request:12_34-56", RequestIDObserved: true, TransportCompleted: true, Body: []byte(`{"action":{"status":"running"}}`),
		}
	}
	r.Original.OriginalReturn = nativeMemberProviderFixtureJSON(t, published)
	var fields map[string]any
	if err := json.Unmarshal(r.Original.OriginalReturn, &fields); err != nil {
		t.Fatal("publisher fixture JSON unavailable")
	}
	return r, fields
}

func TestNativeMemberProviderOriginalFramingIsNotEffectOrAbsence(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			published, _ := nativeMemberProviderFixture(t, provider)
			if !nativeMemberProviderOriginalComplete(published) {
				t.Fatal("exact independent publisher DTO held")
			}
			// Equivalent timestamp locations are the same physical birth. The
			// parser compares the instant, never Go's internal location pointer.
			published.Context.Physical.CreatedAt = published.Context.Physical.CreatedAt.In(time.FixedZone("fixture", 3600))
			if !nativeMemberProviderOriginalComplete(published) {
				t.Fatal("equal physical birth instant held for time representation")
			}
			// No HTTP status, including a complete 101 or 4xx/5xx, qualifies an
			// effect. This predicate checks only framing and private custody.
			for _, status := range []int{100, 101, 200, 202, 204, 302, 400, 403, 404, 409, 429, 500, 599} {
				t.Run(fmt.Sprint(status), func(t *testing.T) {
					r, fields := nativeMemberProviderFixture(t, provider)
					fields["http_status"], fields["body"] = status, []byte{0, 255, '<', '>', '{', '}', '\n'}
					r.Original.OriginalReturn = nativeMemberProviderFixtureJSON(t, fields)
					if !nativeMemberProviderOriginalComplete(r) {
						t.Fatal("complete framing held solely for HTTP status/body semantics")
					}
				})
			}
			for _, state := range []string{"received", "unknown", "observed"} {
				r, fields := nativeMemberProviderFixture(t, provider)
				r.Context.State = state
				fields["body"], fields["request_id"] = []byte{}, ""
				if provider == "hetzner" {
					fields["request_id_observed"] = false
					if _, exists := fields["permit_id"]; exists {
						t.Fatal("fixture invented a HCloud nested permit")
					}
				}
				r.Original.OriginalReturn = nativeMemberProviderFixtureJSON(t, fields)
				if !nativeMemberProviderOriginalComplete(r) {
					t.Fatalf("historical %s custody with empty body/request ID held", state)
				}
			}
		})
	}
}

func TestNativeMemberProviderOriginalRequiresCurrentCustodyJoins(t *testing.T) {
	cases := []struct {
		name string
		edit func(*nativeWorkerAbortRecord)
	}{
		{"missing-original", func(r *nativeWorkerAbortRecord) { r.Original = nil }},
		{"partial-capture", func(r *nativeWorkerAbortRecord) { r.Original.CaptureComplete = false }},
		{"outer-uncertain", func(r *nativeWorkerAbortRecord) { r.Original.ErrorClass = "ORIGINAL_TRANSPORT_UNCERTAIN" }},
		{"outer-overflow", func(r *nativeWorkerAbortRecord) { r.Original.ErrorClass = "ORIGINAL_CAPTURE_BOUND_EXCEEDED" }},
		{"wrong-context-schema", func(r *nativeWorkerAbortRecord) { r.Context.Schema = "native_worker_attempt_command_v1" }},
		{"zero-permit", func(r *nativeWorkerAbortRecord) { r.Context.PermitID = uuid.Nil; r.Original.PermitID = uuid.Nil }},
		{"outer-permit", func(r *nativeWorkerAbortRecord) {
			r.Original.PermitID = uuid.MustParse("30000000-0000-4000-8000-000000000001")
		}},
		{"attempt", func(r *nativeWorkerAbortRecord) {
			r.Context.AttemptID = uuid.MustParse("30000000-0000-4000-8000-000000000001")
		}},
		{"zero-attempt", func(r *nativeWorkerAbortRecord) { r.Attempt.ID = uuid.Nil; r.Context.AttemptID = uuid.Nil }},
		{"outer-binding", func(r *nativeWorkerAbortRecord) { r.Original.BindingName = "other-binding" }},
		{"context-binding", func(r *nativeWorkerAbortRecord) {
			r.Context.BindingName = "other-binding"
			r.Original.BindingName = "other-binding"
		}},
		{"empty-binding", func(r *nativeWorkerAbortRecord) {
			r.Context.BindingName = ""
			r.Original.BindingName = ""
			r.Attempt.Execution.BindingName = ""
		}},
		{"source-join", func(r *nativeWorkerAbortRecord) { r.SourceCommit = strings.Repeat("c", 40) }},
		{"source-invalid", func(r *nativeWorkerAbortRecord) {
			r.SourceCommit = "not-a-source"
			r.Attempt.SourceCommit = r.SourceCommit
		}},
		{"source-zero", func(r *nativeWorkerAbortRecord) {
			r.SourceCommit = strings.Repeat("0", 40)
			r.Attempt.SourceCommit = r.SourceCommit
		}},
		{"sdk-source-join", func(r *nativeWorkerAbortRecord) { r.Context.SDKSourceCommit = strings.Repeat("d", 40) }},
		{"sdk-source-invalid", func(r *nativeWorkerAbortRecord) {
			r.Context.SDKSourceCommit = strings.Repeat("B", 40)
			r.Attempt.Execution.SDKSourceCommit = r.Context.SDKSourceCommit
		}},
		{"sdk-source-zero", func(r *nativeWorkerAbortRecord) {
			r.Context.SDKSourceCommit = strings.Repeat("0", 40)
			r.Attempt.Execution.SDKSourceCommit = r.Context.SDKSourceCommit
		}},
		{"scope-join", func(r *nativeWorkerAbortRecord) { r.Context.ExecutionScopeSHA256 = strings.Repeat("d", 64) }},
		{"scope-invalid", func(r *nativeWorkerAbortRecord) {
			r.Context.ExecutionScopeSHA256 = "missing"
			r.Attempt.Execution.ScopeSHA256 = "missing"
		}},
		{"legacy-destroy", func(r *nativeWorkerAbortRecord) {
			r.Context.Capability = "destroy_server"
			r.Attempt.Execution.DestroyCapability = "destroy_server"
		}},
		{"capability-join", func(r *nativeWorkerAbortRecord) { r.Attempt.Execution.DestroyCapability = "destroy_other" }},
		{"missing-token-sha", func(r *nativeWorkerAbortRecord) { r.TokenSHA256 = "" }},
		{"noncanonical-token-sha", func(r *nativeWorkerAbortRecord) { r.TokenSHA256 = strings.Repeat("A", 64) }},
		{"plaintext-original-token", func(r *nativeWorkerAbortRecord) { r.Original.SettlementToken = "unconsumed" }},
		{"plaintext-context-token", func(r *nativeWorkerAbortRecord) { r.Context.SettlementToken = "unconsumed" }},
		{"redeemable-projection", func(r *nativeWorkerAbortRecord) { r.Context.Redeemable = true }},
		{"mutation-grant-projection", func(r *nativeWorkerAbortRecord) { r.Context.MutationPermitted = true }},
		{"missing-historical-deadline", func(r *nativeWorkerAbortRecord) { r.Context.ExpiresAt = time.Time{} }},
		{"pool-join", func(r *nativeWorkerAbortRecord) { r.Context.PoolUID = "other-pool" }},
		{"empty-pool", func(r *nativeWorkerAbortRecord) { r.Context.PoolUID = ""; r.Attempt.PoolUID = "" }},
		{"epoch-join", func(r *nativeWorkerAbortRecord) { r.Context.PoolEpoch++ }},
		{"zero-epoch", func(r *nativeWorkerAbortRecord) { r.Context.PoolEpoch = 0; r.Attempt.PoolEpoch = 0 }},
		{"registry-join", func(r *nativeWorkerAbortRecord) { r.Context.Registry.UID = "other-registry" }},
		{"no-physical", func(r *nativeWorkerAbortRecord) { r.Attempt.Physical = nil }},
		{"physical-join", func(r *nativeWorkerAbortRecord) { r.Context.Physical.NetworkID = "other-network" }},
		{"physical-birth", func(r *nativeWorkerAbortRecord) {
			r.Context.Physical.CreatedAt = r.Context.Physical.CreatedAt.Add(time.Second)
		}},
		{"missing-birth", func(r *nativeWorkerAbortRecord) {
			r.Context.Physical.CreatedAt = time.Time{}
			r.Attempt.Physical.CreatedAt = time.Time{}
		}},
		{"attempt-region", func(r *nativeWorkerAbortRecord) { r.Attempt.Region = "other-region" }},
		{"attempt-spec", func(r *nativeWorkerAbortRecord) { r.Attempt.PhysicalSpecSHA256 = strings.Repeat("a", 64) }},
		{"attempt-launch", func(r *nativeWorkerAbortRecord) { r.Attempt.LaunchSHA256 = strings.Repeat("a", 64) }},
		{"binding-invalid", func(r *nativeWorkerAbortRecord) {
			r.Context.Physical.PhysicalBindingSHA256 = ""
			r.Attempt.Physical.PhysicalBindingSHA256 = ""
		}},
		{"unknown-provider", func(r *nativeWorkerAbortRecord) { r.Attempt.Provider = "unmatched" }},
		{"provider-prefix", func(r *nativeWorkerAbortRecord) { r.Attempt.ProviderIDPrefix = "other://" }},
	}
	for _, provider := range []string{"aws", "hetzner"} {
		for _, tc := range cases {
			t.Run(provider+"/"+tc.name, func(t *testing.T) {
				r, _ := nativeMemberProviderFixture(t, provider)
				tc.edit(&r)
				if nativeMemberProviderOriginalComplete(r) {
					t.Fatal("unjoined or incomplete original qualified")
				}
			})
		}
		for _, state := range []string{"", "issued", "redeemed", "preparing", "no_effect", "rejected"} {
			t.Run(provider+"/state-"+state, func(t *testing.T) {
				r, _ := nativeMemberProviderFixture(t, provider)
				r.Context.State = state
				if nativeMemberProviderOriginalComplete(r) {
					t.Fatal("record without received custody state qualified")
				}
			})
		}
	}
}

func TestNativeMemberProviderOriginalRejectsUnmatchedOrMixedPublishers(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		other := "hetzner"
		if provider == "hetzner" {
			other = "aws"
		}
		t.Run(provider+"/other-wire", func(t *testing.T) {
			r, _ := nativeMemberProviderFixture(t, provider)
			mixed, _ := nativeMemberProviderFixture(t, other)
			r.Original.OriginalReturn = mixed.Original.OriginalReturn
			if nativeMemberProviderOriginalComplete(r) {
				t.Fatal("other provider wire qualified")
			}
		})
		t.Run(provider+"/unmatched-schema", func(t *testing.T) {
			r, fields := nativeMemberProviderFixture(t, provider)
			fields["schema"] = "native_worker_original_return_v1"
			r.Original.OriginalReturn = nativeMemberProviderFixtureJSON(t, fields)
			if nativeMemberProviderOriginalComplete(r) {
				t.Fatal("unmatched schema qualified")
			}
		})
	}
	for _, key := range []string{"permit_id", "action", "request", "settlement_token", "capture_complete", "original_return"} {
		t.Run("hcloud/invented-"+key, func(t *testing.T) {
			r, fields := nativeMemberProviderFixture(t, "hetzner")
			fields[key] = "invented"
			r.Original.OriginalReturn = nativeMemberProviderFixtureJSON(t, fields)
			if nativeMemberProviderOriginalComplete(r) {
				t.Fatal("invented HCloud member qualified")
			}
		})
	}
	for _, tc := range []struct{ provider, id, providerID, account, zone string }{
		{"aws", "i-short", "aws:///us-east-1a/i-short", "153828470928", "us-east-1a"},
		{"aws", "i-0123456789abcdef0", "hcloud://123456789", "153828470928", "us-east-1a"},
		{"aws", "i-0123456789abcdef0", "aws:///us-east-1b/i-0123456789abcdef0", "153828470928", "us-east-1a"},
		{"hetzner", "0123456789", "hcloud://0123456789", "", "hel1"},
		{"hetzner", "-1", "hcloud://-1", "", "hel1"},
		{"hetzner", "0", "hcloud://0", "", "hel1"},
		{"hetzner", "9223372036854775808", "hcloud://9223372036854775808", "", "hel1"},
		{"hetzner", "123456789", "aws:///hel1/i-0123456789abcdef0", "", "hel1"},
		{"hetzner", "123456789", "hcloud://123456789", "invented-project-account", "hel1"},
		{"hetzner", "123456789", "hcloud://123456789", "", "nbg1"},
	} {
		t.Run(tc.provider+"/physical-"+tc.id+"-"+tc.zone+"-"+tc.account, func(t *testing.T) {
			r, _ := nativeMemberProviderFixture(t, tc.provider)
			p := *r.Attempt.Physical
			p.ResourceID, p.ProviderID, p.AccountID, p.Zone = tc.id, tc.providerID, tc.account, tc.zone
			r.Attempt.Physical, r.Context.Physical = &p, p
			if nativeMemberProviderOriginalComplete(r) {
				t.Fatal("noncanonical or mixed provider physical identity qualified")
			}
		})
	}
}

func TestNativeMemberProviderOriginalStrictFraming(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		_, originalFields := nativeMemberProviderFixture(t, provider)
		for key := range originalFields {
			for _, operation := range []string{"missing", "null"} {
				t.Run(provider+"/"+operation+"-"+key, func(t *testing.T) {
					r, fields := nativeMemberProviderFixture(t, provider)
					if operation == "missing" {
						delete(fields, key)
					} else {
						fields[key] = nil
					}
					r.Original.OriginalReturn = nativeMemberProviderFixtureJSON(t, fields)
					if nativeMemberProviderOriginalComplete(r) {
						t.Fatal("missing/null actual publisher member qualified")
					}
				})
			}
		}
		cases := []struct {
			name string
			wire func([]byte) []byte
		}{
			{"empty", func([]byte) []byte { return nil }},
			{"empty-object", func([]byte) []byte { return []byte(`{}`) }},
			{"null-root", func([]byte) []byte { return []byte(`null`) }},
			{"array-root", func(raw []byte) []byte { return append(append([]byte{'['}, raw...), ']') }},
			{"truncated", func(raw []byte) []byte { return raw[:len(raw)-1] }},
			{"trailing-object", func(raw []byte) []byte { return append(raw, []byte(` {}`)...) }},
			{"trailing-null", func(raw []byte) []byte { return append(raw, []byte(` null`)...) }},
			{"duplicate-schema", func(raw []byte) []byte { return append(raw[:len(raw)-1], []byte(`,"schema":"other"}`)...) }},
			{"duplicate-escaped-schema", func(raw []byte) []byte { return append(raw[:len(raw)-1], []byte(`,"schem\u0061":"other"}`)...) }},
			{"case-alias", func(raw []byte) []byte { return bytes.Replace(raw, []byte(`"schema"`), []byte(`"Schema"`), 1) }},
			{"unknown-member", func(raw []byte) []byte { return append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...) }},
			{"oversize-wire", func(raw []byte) []byte {
				return append(raw, bytes.Repeat([]byte{' '}, nativeMemberProviderWireLimit+1-len(raw))...)
			}},
		}
		for _, tc := range cases {
			t.Run(provider+"/"+tc.name, func(t *testing.T) {
				r, _ := nativeMemberProviderFixture(t, provider)
				r.Original.OriginalReturn = tc.wire(r.Original.OriginalReturn)
				if nativeMemberProviderOriginalComplete(r) {
					t.Fatal("malformed or ambiguous framing qualified")
				}
			})
		}
		for _, tc := range []struct {
			name, key string
			value     any
		}{
			{"body-array", "body", json.RawMessage(`[1,2,3]`)},
			{"body-object", "body", map[string]any{"secret": true}},
			{"body-invalid-base64", "body", "%%%"},
			{"body-noncanonical-base64", "body", "YQ==\n"},
			{"body-overbound", "body", bytes.Repeat([]byte{'x'}, nativeMemberProviderBodyLimit+1)},
			{"status-string", "http_status", "200"},
			{"status-fraction", "http_status", 200.5},
			{"status-zero", "http_status", 0},
			{"status-low", "http_status", 99},
			{"status-high", "http_status", 600},
			{"transport-incomplete", "transport_completed", false},
			{"transport-string", "transport_completed", "true"},
			{"attempt-other", "attempt_id", "30000000-0000-4000-8000-000000000001"},
			{"attempt-case-alias", "attempt_id", strings.ToUpper("6f305c12-bb9d-4c51-84b5-9fcf52485029")},
			{"request-id-type", "request_id", 12},
			{"request-id-newline", "request_id", "bad\nrequest"},
			{"request-id-unicode", "request_id", "request-ç"},
			{"request-id-oversize", "request_id", strings.Repeat("a", 257)},
		} {
			t.Run(provider+"/"+tc.name, func(t *testing.T) {
				r, fields := nativeMemberProviderFixture(t, provider)
				fields[tc.key] = tc.value
				r.Original.OriginalReturn = nativeMemberProviderFixtureJSON(t, fields)
				if nativeMemberProviderOriginalComplete(r) {
					t.Fatal("invalid typed/bounded original qualified")
				}
			})
		}
	}
}

func TestNativeMemberProviderOriginalPublisherSpecificJoins(t *testing.T) {
	for _, tc := range []struct {
		provider, name, key string
		value               any
	}{
		{"aws", "permit-join", "permit_id", "30000000-0000-4000-8000-000000000001"},
		{"aws", "action-join", "action", "StopInstances"},
		{"aws", "hcloud-request-id-charset", "request_id", "request.id"},
		{"aws", "request-id-overbound", "request_id", strings.Repeat("a", 129)},
		{"aws", "hcloud-only-member", "request_id_observed", true},
		{"hetzner", "request-id-unobserved", "request_id_observed", false},
		{"hetzner", "observed-id-empty", "request_id", ""},
		{"hetzner", "observed-type", "request_id_observed", "true"},
	} {
		t.Run(tc.provider+"/"+tc.name, func(t *testing.T) {
			r, fields := nativeMemberProviderFixture(t, tc.provider)
			fields[tc.key] = tc.value
			r.Original.OriginalReturn = nativeMemberProviderFixtureJSON(t, fields)
			if nativeMemberProviderOriginalComplete(r) {
				t.Fatal("publisher-specific framing/identity mismatch qualified")
			}
		})
	}
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider+"/exact-bounds-and-no-mutation", func(t *testing.T) {
			r, fields := nativeMemberProviderFixture(t, provider)
			fields["body"] = bytes.Repeat([]byte{'p'}, nativeMemberProviderBodyLimit)
			limit := 128
			if provider == "hetzner" {
				limit = 256
			}
			fields["request_id"] = strings.Repeat("a", limit)
			r.Original.OriginalReturn = nativeMemberProviderFixtureJSON(t, fields)
			if len(r.Original.OriginalReturn) > nativeMemberProviderWireLimit {
				t.Fatal("actual publisher body bound exceeds wire bound")
			}
			// Preserve retained original bytes even at the exact envelope bound;
			// harmless JSON whitespace/order does not invent a different identity.
			r.Original.OriginalReturn = append(r.Original.OriginalReturn, bytes.Repeat([]byte{' '}, nativeMemberProviderWireLimit-len(r.Original.OriginalReturn))...)
			before := r
			physicalCopy, originalCopy := *r.Attempt.Physical, *r.Original
			originalCopy.OriginalReturn = append([]byte(nil), r.Original.OriginalReturn...)
			before.Attempt.Physical, before.Original = &physicalCopy, &originalCopy
			if !nativeMemberProviderOriginalComplete(r) {
				t.Fatal("actual publisher body/request-ID/envelope boundary held")
			}
			if !reflect.DeepEqual(r, before) {
				t.Fatal("pure parser changed retained custody/attempt")
			}
		})
	}
}

func TestNativeMemberProviderOriginalPrivateMirrorsCannotPublishBody(t *testing.T) {
	const body = "private-provider-body-sentinel"
	for _, value := range []any{
		nativeMemberAWSDeleteOriginal{Body: []byte(body), RequestID: body},
		nativeMemberHCloudDeleteOriginal{Body: []byte(body), RequestID: body},
	} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if strings.Contains(fmt.Sprintf(format, value), body) {
				t.Fatal("private original leaked through ordinary formatting")
			}
		}
		if raw, err := json.Marshal(value); err == nil || len(raw) != 0 {
			t.Fatal("private original became public JSON")
		}
	}
}
