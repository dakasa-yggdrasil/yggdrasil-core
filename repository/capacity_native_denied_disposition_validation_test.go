package repository

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

func nativeDeniedDeclaredCandidate() model.CapacityNativeDeniedCandidate {
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	raw, _ := json.Marshal(model.CapacityPolicySpec{Profiles: []model.CapacityProfile{{Name: "original", Provider: "aws", Region: "us-east-1"}}})
	return model.CapacityNativeDeniedCandidate{Original: model.CapacityOriginalCreateDispositionCandidate{OriginalPolicy: model.Manifest{Spec: raw}}, Request: model.CapacityNativeDeniedReadRequest{Schema: model.NativeDeniedReadRequestSchema, Profile: "original", Slot: 1, GrantID: uuid.NewString(), AttemptID: uuid.NewString(), RequestSHA256: strings.Repeat("a", 64), ScopeChecksum: strings.Repeat("b", 64), OriginalAdapterSourceCommit: nativeDeniedOriginalAWSCreator, GrantCreatedAt: at, SettlementObservedAt: at.Add(2 * time.Second), OriginalDeadline: at.Add(time.Minute)}}
}

// Reclose SHA/extent after each semantic counterexample. This tests the owning
// evidence joins rather than relying on corruption of a superficial hash.
func nativeDeniedMutateCT(t *testing.T, o *model.CapacityNativeDeniedObservation, change func(map[string]any, map[string]any)) {
	t.Helper()
	r := &o.NativeReads[1]
	raw, e := base64.StdEncoding.DecodeString(r.ResponseBodyBase64)
	if e != nil {
		t.Fatal(e)
	}
	var projection map[string]any
	if json.Unmarshal(raw, &projection) != nil {
		t.Fatal("projection")
	}
	page := projection["response"].(map[string]any)
	eventWrapper := page["Events"].([]any)[0].(map[string]any)
	var event map[string]any
	if json.Unmarshal([]byte(eventWrapper["CloudTrailEvent"].(string)), &event) != nil {
		t.Fatal("event")
	}
	change(projection, event)
	ev, _ := json.Marshal(event)
	eventWrapper["CloudTrailEvent"] = string(ev)
	raw, _ = json.Marshal(projection)
	r.ResponseBodyBase64 = base64.StdEncoding.EncodeToString(raw)
	r.ResponseBytes = int64(len(raw))
	r.ResponseSHA256 = originalDispositionDigest(raw)
}
func TestNativeDeniedDecisionProofRejectsReclosedForeignOrSuccessfulEvents(t *testing.T) {
	c := nativeDeniedDeclaredCandidate()
	o := nativeDeniedEvidence(t, c)
	now := time.Now().UTC()
	if e := validateNativeDeniedObservation(c, o, now, now, 30*time.Second); e != nil {
		t.Fatal("declared exact denied", e)
	}

	// A complete empty two-page EC2 census is legitimate, but an occupied second
	// page must never be hidden by the first empty page.
	two := nativeDeniedEvidence(t, c)
	last := two.NativeReads[2]
	first := last
	emptyRaw, _ := base64.StdEncoding.DecodeString(last.ResponseBodyBase64)
	pageRaw := bytes.Replace(emptyRaw, []byte("<reservationSet/>"), []byte("<reservationSet/><nextToken>page-two</nextToken>"), 1)
	first.ResponseBodyBase64 = base64.StdEncoding.EncodeToString(pageRaw)
	first.ResponseBytes = int64(len(pageRaw))
	first.ResponseSHA256 = originalDispositionDigest(pageRaw)
	last.CalledAt = last.CalledAt.Add(time.Millisecond)
	last.ReturnedAt = last.ReturnedAt.Add(time.Millisecond)
	two.NativeReads[2] = first
	two.NativeReads = append(two.NativeReads, last)
	if e := validateNativeDeniedObservation(c, two, now, now, 30*time.Second); e != nil {
		t.Fatal("complete empty two-page EC2 refused", e)
	}
	occupied := bytes.Replace(emptyRaw, []byte("<reservationSet/>"), []byte("<reservationSet><item><instancesSet><item><instanceId>i-present</instanceId></item></instancesSet></item></reservationSet>"), 1)
	two.NativeReads[3].ResponseBodyBase64 = base64.StdEncoding.EncodeToString(occupied)
	two.NativeReads[3].ResponseBytes = int64(len(occupied))
	two.NativeReads[3].ResponseSHA256 = originalDispositionDigest(occupied)
	if e := validateNativeDeniedObservation(c, two, now, now, 30*time.Second); e == nil {
		t.Fatal("occupied second EC2 page accepted")
	}
	for _, name := range []string{"accepted", "missing_original_error", "foreign_request", "foreign_token", "foreign_principal", "foreign_region", "foreign_account", "response_resource", "resources", "userdata", "retained_raw", "hashed_raw", "EOF_unknown", "CT_raw_alias", "STS_foreign", "empty_XML_missing", "original_HTTP_invented", "mutation", "duplicate_token_event", "pagination_unclosed", "wrong_source", "wrong_scope", "event_after_original", "missing_projection_flags"} {
		t.Run(name, func(t *testing.T) {
			x := nativeDeniedEvidence(t, c)
			switch name {
			case "CT_raw_alias":
				x.NativeReads[1].ResponseRepresentation = "raw_http_body_v1"
			case "STS_foreign":
				x.PrincipalARN = "arn:aws:iam::153828470928:user/other"
			case "empty_XML_missing":
				x.NativeReads[2].ResponseBodyBase64 = "eA=="
				x.NativeReads[2].ResponseBytes = 1
				x.NativeReads[2].ResponseSHA256 = originalDispositionDigest([]byte("x"))
			case "original_HTTP_invented":
				x.OriginalHTTPResponseAvailable = true
			case "mutation":
				x.NativeMutations = 1
			case "wrong_source":
				x.Request.OriginalAdapterSourceCommit = strings.Repeat("f", 40)
			case "wrong_scope":
				x.Request.ScopeChecksum = strings.Repeat("f", 64)
			default:
				nativeDeniedMutateCT(t, &x, func(p, e map[string]any) {
					switch name {
					case "accepted":
						delete(e, "errorCode")
						e["responseElements"] = map[string]any{"instancesSet": map[string]any{"items": []any{map[string]any{"instanceId": "i-not-denied"}}}}
					case "missing_original_error":
						delete(e, "errorCode")
					case "foreign_request":
						e["requestID"] = uuid.NewString()
					case "foreign_token":
						e["requestParameters"].(map[string]any)["clientToken"] = strings.Repeat("b", 64)
					case "foreign_principal":
						e["userIdentity"].(map[string]any)["arn"] = "arn:aws:iam::153828470928:user/other"
					case "foreign_region":
						e["awsRegion"] = "sa-east-1"
					case "foreign_account":
						e["recipientAccountId"] = "111111111111"
					case "response_resource":
						e["responseElements"] = map[string]any{"instanceId": "i-not-denied"}
					case "resources":
						e["resources"] = []any{map[string]any{"ARN": "arn:resource"}}
					case "userdata":
						e["requestParameters"].(map[string]any)["userData"] = "DECLARED_PRIVATE_BODY_MUST_NOT_ENTER_LEDGER"
					case "retained_raw":
						p["original_http_body_retained"] = true
					case "hashed_raw":
						p["original_http_body_hashed"] = true
					case "EOF_unknown":
						p["original_eof_and_close"] = false
					case "event_after_original":
						e["eventTime"] = c.Request.OriginalDeadline.Add(time.Hour).Format(time.RFC3339)
					case "missing_projection_flags":
						delete(p, "original_eof_and_close")
					case "duplicate_token_event":
						page := p["response"].(map[string]any)
						v := page["Events"].([]any)
						page["Events"] = append(v, v[0])
					case "pagination_unclosed":
						p["response"].(map[string]any)["NextToken"] = "unconsumed"
					}
				})
			}
			if e := validateNativeDeniedObservation(c, x, now, now, 30*time.Second); e == nil {
				t.Fatal("reclosed semantic forgery accepted", name)
			}
		})
	}
}
func TestNativeDeniedUniqueOriginalProjection(t *testing.T) {
	for _, raw := range []string{`{"outer":{"key":1,"key":2}}`, `{"a":1} {"b":2}`, `{"x":[{"a":0,"a":1}]}`} {
		if nativeDeniedUniqueJSON([]byte(raw)) {
			t.Fatal("duplicate/trailing accepted")
		}
	}
	if !nativeDeniedUniqueJSON([]byte(`{"Events":[],"NextToken":""}`)) {
		t.Fatal("valid bounded object")
	}
}
