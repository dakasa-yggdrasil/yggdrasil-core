package capacity

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// This small storage shape tests the exact byte decoder without importing a
// repository (and creating a capacity/repository cycle). These synthetic bytes
// and flags are grammar inputs, never an original native caller certificate.
type guestOriginalByteEnvelope struct {
	Body                  []byte `json:"body"`
	ReceivedBodyBytes     int    `json:"received_body_bytes"`
	BodyPersisted         bool   `json:"body_persisted"`
	ResponseSHA256        string `json:"response_sha256"`
	ReadFailed            bool   `json:"read_failed"`
	OriginalContextFailed bool   `json:"original_context_failed"`
}

func guestOriginalByteWire(t *testing.T, record guestOriginalByteEnvelope) []byte {
	t.Helper()
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestGuestOriginalClosedBytes(t *testing.T) {
	for _, test := range []struct {
		name string
		body []byte
	}{
		{"canonical_binary_roundtrip", []byte{0, 1, 2, 3, 254, 255}},
		{"canonical_more_than_array_limit", bytes.Repeat([]byte{0, 255}, 65)},
		{"bounded_large_body_preserves_bytes", bytes.Repeat([]byte{0xff}, GuestBootstrapLimit/2)},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := guestOriginalByteEnvelope{Body: test.body, ReceivedBodyBytes: len(test.body), BodyPersisted: true, ResponseSHA256: BusinessCreationSHA256(test.body)}
			raw := guestOriginalByteWire(t, original)
			var decoded guestOriginalByteEnvelope
			if DecodeGuestLifecycle(raw, &decoded) != nil || !bytes.Equal(decoded.Body, test.body) || decoded.ResponseSHA256 != BusinessCreationSHA256(decoded.Body) || decoded.ReceivedBodyBytes != len(test.body) || !decoded.BodyPersisted {
				t.Fatal("canonical bytes/count/hash were changed")
			}
		})
	}
	t.Run("nil_bytes_are_not_retained_empty", func(t *testing.T) {
		raw := guestOriginalByteWire(t, guestOriginalByteEnvelope{Body: nil, ResponseSHA256: BusinessCreationSHA256(nil)})
		var decoded guestOriginalByteEnvelope
		if DecodeGuestLifecycle(raw, &decoded) == nil {
			t.Fatal("null byte presence became an empty original body")
		}
	})
	t.Run("retained_empty_remains_empty", func(t *testing.T) {
		raw := guestOriginalByteWire(t, guestOriginalByteEnvelope{Body: []byte{}, BodyPersisted: true, ResponseSHA256: BusinessCreationSHA256([]byte{})})
		var decoded guestOriginalByteEnvelope
		if DecodeGuestLifecycle(raw, &decoded) != nil || decoded.Body == nil || len(decoded.Body) != 0 || !decoded.BodyPersisted || decoded.ReadFailed || decoded.OriginalContextFailed {
			t.Fatal("retained empty body or explicit false facts lost")
		}
	})
	t.Run("partial_metadata_keeps_empty_body_and_hash", func(t *testing.T) {
		prefix := []byte(`{"private-incomplete-prefix":`)
		original := guestOriginalByteEnvelope{Body: []byte{}, ReceivedBodyBytes: len(prefix), BodyPersisted: false, ResponseSHA256: BusinessCreationSHA256(prefix), ReadFailed: true, OriginalContextFailed: true}
		var decoded guestOriginalByteEnvelope
		if DecodeGuestLifecycle(guestOriginalByteWire(t, original), &decoded) != nil || decoded.Body == nil || len(decoded.Body) != 0 || decoded.ReceivedBodyBytes != len(prefix) || decoded.ResponseSHA256 != BusinessCreationSHA256(prefix) || decoded.BodyPersisted || !decoded.ReadFailed || !decoded.OriginalContextFailed {
			t.Fatal("partial metadata was relabeled as a complete empty return")
		}
	})
	for _, name := range []string{"partial_transport_never_decodes_complete", "canceled_transport_never_decodes_complete"} {
		t.Run(name, func(t *testing.T) {
			at := time.Date(2026, 10, 13, 1, 2, 3, 0, time.UTC)
			r := GuestOriginalHTTPReturn{StartedAt: at, DoStartedAt: at.Add(time.Millisecond), DoReturnedAt: at.Add(2 * time.Millisecond), ReadReturnedAt: at.Add(3 * time.Millisecond), CloseReturnedAt: at.Add(4 * time.Millisecond), DriverReturnedAt: at.Add(5 * time.Millisecond), Status: http.StatusOK, Body: guestOriginalByteWire(t, guestOriginalByteEnvelope{Body: []byte{}, ResponseSHA256: BusinessCreationSHA256([]byte{})})}
			r.ReceivedBodyBytes = len(r.Body)
			r.ResponseSHA256 = BusinessCreationSHA256(r.Body)
			r.ResponseBodyScope = GuestOriginalBodyCompleteRead
			r.RetainedPrefixBytes = len(r.Body)
			r.RetainedPrefixSHA256 = r.ResponseSHA256
			if name == "partial_transport_never_decodes_complete" {
				r.ReadFailed = true
			} else {
				r.OriginalContextFailed = true
			}
			var decoded guestOriginalByteEnvelope
			if GuestOriginalHTTPDecode(r, &decoded) == nil || decoded.Body != nil {
				t.Fatal("failed original transport promoted its bytes into a complete typed reply")
			}
		})
	}
	t.Run("named_byte_slice_is_not_specialcase", func(t *testing.T) {
		type namedBytes []byte
		var decoded struct {
			Body namedBytes `json:"body"`
		}
		if DecodeGuestLifecycle([]byte(`{"body":"AQ=="}`), &decoded) == nil {
			t.Fatal("exact byte exception widened to a distinct named slice")
		}
	})
	t.Run("exact_byte_alias_retains_specialcase", func(t *testing.T) {
		type sameBytes = []byte
		var decoded struct {
			Body sameBytes `json:"body"`
		}
		if DecodeGuestLifecycle([]byte(`{"body":"AQ=="}`), &decoded) != nil || !bytes.Equal(decoded.Body, []byte{1}) {
			t.Fatal("Go type alias no longer denotes exact []byte")
		}
	})
	base := guestOriginalByteWire(t, guestOriginalByteEnvelope{Body: []byte{1}, ReceivedBodyBytes: 1, BodyPersisted: true, ResponseSHA256: BusinessCreationSHA256([]byte{1})})
	for _, test := range []struct{ name, field string }{
		{"null_body", `null`}, {"numeric_array", `[1]`}, {"number_body", `1`}, {"object_body", `{}`}, {"bool_body", `false`},
		{"unpadded", `"AQ"`}, {"nonzero_pad_bits", `"AB=="`}, {"url_alphabet", `"_w=="`},
		{"embedded_lf", `"AQ==\n"`}, {"embedded_cr", `"AQ==\r"`}, {"embedded_tab", `"AQ==\t"`},
		{"json_literal_newline", "\"AQ==\n\""},
		{"encoded_oversize", `"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, GuestBootstrapLimit+1)) + `"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := bytes.Replace(base, []byte(`"body":"AQ=="`), []byte(`"body":`+test.field), 1)
			var decoded guestOriginalByteEnvelope
			if DecodeGuestLifecycle(raw, &decoded) == nil {
				t.Fatal("malformed/noncanonical byte representation accepted")
			}
		})
	}
	for _, name := range []string{"missing_body", "uppercase_alias", "duplicate_body", "unknown_field", "raw_wire_oversize", "trailing_object"} {
		t.Run(name, func(t *testing.T) {
			raw := append([]byte(nil), base...)
			switch name {
			case "missing_body":
				raw = bytes.Replace(raw, []byte(`"body":"AQ==",`), nil, 1)
			case "uppercase_alias":
				raw = bytes.Replace(raw, []byte(`"body":`), []byte(`"Body":`), 1)
			case "duplicate_body":
				raw = bytes.Replace(raw, []byte(`"body":"AQ=="`), []byte(`"body":"AQ==","body":"AQ=="`), 1)
			case "unknown_field":
				raw = append([]byte(`{"complete":true,`), raw[1:]...)
			case "raw_wire_oversize":
				raw = append(raw, []byte(strings.Repeat(" ", GuestBootstrapLimit))...)
			case "trailing_object":
				raw = append(raw, []byte(`{}`)...)
			}
			var decoded guestOriginalByteEnvelope
			if DecodeGuestLifecycle(raw, &decoded) == nil {
				t.Fatal("missing/aliased/extra original byte facts accepted")
			}
		})
	}
}

type guestOriginalFactsRoundTrip func(*http.Request) (*http.Response, error)

func (f guestOriginalFactsRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type guestOriginalFactsBody struct {
	reader io.Reader
	close  func() error
}

func (b guestOriginalFactsBody) Read(p []byte) (int, error) { return b.reader.Read(p) }
func (b guestOriginalFactsBody) Close() error               { return b.close() }

type guestOriginalPartialFactsReader struct{ returned bool }

func (r *guestOriginalPartialFactsReader) Read(p []byte) (int, error) {
	if r.returned {
		return 0, errors.New("same original body read refused")
	}
	r.returned = true
	return copy(p, []byte("partial-original")), errors.New("same original body read refused")
}

// Source driver IO cases exercise the real bounded ReadAll and Close calls.
// The injected transport is a source test seam, never native/capacity proof.
func TestGuestOriginalHTTPBoundedFacts(t *testing.T) {
	for _, name := range []string{"actual_complete_read", "actual_empty_eof", "actual_cap_plus_one_before_prefix", "actual_partial_read_error", "no_read_do_refusal", "no_read_preflight_refusal", "actual_close_refusal_after_eof", "actual_context_refusal_after_eof"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			raw := []byte(`{"value":"original"}`)
			if name == "actual_empty_eof" {
				raw = []byte{}
			}
			if name == "actual_cap_plus_one_before_prefix" {
				raw = append(bytes.Repeat([]byte{'x'}, GuestBootstrapLimit), 'z')
			}
			var reader io.Reader = bytes.NewReader(raw)
			if name == "actual_partial_read_error" {
				reader = &guestOriginalPartialFactsReader{}
				raw = []byte("partial-original")
			}
			closeCalls, doCalls := 0, 0
			client := &GuestOriginalHTTPClient{origin: "https://original.invalid", client: &http.Client{Transport: guestOriginalFactsRoundTrip(func(*http.Request) (*http.Response, error) {
				doCalls++
				if name == "no_read_do_refusal" {
					return nil, errors.New("original Do refused")
				}
				return &http.Response{StatusCode: 200, Body: guestOriginalFactsBody{reader, func() error {
					closeCalls++
					if name == "actual_context_refusal_after_eof" {
						cancel()
					}
					if name == "actual_close_refusal_after_eof" {
						return errors.New("original Close refused")
					}
					return nil
				}}}, nil
			})}}
			path := "/v1/retirement"
			if name == "no_read_preflight_refusal" {
				path = "/foreign"
			}
			returned, err := client.Original(ctx, http.MethodGet, path, []byte(`{}`))
			if !GuestOriginalHTTPBodyFactsValid(returned.ResponseBodyScope, returned.ReadReturnedAt, returned.ReceivedBodyBytes, returned.ResponseSHA256, returned.RetainedPrefixBytes, returned.RetainedPrefixSHA256, returned.ReadFailed) {
				t.Fatal("source body facts invalid")
			}
			if strings.HasPrefix(name, "no_read_") {
				if err == nil || closeCalls != 0 || !returned.ReadReturnedAt.IsZero() || returned.ResponseSHA256 != "" || returned.ResponseBodyScope != GuestOriginalBodyNoRead || returned.RetainedPrefixSHA256 != BusinessCreationSHA256([]byte{}) || (name == "no_read_preflight_refusal" && doCalls != 0) {
					t.Fatal("unavailable original body read became empty EOF")
				}
				return
			}
			prefix := raw[:min(len(raw), GuestBootstrapLimit)]
			if doCalls != 1 || closeCalls != 1 || returned.ReadReturnedAt.IsZero() || returned.CloseReturnedAt.Before(returned.ReadReturnedAt) || returned.DriverReturnedAt.Before(returned.CloseReturnedAt) || returned.ReceivedBodyBytes != len(raw) || returned.ResponseSHA256 != BusinessCreationSHA256(raw) || returned.RetainedPrefixBytes != len(prefix) || returned.RetainedPrefixSHA256 != BusinessCreationSHA256(prefix) || !bytes.Equal(returned.Body, prefix) {
				t.Fatal("actual read/prefix/Close facts changed")
			}
			incomplete := name == "actual_partial_read_error" || name == "actual_cap_plus_one_before_prefix"
			if incomplete != (returned.ResponseBodyScope == GuestOriginalBodyIncompleteRead) || incomplete != returned.ReadFailed {
				t.Fatal("partial original read was promoted")
			}
			if name == "actual_cap_plus_one_before_prefix" && returned.ResponseSHA256 == returned.RetainedPrefixSHA256 {
				t.Fatal("cap+1 last byte lost before digest")
			}
			valid := name == "actual_complete_read" || name == "actual_empty_eof"
			if (err == nil) != valid {
				t.Fatal("Close/context refusal changed original read scope")
			}
			if name == "actual_close_refusal_after_eof" && (!returned.CloseFailed || returned.ResponseBodyScope != GuestOriginalBodyCompleteRead) {
				t.Fatal("Close refusal erased complete read fact")
			}
			if name == "actual_context_refusal_after_eof" && (!returned.OriginalContextFailed || returned.ResponseBodyScope != GuestOriginalBodyCompleteRead) {
				t.Fatal("context refusal erased complete read fact")
			}
			var out struct {
				Value string `json:"value"`
			}
			if !valid && GuestOriginalHTTPDecode(returned, &out) == nil {
				t.Fatal("failed original IO admitted typed bytes")
			}
			if name == "actual_complete_read" && (GuestOriginalHTTPDecode(returned, &out) != nil || out.Value != "original") {
				t.Fatal("same original complete typed return rejected")
			}
		})
	}
}

func TestGuestOriginalHTTPClosedFactFields(t *testing.T) {
	type facts struct {
		ResponseBodyScope    string `json:"response_body_scope"`
		RetainedPrefixBytes  int    `json:"retained_prefix_bytes"`
		RetainedPrefixSHA256 string `json:"retained_prefix_sha256"`
	}
	base, _ := json.Marshal(facts{GuestOriginalBodyCompleteRead, 0, BusinessCreationSHA256([]byte{})})
	for _, name := range []string{"exact_three_fields", "missing_scope", "missing_prefix_count", "missing_prefix_hash", "scope_case_alias", "prefix_count_alias", "prefix_hash_alias", "unknown_fact", "duplicate_scope"} {
		t.Run(name, func(t *testing.T) {
			raw := append([]byte(nil), base...)
			switch name {
			case "missing_scope":
				raw = bytes.Replace(raw, []byte(`"response_body_scope":"complete_original_body_read",`), nil, 1)
			case "missing_prefix_count":
				raw = bytes.Replace(raw, []byte(`"retained_prefix_bytes":0,`), nil, 1)
			case "missing_prefix_hash":
				raw = bytes.Replace(raw, []byte(`,"retained_prefix_sha256":"`+BusinessCreationSHA256([]byte{})+`"`), nil, 1)
			case "scope_case_alias":
				raw = bytes.Replace(raw, []byte(`"response_body_scope"`), []byte(`"Response_Body_Scope"`), 1)
			case "prefix_count_alias":
				raw = bytes.Replace(raw, []byte(`"retained_prefix_bytes"`), []byte(`"Retained_Prefix_Bytes"`), 1)
			case "prefix_hash_alias":
				raw = bytes.Replace(raw, []byte(`"retained_prefix_sha256"`), []byte(`"Retained_Prefix_SHA256"`), 1)
			case "unknown_fact":
				raw = append([]byte(`{"complete":true,`), raw[1:]...)
			case "duplicate_scope":
				raw = append([]byte(`{"response_body_scope":"complete_original_body_read",`), raw[1:]...)
			}
			var out facts
			if (DecodeGuestLifecycle(raw, &out) == nil) != (name == "exact_three_fields") {
				t.Fatal("closed original facts widened")
			}
		})
	}
}
