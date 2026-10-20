package capacity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestGuestQualificationRefusalClosedProjection(t *testing.T) {
	cause := errors.New("SECRET SQL HTTP credential body")
	cases := []struct{ stage, predicate string }{
		{"observe", "original-guest-step-60"},
		{"lease_missing", "original-guest-step-61"},
		{"generation", "original-guest-step-62"},
		{"fence", "original-guest-step-63"},
		{"phase", "original-guest-step-64"},
		{"binding", "original-guest-step-65"},
		{"owned_slots", "original-guest-step-66"},
		{"member", "original-guest-step-67"},
		{"client", "original-guest-step-68"},
		{"probe", "original-guest-step-69"},
		{"fresh_native", "original-guest-step-70"},
		{"projection", "original-guest-step-71"},
		{"projection_encode", "original-guest-step-72"},
		{"record_slot", "original-guest-step-73"},
		{"advance_prepared", "original-guest-step-74"},
		{"advance_canary", "original-guest-step-75"},
		{"advance_promoted", "original-guest-step-76"},
		{"realm_profile", "original-guest-step-77"},
		{"enrollment", "original-guest-step-78"},
		{"key_writers", "original-guest-step-79"},
		{"deadline", "original-guest-step-80"},
		{"nonce", "original-guest-step-81"},
		{"signature", "original-guest-step-82"},
		{"request_encode", "original-guest-step-83"},
		{"reserve_probe", "original-guest-step-84"},
		{"probe_http", "original-guest-step-85"},
		{"probe_decode", "original-guest-step-86"},
		{"probe_validate", "original-guest-step-87"},
		{"finish_probe", "original-guest-step-88"},
		{"publish_probe", "original-guest-step-89"},
		{"probe_http_preflight", "original-guest-step-90"},
		{"probe_http_context", "original-guest-step-91"},
		{"probe_http_transport", "original-guest-step-92"},
		{"probe_http_read", "original-guest-step-93"},
		{"probe_http_close", "original-guest-step-94"},
		{"probe_http_auth_status", "original-guest-step-95"},
		{"probe_http_not_found", "original-guest-step-96"},
		{"probe_http_client_status", "original-guest-step-97"},
		{"probe_http_server_status", "original-guest-step-98"},
		{"probe_http_other_status", "original-guest-step-99"},
		{"arbitrary SECRET", "original-guest-step-17"},
		{"probe_http\nSECRET", "original-guest-step-17"},
		{"", "original-guest-step-17"},
	}
	for i, tc := range cases {
		t.Run(fmt.Sprintf("%02d", i), func(t *testing.T) {
			err := GuestQualificationRefusal(tc.stage, cause)
			if !errors.Is(err, cause) {
				t.Fatal("cause identity lost")
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatal("private text exposed")
			}
			if got := GuestQualificationPredicate(fmt.Errorf("outer: %w", err)); got != tc.predicate {
				t.Fatalf("got %q", got)
			}
		})
	}
	if GuestQualificationRefusal("probe_http", nil) != nil {
		t.Fatal("success changed")
	}
	for _, err := range []error{nil, cause, fmt.Errorf("original-guest-step-85: %w", cause)} {
		if GuestQualificationPredicate(err) != "original-guest-step-17" {
			t.Fatal("untyped error acquired stage")
		}
	}
}

func TestGuestQualificationHTTPRefusalClosedFacts(t *testing.T) {
	cause := errors.New("SECRET URL header body transport")
	cases := []struct {
		name  string
		facts GuestOriginalHTTPReturn
		code  string
	}{
		{"preflight", GuestOriginalHTTPReturn{PreflightFailed: true}, "90"},
		{"context_preflight", GuestOriginalHTTPReturn{OriginalContextFailed: true, PreflightFailed: true}, "91"},
		{"context_transport", GuestOriginalHTTPReturn{OriginalContextFailed: true, DoFailed: true}, "91"},
		{"transport", GuestOriginalHTTPReturn{DoFailed: true}, "92"},
		{"read_close", GuestOriginalHTTPReturn{ReadFailed: true, CloseFailed: true}, "93"},
		{"close_status", GuestOriginalHTTPReturn{CloseFailed: true, Status: 503}, "94"},
		{"unauthorized", GuestOriginalHTTPReturn{Status: 401}, "95"},
		{"forbidden", GuestOriginalHTTPReturn{Status: 403}, "95"},
		{"not_found", GuestOriginalHTTPReturn{Status: 404}, "96"},
		{"bad_request", GuestOriginalHTTPReturn{Status: 400}, "97"},
		{"conflict", GuestOriginalHTTPReturn{Status: 409}, "97"},
		{"server", GuestOriginalHTTPReturn{Status: 503}, "98"},
		{"redirect", GuestOriginalHTTPReturn{Status: 302}, "99"},
		{"no_status", GuestOriginalHTTPReturn{}, "99"},
		{"unknown", GuestOriginalHTTPReturn{Status: 200}, "85"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.facts.Body = []byte("SECRET body")
			err := GuestQualificationHTTPRefusal(tc.facts, cause)
			if !errors.Is(err, cause) || strings.Contains(err.Error(), "SECRET") || GuestQualificationPredicate(err) != "original-guest-step-"+tc.code {
				t.Fatal("closed original HTTP failure classification changed")
			}
			if GuestQualificationHTTPRefusal(tc.facts, nil) != nil {
				t.Fatal("diagnostic turned success into refusal")
			}
		})
	}
}

type qualificationHTTPRoundTrip func(*http.Request) (*http.Response, error)

func (f qualificationHTTPRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type qualificationHTTPBody struct {
	readError  bool
	closeError bool
}

func (b qualificationHTTPBody) Read(p []byte) (int, error) {
	if b.readError {
		return 0, errors.New("SECRET read")
	}
	return 0, io.EOF
}
func (b qualificationHTTPBody) Close() error {
	if b.closeError {
		return errors.New("SECRET close")
	}
	return nil
}

func TestGuestQualificationHTTPOriginalFailureFacts(t *testing.T) {
	for _, mode := range []string{"transport", "read", "close", "status", "context"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		calls := 0
		client := &GuestOriginalHTTPClient{origin: "https://example.invalid", client: &http.Client{Transport: qualificationHTTPRoundTrip(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.Method != http.MethodGet || r.URL.Path != "/v1/runtime-snapshot" {
				t.Fatal("original request changed")
			}
			if mode == "context" {
				cancel()
			}
			if mode == "transport" || mode == "context" {
				return nil, errors.New("SECRET transport")
			}
			status := 200
			if mode == "status" {
				status = 409
			}
			return &http.Response{StatusCode: status, Body: qualificationHTTPBody{readError: mode == "read", closeError: mode == "close"}, Header: make(http.Header)}, nil
		})}}
		returned, err := client.Original(ctx, http.MethodGet, "/v1/runtime-snapshot", []byte("{}"))
		cancel()
		want := map[string]string{"transport": "92", "read": "93", "close": "94", "status": "97", "context": "91"}[mode]
		if err == nil || calls != 1 || GuestQualificationPredicate(GuestQualificationHTTPRefusal(returned, err)) != "original-guest-step-"+want {
			t.Fatalf("original %s return lost or retried", mode)
		}
	}
}
