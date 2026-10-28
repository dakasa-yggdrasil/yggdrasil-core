//go:build linux && nativequalification

package main

import (
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"testing"
)

func TestSourceFailureDiagnosticClosed(t *testing.T) {
	for _, stage := range []string{"witness", "client", "transport", "http_pending", "http_unexpected", "decode", "validation", "record", "publish", "timeout"} {
		if sourceFailureDiagnosticStage(stage) != stage {
			t.Fatal("closed stage omitted", stage)
		}
	}
	for _, stage := range []string{"", "unexpected private material", "transport ", "HTTP_PENDING"} {
		if sourceFailureDiagnosticStage(stage) != "" {
			t.Fatal("unexpected stage admitted")
		}
	}
}

func TestSourceFailureHTTPDiagnosticClosed(t *testing.T) {
	for _, c := range []struct {
		r     capacity.GuestOriginalHTTPReturn
		stage string
	}{
		{capacity.GuestOriginalHTTPReturn{OriginalContextFailed: true, DoFailed: true}, "http_context"},
		{capacity.GuestOriginalHTTPReturn{PreflightFailed: true}, "http_preflight"},
		{capacity.GuestOriginalHTTPReturn{DoFailed: true}, "http_transport"},
		{capacity.GuestOriginalHTTPReturn{ReadFailed: true}, "http_read"},
		{capacity.GuestOriginalHTTPReturn{CloseFailed: true}, "http_close"},
		{capacity.GuestOriginalHTTPReturn{Status: 403}, "http_auth"},
		{capacity.GuestOriginalHTTPReturn{Status: 404}, "http_not_found"},
		{capacity.GuestOriginalHTTPReturn{Status: 409, ResponseBodyScope: capacity.GuestOriginalBodyCompleteRead}, "http_409_complete"},
		{capacity.GuestOriginalHTTPReturn{Status: 409}, "http_409_other"},
		{capacity.GuestOriginalHTTPReturn{Status: 400}, "http_client"},
		{capacity.GuestOriginalHTTPReturn{Status: 503}, "http_server"},
		{capacity.GuestOriginalHTTPReturn{Status: 302}, "http_other"},
	} {
		stage := sourceFailureHTTPStage(c.r, errors.New("private material"))
		if stage != c.stage || sourceFailureDiagnosticStage(stage) != stage {
			t.Fatal("HTTP classification refused", c.stage)
		}
	}
	if sourceFailureHTTPStage(capacity.GuestOriginalHTTPReturn{}, nil) != "" {
		t.Fatal("success classified as failure")
	}
}
