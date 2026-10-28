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

func TestSourceFailureHTTPHistoryLastAndNoCall(t *testing.T) {
	var history sourceFailureHTTPHistory
	if history.calls != 0 || history.lastClass() != "no_call" {
		t.Fatal("missing no-call timeout classification")
	}
	for _, c := range []struct {
		r    capacity.GuestOriginalHTTPReturn
		want string
	}{
		{capacity.GuestOriginalHTTPReturn{Status: 409, ResponseBodyScope: capacity.GuestOriginalBodyCompleteRead}, "http_409_complete"},
		{capacity.GuestOriginalHTTPReturn{DoFailed: true}, "http_transport"},
		{capacity.GuestOriginalHTTPReturn{OriginalContextFailed: true, DoFailed: true}, "http_context"},
	} {
		if got := history.observe(c.r, errors.New("private material")); got != c.want || history.lastClass() != c.want {
			t.Fatal("last original return lost", c.want)
		}
	}
	if history.calls != 3 || history.lastClass() != "http_context" {
		t.Fatal("wrong original attempt count or final classification")
	}
	var unclassified sourceFailureHTTPHistory
	unclassified.observe(capacity.GuestOriginalHTTPReturn{}, nil)
	if unclassified.calls != 1 || unclassified.lastClass() != "unclassified" {
		t.Fatal("unclassified original return was invented")
	}
	// The diagnostic must never output arbitrary input as a classification.
	for _, bad := range []string{"private material", "timeout", "http_private"} {
		unclassified.last = bad
		if unclassified.lastClass() != "unclassified" {
			t.Fatal("arbitrary last stage admitted")
		}
	}
}
