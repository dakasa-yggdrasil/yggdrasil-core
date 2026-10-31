//go:build linux && nativequalification

package main

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
)

// refusalPollDiagnostic describes only the already-returned source-refusal
// transport calls. It never retains a body, URL, credential, or error text,
// and it cannot establish why Guest did or did not publish a diagnostic.
type refusalPollDiagnostic struct {
	Schema              string    `json:"schema"`
	Case                string    `json:"native_case"`
	FirstReturnedAt     time.Time `json:"first_returned_at"`
	LastReturnedAt      time.Time `json:"last_returned_at"`
	Calls               int       `json:"calls"`
	StatusOK            int       `json:"status_200"`
	StatusConflict      int       `json:"status_409"`
	StatusOther         int       `json:"status_other"`
	StatusAbsent        int       `json:"status_absent"`
	CallErrors          int       `json:"call_errors"`
	PreflightFailures   int       `json:"preflight_failures"`
	DoFailures          int       `json:"do_failures"`
	ReadFailures        int       `json:"read_failures"`
	CloseFailures       int       `json:"close_failures"`
	ContextFailures     int       `json:"context_failures"`
	OuterContextFailed  bool      `json:"outer_context_failed"`
	ProductionQualified bool      `json:"production_qualified"`
}

func (d *refusalPollDiagnostic) observe(r capacity.GuestOriginalHTTPReturn, callErr error) {
	at := r.DriverReturnedAt
	if d.Calls == 0 {
		d.FirstReturnedAt = at
	}
	d.LastReturnedAt = at
	d.Calls++
	switch r.Status {
	case 0:
		d.StatusAbsent++
	case 200:
		d.StatusOK++
	case 409:
		d.StatusConflict++
	default:
		d.StatusOther++
	}
	if callErr != nil {
		d.CallErrors++
	}
	if r.PreflightFailed {
		d.PreflightFailures++
	}
	if r.DoFailed {
		d.DoFailures++
	}
	if r.ReadFailed {
		d.ReadFailures++
	}
	if r.CloseFailed {
		d.CloseFailures++
	}
	if r.OriginalContextFailed {
		d.ContextFailures++
	}
}

func (f *fixture) retainRefusalPollDiagnostic(ctx context.Context, d refusalPollDiagnostic, snapshot int) {
	if d.Case != "held_ack_after_owned_original_deadline" {
		return
	}
	d.OuterContextFailed = ctx.Err() != nil
	diagnostic, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	name := "core-refusal-poll-final.json"
	if snapshot >= 0 {
		name = fmt.Sprintf("core-refusal-poll-snapshot-%02d.json", snapshot)
	}
	_, _ = q.Publish(diagnostic, filepath.Join(f.private, name), d)
}
