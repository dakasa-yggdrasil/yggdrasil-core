//go:build linux && nativequalification

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type originalPublicReturn struct {
	DoStartedAt           time.Time `json:"do_started_at"`
	DriverReturnedAt      time.Time `json:"driver_returned_at"`
	PreflightFailed       bool      `json:"preflight_failed"`
	DoFailed              bool      `json:"do_failed"`
	ReadFailed            bool      `json:"read_failed"`
	CloseFailed           bool      `json:"close_failed"`
	Method                string    `json:"method"`
	Path                  string    `json:"path"`
	StartedAt             time.Time `json:"started_at"`
	DoReturnedAt          time.Time `json:"do_returned_at"`
	ReadReturnedAt        time.Time `json:"read_returned_at"`
	CloseReturnedAt       time.Time `json:"close_returned_at"`
	Status                int       `json:"status"`
	BodySHA256            string    `json:"body_sha256"`
	BodyBytes             int       `json:"body_bytes"`
	OriginalContextFailed bool      `json:"original_context_failed"`
	WorkflowStatus        string    `json:"workflow_status"`
	WorkflowFailedStep    string    `json:"workflow_failed_step"`
	WorkflowPredicate     string    `json:"workflow_predicate"`
	WorkflowErrorClass    string    `json:"workflow_error_class"`
	WorkflowErrorBytes    int       `json:"workflow_error_bytes"`
	WorkflowErrorSHA256   string    `json:"workflow_error_sha256"`
}

func (f *fixture) originalPublic(ctx context.Context, method, path string, input, out any) (record originalPublicReturn, returnedErr error) {
	record = originalPublicReturn{Method: method, Path: path, StartedAt: time.Now().UTC()}
	defer func() {
		record.DriverReturnedAt = time.Now().UTC()
		record.OriginalContextFailed = ctx.Err() != nil
		if run, ok := out.(*model.WorkflowRunRecord); ok && returnedErr == nil {
			record.projectOriginalWorkflowReturn(*run)
		}
		f.publicReturns = append(f.publicReturns, record)
	}()
	var body []byte
	var err error
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil {
			record.PreflightFailed = true
			return record, err
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, f.realm.CoreOrigin+path, bytes.NewReader(body))
	if err != nil {
		record.PreflightFailed = true
		return record, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+f.workflowToken)
	record.DoStartedAt = time.Now().UTC()
	response, doErr := f.realm.Client.Do(request)
	record.DoReturnedAt = time.Now().UTC()
	record.DoFailed = doErr != nil
	if response != nil {
		record.Status = response.StatusCode
		if response.Body != nil {
			raw, re := io.ReadAll(io.LimitReader(response.Body, 2<<20))
			record.ReadReturnedAt = time.Now().UTC()
			ce := response.Body.Close()
			record.CloseReturnedAt = time.Now().UTC()
			record.BodySHA256 = capacity.BusinessCreationSHA256(raw)
			record.BodyBytes = len(raw)
			record.ReadFailed = re != nil || len(raw) == 2<<20
			record.CloseFailed = ce != nil
			if doErr != nil || record.ReadFailed || record.CloseFailed || ctx.Err() != nil {
				return record, q.ErrOriginalUnknown
			}
			if out != nil {
				decoder := json.NewDecoder(bytes.NewReader(raw))
				decoder.DisallowUnknownFields()
				if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
					return record, q.ErrOriginalUnknown
				}
			}
		} else {
			record.ReadFailed = true
		}
	}
	if response == nil || record.ReadFailed || record.DoFailed || ctx.Err() != nil {
		return record, q.ErrOriginalUnknown
	}
	return record, nil
}

func (f *fixture) originalWorkflow(ctx context.Context, mode string, slot int, assessment model.CapacityAssessment, preID string) (model.WorkflowRunRecord, []originalPublicReturn, error) {
	var run model.WorkflowRunRecord
	var originals []originalPublicReturn
	request := model.RunWorkflowRequest{Workflow: model.ManifestSelector{Namespace: f.namespace, Name: f.workflow.Metadata.Name}, Inputs: map[string]any{"mode": mode, "slot": slot, "assessment": assessment, "preregistration_id": preID}, Metadata: map[string]any{"idempotency_key": uuid.NewString()}}
	var accepted struct {
		RunID    string                 `json:"run_id"`
		Status   string                 `json:"status"`
		Workflow model.ManifestSelector `json:"workflow"`
		Deduped  bool                   `json:"deduped,omitempty"`
	}
	returned, err := f.originalPublic(ctx, http.MethodPost, "/api/v1/workflow-runs", request, &accepted)
	originals = append(originals, returned)
	if err != nil || returned.Status != http.StatusAccepted || accepted.Status != "pending" || accepted.Deduped {
		return run, originals, q.ErrOriginalUnknown
	}
	parsed, err := uuid.Parse(accepted.RunID)
	if err != nil || parsed == uuid.Nil || parsed.String() != accepted.RunID {
		return run, originals, q.ErrOriginalUnknown
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		returned, err = f.originalPublic(ctx, http.MethodGet, "/api/v1/workflow-runs/"+accepted.RunID, nil, &run)
		originals = append(originals, returned)
		if err != nil || returned.Status != http.StatusOK || run.ID.String() != accepted.RunID {
			return run, originals, q.ErrOriginalUnknown
		}
		if run.Status == "succeeded" || run.Status == "failed" {
			if run.Result == nil || run.Result.Workflow.ID != f.workflow.ID {
				return run, originals, q.ErrOriginalUnknown
			}
			return run, originals, nil
		}
		select {
		case <-ctx.Done():
			return run, originals, q.ErrOriginalUnknown
		case <-ticker.C:
		}
	}
}

func (f *fixture) runOriginalPublicCaller(ctx context.Context) (runErr error) {
	defer func() {
		if runErr != nil {
			diagnostic, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_, writeErr := q.Publish(diagnostic, filepath.Join(f.private, "core-original-public-caller-failure-returns.json"), f.publicReturns)
			runErr = errors.Join(runErr, writeErr)
		}
	}()

	var p model.CapacityPolicySpec
	if json.Unmarshal(f.policy.Spec, &p) != nil {
		return q.ErrOriginalUnknown
	}
	var returns []originalPublicReturn
	var runIDs []string
	// The original scoped realm has no process or possible-create before its
	// first public dispatch. No floor/native/member counter is seeded in SQL.
	if len(f.realm.OwnedSlots()) != 0 {
		return q.ErrOriginalUnknown
	}
	baseline, originals, err := f.originalWorkflow(ctx, "baseline", 1, q.QualificationAssessment(p, 0, 0.9, time.Now().UTC()), "")
	returns = append(returns, originals...)
	if err != nil || baseline.Status != "succeeded" {
		return q.ErrOriginalUnknown
	}
	runIDs = append(runIDs, baseline.ID.String())
	var prepared q.PreCreateRequest
	if _, err = q.Await(ctx, filepath.Join(q.SlotDirectory(f.private, 2), "pre-create-request.json"), &prepared); err != nil {
		return err
	}
	baselineProbeAt, err := f.actualLastUsefulProbeTime(ctx, 1)
	if err != nil || !capacity.Fresh(baselineProbeAt, time.Now().UTC(), p.MaxEvidenceAgeSeconds) {
		return q.ErrOriginalUnknown
	}
	burst, originals, err := f.originalWorkflow(ctx, "burst", 2, q.QualificationAssessment(p, 1, 0.9, baselineProbeAt), "")
	returns = append(returns, originals...)
	if err != nil {
		return err
	}
	runIDs = append(runIDs, burst.ID.String())
	if q.CanonicalSourceCompensationCase(f.request.NativeCase) {
		return f.finishOriginalCanonicalSourceCompensation(ctx, p, baseline, burst, runIDs, returns)
	}
	if q.SourceCompensationCase(f.request.NativeCase) {
		return f.finishOriginalSourceCompensation(ctx, p, baseline, burst, runIDs, returns)
	}
	if !q.PositiveCase(f.request.NativeCase) && f.request.NativeCase != "held_ack_after_owned_original_deadline" {
		return f.finishExpectedOriginalHold(ctx, p, baseline, burst, runIDs, returns)
	}
	if burst.Status != "succeeded" {
		return q.ErrOriginalUnknown
	}
	// A fixed two-second qualification demand window precedes the original
	// reduction; it is not a production pressure observation or a new budget.
	lowDemandStartedAt := time.Now().UTC()
	at, err := f.actualLastUsefulProbeTime(ctx, 2)
	if err != nil {
		return err
	}
	observedDemand, originals, err := f.originalWorkflow(ctx, "observe_reduction_demand", 2, q.QualificationDemandWindow(p, 2, 0.1, at, lowDemandStartedAt, lowDemandStartedAt), "")
	returns = append(returns, originals...)
	if err != nil || observedDemand.Status != "succeeded" {
		return q.ErrOriginalUnknown
	}
	runIDs = append(runIDs, observedDemand.ID.String())
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return q.ErrOriginalUnknown
	case <-timer.C:
	}
	lowDemandReturnedAt := time.Now().UTC()
	at, err = f.actualLastUsefulProbeTime(ctx, 2)
	if err != nil {
		return err
	}
	pre, _, err := f.realm.OriginalEnrollment(2)
	if err != nil {
		return err
	}
	retirement, originals, err := f.originalWorkflow(ctx, "retire", 2, q.QualificationDemandWindow(p, 2, 0.1, at, lowDemandStartedAt, lowDemandReturnedAt), pre.PreregistrationID)
	returns = append(returns, originals...)
	if err != nil {
		return err
	}
	if f.request.NativeCase == "held_ack_after_owned_original_deadline" {
		runIDs = append(runIDs, retirement.ID.String())
		return f.finishExpectedOriginalHold(ctx, p, baseline, retirement, runIDs, returns)
	}
	if retirement.Status != "succeeded" {
		return q.ErrOriginalUnknown
	}
	runIDs = append(runIDs, retirement.ID.String())
	return f.finishActualOriginalCorpus(ctx, p, runIDs, returns)
}

func (f *fixture) actualLastUsefulProbeTime(ctx context.Context, slot int) (time.Time, error) {
	var at time.Time
	pre, _, err := f.realm.OriginalEnrollment(slot)
	if err != nil {
		return at, err
	}
	var wire []byte
	if err = f.db.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='serving_probe' ORDER BY recorded_at DESC LIMIT 1`, pre.PreregistrationID).Scan(&wire); err != nil {
		return at, err
	}
	var probe q.QualificationProbeReceipt
	if capacity.DecodeGuestLifecycle(wire, &probe) != nil {
		return at, q.ErrOriginalUnknown
	}
	return probe.OriginalNativeAfterReturnedAt, nil
}

// projectOriginalWorkflowReturn retains only the existing closed diagnostic fields.
// One exact Source-owned hyphenated ID is accepted; arbitrary hyphenated IDs remain refused.
func (record *originalPublicReturn) projectOriginalWorkflowReturn(run model.WorkflowRunRecord) {
	switch run.Status {
	case "pending", "running", "succeeded", "failed":
		record.WorkflowStatus = run.Status
	}
	// Async dispatch can fail before any step result exists. Retain only
	// closed class, byte count and hash of that actual top-level error.
	if run.Error != "" {
		record.WorkflowErrorBytes = len(run.Error)
		record.WorkflowErrorSHA256 = capacity.BusinessCreationSHA256([]byte(run.Error))
		record.WorkflowErrorClass = "other"
		switch run.Error {
		case "sql: no rows in result set":
			record.WorkflowErrorClass = "sql_no_rows"
		case "capacity execution is disabled":
			record.WorkflowErrorClass = "capacity_disabled"
		case "capacity intent conflict":
			record.WorkflowErrorClass = "capacity_conflict"
		case "capacity mutation authorization denied":
			record.WorkflowErrorClass = "authorization"
		}
	}
	if run.Result != nil {
		for _, step := range run.Result.Steps {
			if step.Status != "failed" || (step.ID != "original-native-qemu-create" && !regexp.MustCompile(`^[a-z0-9_]{1,96}$`).MatchString(step.ID)) {
				continue
			}
			record.WorkflowFailedStep = step.ID
			if predicate, ok := step.Metadata["original_guest_refusal_predicate"].(string); ok && regexp.MustCompile(`^(?:original-guest-step-[0-9]{2}|original-retirement-39-(?:http|floor|decode|load|auth|record)|original-canonical-floor-next-output|original-canonical-floor-next-permission|original-canonical-floor-permission-gate|original-source-historical-confirm|original-source-historical-output|original-source-live-partial|original-source-live-partial-output|original-source-terminal|original-source-terminal-output|pg17-original-confirm-assertions|pg17-original-create-assertions|pg17-original-historical-assertions|pg17-original-terminal-assertions|pg17-original-workflow-confirm|pg17-confirm-(?:check-0[1-6]|native-(?:0[1-9]|[12][0-9]|3[01])))$`).MatchString(predicate) {
				record.WorkflowPredicate = predicate
			}
			if step.Error == "" {
				break
			}
			record.WorkflowErrorBytes = len(step.Error)
			record.WorkflowErrorSHA256 = capacity.BusinessCreationSHA256([]byte(step.Error))
			record.WorkflowErrorClass = "other"
			switch {
			case strings.Contains(step.Error, "protected original Guest source step unavailable"):
				record.WorkflowErrorClass = "original_guest_source_hold"
			case strings.Contains(step.Error, "capacity intent conflict"):
				record.WorkflowErrorClass = "capacity_conflict"
			case strings.Contains(strings.ToLower(step.Error), "condition"):
				record.WorkflowErrorClass = "condition"
			case strings.Contains(strings.ToLower(step.Error), "authorization") || strings.Contains(strings.ToLower(step.Error), "forbidden"):
				record.WorkflowErrorClass = "authorization"
			}
			break
		}
	}
}
