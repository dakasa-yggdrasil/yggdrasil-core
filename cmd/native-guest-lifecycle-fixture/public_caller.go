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

// retainSourceCallerFailure records only the already projected public returns.
// It does not change the original failure or publish success evidence.
func (f *fixture) retainSourceCallerFailure(ctx context.Context, runErr *error) {
	if *runErr == nil {
		return
	}
	diagnostic, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	returns := append([]originalPublicReturn{}, f.publicReturns...)
	_, _ = q.Publish(diagnostic, filepath.Join(f.private, "core-original-public-caller-failure-returns.json"), returns)
}

func (f *fixture) runOriginalPublicCaller(ctx context.Context) (runErr error) {
	var retirementDiagnosticRun uuid.UUID
	var retirementDiagnosticPre string
	defer func() {
		if runErr != nil {
			diagnostic, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_, writeErr := q.Publish(diagnostic, filepath.Join(f.private, "core-original-public-caller-failure-returns.json"), f.publicReturns)
			runErr = errors.Join(runErr, writeErr)
			// Reuse only already retained original facts. Failure to export is
			// diagnostic uncertainty, never a replacement for the original error.
			f.exportFailedOriginalRetirement(diagnostic, retirementDiagnosticRun, retirementDiagnosticPre)
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
	baselineSlot, failedSlot := 1, 2
	if q.SourceFailureSlot(f.request.NativeCase) == 1 {
		baselineSlot, failedSlot = 2, 1
	}
	baseline, originals, err := f.originalWorkflow(ctx, "baseline", baselineSlot, q.QualificationAssessment(p, 0, 0.9, time.Now().UTC()), "")
	returns = append(returns, originals...)
	if err != nil || baseline.Status != "succeeded" {
		return q.ErrOriginalUnknown
	}
	runIDs = append(runIDs, baseline.ID.String())
	var prepared q.PreCreateRequest
	if _, err = q.Await(ctx, filepath.Join(q.SlotDirectory(f.private, failedSlot), "pre-create-request.json"), &prepared); err != nil {
		return err
	}
	baselineProbeAt, err := f.actualLastUsefulProbeTime(ctx, baselineSlot)
	if err != nil || !capacity.Fresh(baselineProbeAt, time.Now().UTC(), p.MaxEvidenceAgeSeconds) {
		return q.ErrOriginalUnknown
	}
	burst, originals, err := f.originalWorkflow(ctx, "burst", failedSlot, q.QualificationAssessment(p, 1, 0.9, baselineProbeAt), "")
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
	retirementDiagnosticPre = pre.PreregistrationID
	if err == nil {
		// originalWorkflow authenticated this exact terminal result workflow ID.
		retirementDiagnosticRun = retirement.ID
	}
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

// The public insert leaves workflow_id nullable. Match the exact authenticated
// returned result identity, while rejecting any nonnull foreign workflow_id.
const failedOriginalRetirementIntentSQL = `SELECT i.id::text
FROM public.capacity_vm_retirement_intents i
JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=i.preregistration_id
JOIN public.capacity_vm_original_enrollments e ON e.preregistration_id=p.id
JOIN public.workflow_runs w ON w.id=$1
 AND (w.workflow_id IS NULL OR w.workflow_id=$2)
 AND w.result#>>'{workflow,id}'=$2::text
WHERE i.preregistration_id=$3 AND w.workflow_namespace=$8 AND w.workflow_name=$9
 AND w.inputs->>'mode'='retire' AND w.inputs->'slot'='2'::jsonb
 AND w.inputs->>'preregistration_id'=$3::text
 AND p.preregistration_record->'slot'='2'::jsonb
 AND p.preregistration_record->>'policy_id'=$4::text AND p.preregistration_record->>'policy_checksum'=$5
 AND p.preregistration_record->>'workflow_id'=$2::text AND p.preregistration_record->>'workflow_checksum'=$6
 AND i.intent_record->'slot'='2'::jsonb
 AND i.intent_record->>'policy_id'=$4::text AND i.intent_record->>'policy_checksum'=$5
 AND i.intent_record->>'workflow_id'=$2::text AND i.intent_record->>'workflow_checksum'=$6
 AND i.intent_record->'tuple'=e.enrollment_record#>'{statement,tuple}'
 AND i.intent_record#>>'{tuple,resource_id}'=$7
 AND w.started_at IS NOT NULL AND i.created_at>=w.started_at
 AND (w.finished_at IS NULL OR i.created_at<=w.finished_at)`

// This runs only from the original caller's failure defer, before its DB closes.
// Every selector comes from that same authenticated workflow and sealed S2.
// Zero/multiple/invalid matches never export a favorable/latest row.
func (f *fixture) exportFailedOriginalRetirement(ctx context.Context, run uuid.UUID, preID string) {
	d := originalRetirementFailureDisposition{Schema: originalRetirementFailureDispositionSchema, Status: "not_exported", ErrorClass: "invalid_precondition", Stage: "precondition"}
	defer func() { f.publishOriginalRetirementFailureDisposition(ctx, d) }()
	pre, err := uuid.Parse(preID)
	if f == nil || f.db == nil || ctx == nil || ctx.Err() != nil || run == uuid.Nil || err != nil || pre == uuid.Nil || pre.String() != preID || len(f.request.Slots) != 2 || f.policy.ID == uuid.Nil || f.workflow.ID == uuid.Nil {
		if ctx != nil && ctx.Err() != nil {
			d.setError(ctx.Err())
		}
		return
	}
	d.Stage = "query"
	rows, err := f.db.QueryContext(ctx, failedOriginalRetirementIntentSQL, run, f.workflow.ID, pre, f.policy.ID, f.policy.Checksum, f.workflow.Checksum, f.request.Slots[1].ResourceID, f.namespace, f.workflow.Metadata.Name)
	if err != nil {
		d.setError(err)
		return
	}
	var candidates []string
	for rows.Next() {
		d.Stage = "scan"
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		candidates = append(candidates, id)
		if len(candidates) > 1 {
			break
		}
	}
	d.Matches = len(candidates)
	rowsErr, closeErr := rows.Err(), rows.Close()
	if err != nil {
		d.setError(err)
		return
	}
	if rowsErr != nil {
		d.Stage = "rows"
		d.setError(rowsErr)
		return
	}
	if closeErr != nil {
		d.Stage = "rows_close"
		d.setError(closeErr)
		return
	}
	if len(candidates) == 0 {
		d.Stage, d.ErrorClass = "zero", "zero_matches"
		return
	}
	if len(candidates) > 1 {
		d.Stage, d.ErrorClass = "multiple", "multiple_matches"
		return
	}
	id, unique := uniqueOriginalRetirementDiagnosticIntent(candidates)
	if !unique {
		d.Stage, d.ErrorClass = "invalid_id", "invalid_id"
		return
	}
	// The helper retains 21 caller facts then 0..N existing rows. No corpus
	// completion is created, and a partial export remains visibly partial.
	if err = f.exportOriginalRetirementProjectionsWithDisposition(ctx, id, &d); err != nil {
		d.setError(err)
		return
	}
	d.Status, d.Stage, d.ErrorClass = "exported", "exported", "none"
}

func uniqueOriginalRetirementDiagnosticIntent(candidates []string) (string, bool) {
	if len(candidates) != 1 {
		return "", false
	}
	id, err := uuid.Parse(candidates[0])
	if err != nil || id == uuid.Nil || id.String() != candidates[0] {
		return "", false
	}
	return candidates[0], true
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
			if predicate, ok := step.Metadata["original_guest_refusal_predicate"].(string); ok && regexp.MustCompile(`^(?:original-guest-step-[0-9]{2}|original-retirement-39-(?:http|floor|decode|load|auth|record)|original-refusal-43-(?:pre|initial|publish|check-(?:0[1-9]|1[01])-(?:accepted|error|state))|original-canonical-floor-next-output|original-canonical-floor-next-permission|original-canonical-floor-permission-gate|original-recovery-cleanup-(?:scope|preregistration|observe|epoch|client|case|random|challenge|request-publish|fresh-native|http-transport|http-status|http-late|return-publish|failure-publish|complete|session|nonce|store|challenge-tx|policy|lock|parent-load|parent-state|prereg-id|prereg-load|prereg-binding|clock|intent-load|intent-epoch|intent-parent|deadline|lease-state|lease|challenge-encode|challenge-insert|challenge-commit)|original-source-historical-confirm|original-source-historical-output|original-source-postloss-pending|original-source-live-partial|original-source-live-partial-output|original-source-terminal|original-source-terminal-output|pg17-original-confirm-assertions|pg17-original-create-assertions|pg17-original-historical-assertions|pg17-original-terminal-assertions|pg17-original-workflow-confirm|pg17-confirm-(?:check-0[1-6]|native-(?:0[1-9]|[12][0-9]|3[01])))$`).MatchString(predicate) {
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
