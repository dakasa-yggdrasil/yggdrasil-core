package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/reqcache"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// The operator is a real collaborator created by the existing identity
// repository. Its declared test GodMode trait authorizes this isolated admin
// fixture only; no native capacity or execution receipt is manufactured.
func dispatchPrestartHTTPAdminFixture(t *testing.T, f dispatchHTTPFixture) (uuid.UUID, http.Handler) {
	t.Helper()
	t.Setenv(contactphone.EnrollmentPolicyEnv, "false")
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "enforce")
	actor := directoryHTTPPerson(t, f.db, false)
	traits := map[string]any{"yggdrasil_admin": true}
	if _, err := repository.UpdateCollaborator(t.Context(), f.db, model.UpdateCollaboratorRequest{ID: actor.ID.String(), Traits: &traits}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.db.ExecContext(context.Background(), `DELETE FROM public.capacity_dispatch_prestart_rejections WHERE job_id IN (SELECT id FROM public.capacity_dispatch_jobs WHERE realm=$1)`, f.policy.Metadata.Namespace); err != nil {
			t.Error(err)
		}
	})
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/ops/capacity/dispatch-prestart-rejections", f.server.requireOpsPermissionFunc(permManageWorkflows, f.server.handleOpsCapacityDispatchPrestartRejection))
	mux.HandleFunc("GET /api/v1/ops/capacity/dispatch-prestart-rejections/{jobId}", f.server.requireOpsPermissionFunc(permManageWorkflows, f.server.handleOpsCapacityDispatchPrestartRejectionRead))
	return actor.ID, mux
}

func dispatchPrestartHTTPCall(t *testing.T, h http.Handler, actor uuid.UUID, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := rbacTestRequestWithClaims(method, path, actor)
	r.Body = io.NopCloser(strings.NewReader(string(raw)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func dispatchPrestartHTTPCAS(old repository.CapacityDispatchJob, next model.Manifest) repository.CapacityDispatchPrestartRejectionRequest {
	return repository.CapacityDispatchPrestartRejectionRequest{JobID: old.JobID, ExpectedRunID: old.RunID, ExpectedEnvelopeSHA256: old.EnvelopeSHA256, ExpectedFencingToken: old.FencingToken, ExpectedSupersedingPolicyID: next.ID, ExpectedSupersedingPolicyVersion: next.Version, ExpectedSupersedingPolicyChecksum: next.Checksum}
}

func TestCapacityDispatchPrestartRejectionHTTPPostgres(t *testing.T) {
	t.Run("administrative_POST_GET_then_independent_current_tick", func(t *testing.T) {
		f := dispatchHTTPPostgresFixture(t)
		actor, h := dispatchPrestartHTTPAdminFixture(t, f)
		prepared := f.prepare(t)
		old := f.enqueue(t, prepared)
		if old.LeaseExpiresAt != nil || old.StartedAt != nil || old.ReturnedAt != nil || old.FinalizationAckAt != nil {
			t.Fatal("expected real unclaimed pending fixture")
		}
		changed := f.spec
		changed.DownHoldSeconds++
		next := f.create("capacity_policy", "pods", changed)
		tick, err := time.Parse(time.RFC3339Nano, old.SourceTick)
		if err != nil {
			t.Fatal(err)
		}
		current, err := f.service.PrepareScheduledTick(t.Context(), f.workflow.ID, tick.Add(time.Minute))
		if err != nil || current == nil {
			t.Fatal("new policy full admission refused", err)
		}
		coalesced := f.enqueue(t, current)
		if coalesced.JobID != old.JobID || coalesced.State != "queued" || coalesced.Policy.ID != old.Policy.ID || coalesced.PendingWakeCount != 2 {
			t.Fatal("ordinary Enqueue rejected/rebased the obsolete envelope automatically")
		}
		before, err := repository.ReadCapacityDispatchForPrestartRejection(t.Context(), f.db, old.JobID)
		if err != nil {
			t.Fatal(err)
		}
		runBefore, err := repository.GetWorkflowRun(t.Context(), f.db, old.RunID)
		if err != nil {
			t.Fatal(err)
		}
		post := dispatchPrestartHTTPCall(t, h, actor, http.MethodPost, "/api/v1/ops/capacity/dispatch-prestart-rejections", dispatchPrestartHTTPCAS(before, next))
		if post.Code != http.StatusCreated {
			t.Fatalf("owning POST status=%d body=%s", post.Code, post.Body.String())
		}
		after, err := repository.ReadCapacityDispatchForPrestartRejection(t.Context(), f.db, old.JobID)
		if err != nil || after.State != "prestart_rejected" || after.EnvelopeSHA256 != before.EnvelopeSHA256 || !reflect.DeepEqual(after.CapacityDispatchEnvelope, before.CapacityDispatchEnvelope) || after.PendingWakeCount != before.PendingWakeCount || after.LeaseOwner != before.LeaseOwner || after.FencingToken != before.FencingToken || after.LeaseExpiresAt != nil || after.StartedAt != nil || after.ReturnedAt != nil || after.FinalizationAckAt != nil {
			t.Fatal("administrative POST changed original envelope/ownership/wakes or invented execution", err)
		}
		receipt, err := repository.ReadCapacityDispatchPrestartRejection(t.Context(), f.db, old.JobID)
		if err != nil || receipt.Issuer != "collaborator:"+actor.String() || receipt.RunID != old.RunID || receipt.SupersededPolicyID != old.Policy.ID || receipt.SupersedingPolicyID != next.ID {
			t.Fatal("missing exact durable administrative receipt", err)
		}
		run, err := repository.GetWorkflowRun(t.Context(), f.db, old.RunID)
		if err != nil || run.Status != "cancelled" || run.StartedAt != nil || run.FinishedAt == nil || !run.FinishedAt.Equal(receipt.RecordedAt) || run.Result != nil || run.Error != repository.CapacityDispatchPrestartRejectionReason || !reflect.DeepEqual(run.Inputs, runBefore.Inputs) || !reflect.DeepEqual(run.Metadata, runBefore.Metadata) {
			t.Fatal("pending original workflow was not cancelled truthfully", err)
		}
		var jobs, runs, ledger, wakes int
		if err = f.db.QueryRowContext(t.Context(), `SELECT (SELECT count(*) FROM public.capacity_dispatch_jobs WHERE realm=$1),(SELECT count(*) FROM public.workflow_runs WHERE workflow_namespace=$1),(SELECT count(*) FROM public.capacity_dispatch_prestart_rejections WHERE job_id=$2),(SELECT count(*) FROM public.capacity_dispatch_wakes WHERE job_id=$2)`, old.Realm, old.JobID).Scan(&jobs, &runs, &ledger, &wakes); err != nil || jobs != 1 || runs != 1 || ledger != 1 || wakes != 2 {
			t.Fatalf("admin POST enqueued/replayed/dropped history jobs=%d runs=%d ledger=%d wakes=%d err=%v", jobs, runs, ledger, wakes, err)
		}
		get := dispatchPrestartHTTPCall(t, h, actor, http.MethodGet, "/api/v1/ops/capacity/dispatch-prestart-rejections/"+old.JobID.String(), nil)
		if get.Code != http.StatusOK {
			t.Fatalf("receipt GET status=%d body=%s", get.Code, get.Body.String())
		}
		var posted, read map[string]any
		if json.Unmarshal(post.Body.Bytes(), &posted) != nil || json.Unmarshal(get.Body.Bytes(), &read) != nil || !reflect.DeepEqual(posted, read) {
			t.Fatal("GET did not return the same durable POST receipt")
		}
		for _, marker := range []string{"lease_owner", "lease_expires_at", "started_at", "returned_at", "finalization_ack_at", "workflow_run_started_at"} {
			if value, exists := posted[marker]; !exists || value != nil {
				t.Fatal("owning POST omitted or invented original absence proof", marker)
			}
		}
		originalPolicy, ok := posted["original_policy"].(map[string]any)
		if !ok || originalPolicy["id"] != old.Policy.ID.String() || originalPolicy["namespace"] != old.Policy.Namespace || originalPolicy["name"] != old.Policy.Name || originalPolicy["version"] != float64(old.Policy.Version) || originalPolicy["checksum"] != old.Policy.Checksum || posted["workflow_run_status"] != "cancelled" || posted["workflow_run_result_present"] != false {
			t.Fatal("owning POST lost exact original policy/run lineage")
		}
		independentlyPrepared, err := f.service.PrepareScheduledTick(t.Context(), f.workflow.ID, tick.Add(2*time.Minute))
		if err != nil || independentlyPrepared == nil {
			t.Fatal("fresh current admission refused", err)
		}
		successor := f.enqueue(t, independentlyPrepared)
		if successor.JobID == old.JobID || successor.RunID == old.RunID || successor.Policy.ID != next.ID || successor.State != "queued" || successor.StartedAt != nil {
			t.Fatal("independently admitted current tick did not create fresh immutable pending job")
		}
	})
	for _, mode := range []string{"current_machine_RBAC_revoked", "current_policy_execution_disabled", "operator_revoked_after_request_cache_prime"} {
		t.Run(mode, func(t *testing.T) {
			f := dispatchHTTPPostgresFixture(t)
			actor, h := dispatchPrestartHTTPAdminFixture(t, f)
			old := f.enqueue(t, f.prepare(t))
			changed := f.spec
			changed.DownHoldSeconds++
			if mode == "current_policy_execution_disabled" {
				changed.ExecutionEnabled = false
			}
			next := f.create("capacity_policy", "pods", changed)
			if mode == "current_machine_RBAC_revoked" {
				deny := f.allow
				deny.Roles = []model.RBACRole{{Name: "controller", Rules: []model.RBACRule{{Effect: "deny", Resources: []string{"workflow:" + f.workflow.Metadata.Namespace + ":pressure"}, Actions: []string{"run"}}}}}
				f.create("rbac", "dispatch", deny)
			}
			before, err := repository.ReadCapacityDispatchForPrestartRejection(t.Context(), f.db, old.JobID)
			if err != nil {
				t.Fatal(err)
			}
			var post *httptest.ResponseRecorder
			if mode == "operator_revoked_after_request_cache_prime" {
				raw, err := json.Marshal(dispatchPrestartHTTPCAS(before, next))
				if err != nil {
					t.Fatal(err)
				}
				request := rbacTestRequestWithClaims(http.MethodPost, "/api/v1/ops/capacity/dispatch-prestart-rejections", actor)
				request.Body = io.NopCloser(strings.NewReader(string(raw)))
				ctx := reqcache.Install(request.Context())
				setCollaboratorInCache(ctx, model.Collaborator{ID: actor, Status: "active", Traits: map[string]any{"yggdrasil_admin": true}})
				traits := map[string]any{"yggdrasil_admin": false}
				if _, err := repository.UpdateCollaborator(t.Context(), f.db, model.UpdateCollaboratorRequest{ID: actor.String(), Traits: &traits}); err != nil {
					t.Fatal(err)
				}
				post = httptest.NewRecorder()
				h.ServeHTTP(post, request.WithContext(ctx))
			} else {
				post = dispatchPrestartHTTPCall(t, h, actor, http.MethodPost, "/api/v1/ops/capacity/dispatch-prestart-rejections", dispatchPrestartHTTPCAS(before, next))
			}
			if post.Code != http.StatusConflict {
				t.Fatalf("inadmissible current authority status=%d body=%s", post.Code, post.Body.String())
			}
			after, err := repository.ReadCapacityDispatchForPrestartRejection(t.Context(), f.db, old.JobID)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("failed complete admission partially rejected old job", err)
			}
			run, err := repository.GetWorkflowRun(t.Context(), f.db, old.RunID)
			if err != nil || run.Status != "pending" || run.StartedAt != nil || run.FinishedAt != nil || run.Result != nil {
				t.Fatal("failed complete admission changed pending original run", err)
			}
			var records int
			if err = f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM public.capacity_dispatch_prestart_rejections WHERE job_id=$1`, old.JobID).Scan(&records); err != nil || records != 0 {
				t.Fatal("failed complete admission appended rejection", records, err)
			}
		})
	}
}
