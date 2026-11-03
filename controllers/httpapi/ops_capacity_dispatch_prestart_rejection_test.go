package httpapi

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/reqcache"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func prestartRejectionCASFixture() map[string]any {
	return map[string]any{
		"job_id": "0206b60d-ec3d-49d9-ba2e-78f45a60e34a", "expected_run_id": "96f0125a-80c4-4862-9b42-1f6be8d3db00",
		"expected_envelope_sha256": strings.Repeat("a", 64), "expected_fencing_token": int64(15),
		"expected_superseding_policy_id": "eb46d274-a843-4232-bfb2-4f8d8e04e3ef", "expected_superseding_policy_version": 4,
		"expected_superseding_policy_checksum": strings.Repeat("b", 64),
	}
}

func TestCapacityDispatchPrestartRejectionClosedCASRequest(t *testing.T) {
	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	good := encode(prestartRejectionCASFixture())
	request, err := decodeCapacityDispatchPrestartRejection(strings.NewReader(good))
	if err != nil || request.ExpectedFencingToken != 15 || request.ExpectedSupersedingPolicyVersion != 4 || request.Issuer != "" {
		t.Fatal("valid CAS refused or issuer synthesized", request, err)
	}
	for _, fence := range []int64{0, 9007199254740991} {
		value := prestartRejectionCASFixture()
		value["expected_fencing_token"] = fence
		if _, err := decodeCapacityDispatchPrestartRejection(strings.NewReader(encode(value))); err != nil {
			t.Fatal("valid fence boundary refused", fence, err)
		}
	}
	for key := range prestartRejectionCASFixture() {
		t.Run("missing_or_null_"+key, func(t *testing.T) {
			for _, absent := range []bool{false, true} {
				value := prestartRejectionCASFixture()
				value[key] = nil
				if absent {
					delete(value, key)
				}
				if _, err := decodeCapacityDispatchPrestartRejection(strings.NewReader(encode(value))); err == nil {
					t.Fatal("missing/null accepted", key, absent)
				}
			}
		})
	}
	for _, mutation := range []struct {
		key   string
		value any
	}{
		{"issuer", "collaborator:" + uuid.NewString()}, {"resource_absent", true}, {"started_at", nil},
		{"job_id", strings.ToUpper(prestartRejectionCASFixture()["job_id"].(string))}, {"expected_run_id", uuid.Nil.String()},
		{"expected_superseding_policy_id", "not-a-uuid"}, {"expected_envelope_sha256", strings.Repeat("A", 64)},
		{"expected_superseding_policy_checksum", strings.Repeat("g", 64)}, {"expected_fencing_token", -1},
		{"expected_fencing_token", int64(9007199254740992)}, {"expected_fencing_token", 1.5},
		{"expected_superseding_policy_version", 0}, {"expected_superseding_policy_version", "4"},
	} {
		value := prestartRejectionCASFixture()
		value[mutation.key] = mutation.value
		if _, err := decodeCapacityDispatchPrestartRejection(strings.NewReader(encode(value))); err == nil {
			t.Fatal("foreign/malformed accepted", mutation.key, mutation.value)
		}
	}
	duplicate := strings.TrimSuffix(good, "}") + `,"job_id":"0206b60d-ec3d-49d9-ba2e-78f45a60e34a"}`
	for _, raw := range []string{"{}", "null", "[]", good + good, good + strings.Repeat(" ", 4097), duplicate} {
		if _, err := decodeCapacityDispatchPrestartRejection(strings.NewReader(raw)); err == nil {
			t.Fatal("duplicate/trailing/oversize accepted")
		}
	}
}

func TestCapacityDispatchPrestartRejectionNoMachineOrWarnBypass(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")
	server := &Server{}
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(method, "/api/v1/ops/capacity/dispatch-prestart-rejections", strings.NewReader("{}"))
		if method == http.MethodPost {
			server.handleOpsCapacityDispatchPrestartRejection(response, request)
		} else {
			server.handleOpsCapacityDispatchPrestartRejectionRead(response, request)
		}
		if response.Code != http.StatusUnauthorized {
			t.Fatal("no authenticated collaborator reached repository", method, response.Code)
		}
	}
}

func TestCapacityDispatchPrestartRejectionRequiresAdministrativePermission(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		server, mock := rbacTestSetup(t)
		actor := uuid.New()
		programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:manage_workflows"})
		request := rbacTestRequestWithClaims(method, "/api/v1/ops/capacity/dispatch-prestart-rejections", actor)
		response := httptest.NewRecorder()
		if method == http.MethodPost {
			server.handleOpsCapacityDispatchPrestartRejection(response, request)
		} else {
			server.handleOpsCapacityDispatchPrestartRejectionRead(response, request)
		}
		if response.Code != http.StatusForbidden {
			t.Fatal("manage_workflows alone reached repository", method, response.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCapacityDispatchPrestartRejectionGodModeStillChecksClosedRequest(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		server, mock := rbacTestSetup(t)
		actor := uuid.New()
		programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:*"})
		request := rbacTestRequestWithClaims(method, "/api/v1/ops/capacity/dispatch-prestart-rejections", actor)
		request.Body = http.NoBody
		response := httptest.NewRecorder()
		if method == http.MethodPost {
			server.handleOpsCapacityDispatchPrestartRejection(response, request)
		} else {
			request.SetPathValue("jobId", "invalid")
			server.handleOpsCapacityDispatchPrestartRejectionRead(response, request)
		}
		if response.Code != http.StatusBadRequest {
			t.Fatal("admin malformed request reached repository", method, response.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCapacityDispatchPrestartRejectionProjectionMakesNoExecutionClaim(t *testing.T) {
	record := repository.CapacityDispatchPrestartRejection{JobID: uuid.New(), RunID: uuid.New(), Reason: "policy_superseded_before_start", Issuer: "collaborator:" + uuid.NewString(), EnvelopeSHA256: strings.Repeat("a", 64), State: "prestart_rejected", WorkflowRunStatus: "cancelled"}
	raw, err := json.Marshal(capacityDispatchPrestartRejectionSummary(record))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{`"envelope":`, `"inputs":`, `"metadata":`, "principal_sha256", "binding_sha256", "native_body"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("private/invented execution data in summary", secret)
		}
	}
	if !strings.Contains(string(raw), `"original_workflow_started":false`) || !strings.Contains(string(raw), `"provider_mutations":0`) || !strings.Contains(string(raw), `"new_current_admission_required":true`) {
		t.Fatal("rejection claimed execution or future admission")
	}
	var projection map[string]any
	if json.Unmarshal(raw, &projection) != nil {
		t.Fatal("invalid rejection projection")
	}
	for _, marker := range []string{"lease_owner", "lease_expires_at", "started_at", "returned_at", "finalization_ack_at", "workflow_run_started_at"} {
		value, exists := projection[marker]
		if !exists || value != nil {
			t.Fatal("absent original marker was omitted or invented", marker)
		}
	}
	if projection["workflow_run_status"] != "cancelled" || projection["workflow_run_result_present"] != false || projection["state"] != "prestart_rejected" {
		t.Fatal("typed prestart absence evidence missing")
	}
}

func TestCapacityDispatchPrestartRejectionReadRouteReturnsDurableReceipt(t *testing.T) {
	server, mock := rbacTestSetup(t)
	actor, job, run, oldPolicy, newPolicy := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:*"})
	programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:*"})
	now := time.Now().UTC()
	policyRaw, err := json.Marshal(repository.CapacityDispatchManifestPin{ID: oldPolicy, Namespace: "declared-realm", Name: "pressure", Version: 3, Checksum: strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery("FROM public.capacity_dispatch_prestart_rejections").WithArgs(job).
		WillReturnRows(sqlmock.NewRows(prestartRejectionProofColumns()).
			AddRow(job, run, strings.Repeat("a", 64), 0, "policy_superseded_before_start", "collaborator:"+actor.String(), now, oldPolicy, strings.Repeat("b", 64), newPolicy, strings.Repeat("c", 64),
				"prestart_rejected", "declared-realm", "production", "notify", "declared-members", nil, nil, nil, nil, nil,
				"cancelled", nil, now, false, "policy_superseded_before_start", policyRaw))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/ops/capacity/dispatch-prestart-rejections/{jobId}", server.requireOpsPermissionFunc(permManageWorkflows, server.handleOpsCapacityDispatchPrestartRejectionRead))
	request := rbacTestRequestWithClaims(http.MethodGet, "/api/v1/ops/capacity/dispatch-prestart-rejections/"+job.String(), actor)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), job.String()) || !strings.Contains(response.Body.String(), `"state":"prestart_rejected"`) {
		t.Fatal("durable receipt read refused or lost identity", response.Code, response.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func prestartRejectionProofColumns() []string {
	return []string{"job_id", "run_id", "envelope_sha256", "fencing_token", "reason", "issuer", "recorded_at", "superseded_policy_id", "superseded_policy_checksum", "superseding_policy_id", "superseding_policy_checksum",
		"state", "realm", "environment", "domain", "dimension", "lease_owner", "lease_expires_at", "started_at", "returned_at", "finalization_ack_at",
		"workflow_run_status", "workflow_run_started_at", "workflow_run_finished_at", "workflow_run_result_present", "workflow_run_error", "original_policy"}
}

func TestCapacityDispatchPrestartRejectionReadRefusesExecutionOrInvalidRunProof(t *testing.T) {
	for _, mode := range []string{"started", "result", "finish"} {
		t.Run(mode, func(t *testing.T) {
			server, mock := rbacTestSetup(t)
			actor, job, run, oldPolicy, newPolicy := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
			programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:*"})
			now := time.Now().UTC()
			policyRaw, err := json.Marshal(repository.CapacityDispatchManifestPin{ID: oldPolicy, Namespace: "declared-realm", Name: "pressure", Version: 3, Checksum: strings.Repeat("b", 64)})
			if err != nil {
				t.Fatal(err)
			}
			var started any
			finished, resultPresent := now, false
			switch mode {
			case "started":
				started = now.Add(-time.Minute)
			case "result":
				resultPresent = true
			case "finish":
				finished = now.Add(-time.Second)
			}
			mock.ExpectQuery("FROM public.capacity_dispatch_prestart_rejections").WithArgs(job).
				WillReturnRows(sqlmock.NewRows(prestartRejectionProofColumns()).
					AddRow(job, run, strings.Repeat("a", 64), 0, "policy_superseded_before_start", "collaborator:"+actor.String(), now, oldPolicy, strings.Repeat("b", 64), newPolicy, strings.Repeat("c", 64),
						"prestart_rejected", "declared-realm", "production", "notify", "declared-members", nil, nil, started, nil, nil,
						"cancelled", nil, finished, resultPresent, "policy_superseded_before_start", policyRaw))
			request := rbacTestRequestWithClaims(http.MethodGet, "/api/v1/ops/capacity/dispatch-prestart-rejections/"+job.String(), actor)
			request.SetPathValue("jobId", job.String())
			response := httptest.NewRecorder()
			server.handleOpsCapacityDispatchPrestartRejectionRead(response, request)
			if response.Code != http.StatusNotFound {
				t.Fatal("invalid absence evidence projected as typed proof", response.Code)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCapacityDispatchPrestartRejectionValidCASCannotInventMissingJob(t *testing.T) {
	server, mock := rbacTestSetup(t)
	actor := uuid.New()
	programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:*"})
	fixture := prestartRejectionCASFixture()
	id, _ := uuid.Parse(fixture["job_id"].(string))
	mock.ExpectQuery("FROM public.capacity_dispatch_jobs").WithArgs(id).WillReturnError(sql.ErrNoRows)
	raw, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	request := rbacTestRequestWithClaims(http.MethodPost, "/api/v1/ops/capacity/dispatch-prestart-rejections", actor)
	request.Body = io.NopCloser(strings.NewReader(string(raw)))
	response := httptest.NewRecorder()
	server.handleOpsCapacityDispatchPrestartRejection(response, request)
	if response.Code != http.StatusConflict {
		t.Fatal("missing original job admitted", response.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCapacityDispatchPrestartRejectionRechecksOperatorDespitePrimedRequestCache(t *testing.T) {
	server, mock := rbacTestSetup(t)
	actor := uuid.New()
	ctx := reqcache.Install(t.Context())
	setCollaboratorInCache(ctx, model.Collaborator{ID: actor, Status: "active", Traits: map[string]any{"yggdrasil_admin": true}})
	// The initial middleware snapshot can still authorize its ordinary cached
	// boundary. It must not supply authority to the two commit-boundary reads.
	allowed, err := server.collaboratorHasOpsPermission(ctx, actor.String(), repository.YggdrasilGodModeAction)
	if err != nil || !allowed {
		t.Fatal("declared initial middleware snapshot missing", err)
	}
	programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:*"})
	if err := server.capacityDispatchPrestartOperatorCurrent(ctx, actor.String()); err != nil {
		t.Fatal("fresh current GodMode refused", err)
	}
	programCollaboratorWithPermissions(mock, actor, nil)
	if err := server.capacityDispatchPrestartOperatorCurrent(ctx, actor.String()); err == nil {
		t.Fatal("revoked current operator inherited primed GodMode cache")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
