package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/workflowdispatchlock"
	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

// Literal closed wire shape only, not an approved profile/source or enrollment.
const guestOriginalManifestBindingLiteral = `{"mode":"original_guest_retirement_v1","mutation_binding_name":"source-shape","evidence_class":"owned_provisioner_original","provisioner_source_commit":"","guest_source_commit":"","core_authority_source_commit":"","provisioner_public_key":"","enrollment_issuer_public_key":"","enrollment_signing_key_ref":"","intent_signing_key_ref":"","profile_manifest":{"schema":"original_guest_protected_profile_v1","profile":"source-shape","coverage_class":"complete_production_roster","production_catalog_sha256":"","mutation_binding":"source-shape","bootstrap_owner_source_commit":"","bootstrap_owner_binary_sha256":"","bootstrap_reader_binary_sha256":"","bootstrap_payload_sha256":"","bootstrap_sha256":"","original_provisioning_budget_seconds":420,"original_provisioning_step_id":"original-native-qemu-create","owner_source_commit":"","owner_binary_sha256":"","owner_image_digest":"","protected_cgroup":"","actor_source_commit":"","actor_binary_sha256":"","runtime_client_command_sha256":"","poweroff_command_sha256":"","writers":[]},"profile_manifest_sha256":"","max_evidence_age_seconds":30,"members":[]}`

func TestCapacityGuestOriginalManifestPayload(t *testing.T) {
	binding := guestOriginalManifestBindingLiteral
	profileStart := strings.Index(binding, `"profile_manifest":`)
	profileEnd := strings.Index(binding, `,"profile_manifest_sha256":`)
	nullProfile := binding[:profileStart] + `"profile_manifest":null` + binding[profileEnd:]
	for _, test := range []struct{ name, raw string }{
		{"duplicate_outer_binding", `{"guest_retirement_binding":` + binding + `,"guest_retirement_binding":` + binding + `}`},
		{"duplicate_nested_mode", `{"guest_retirement_binding":` + strings.Replace(binding, `"mode":"original_guest_retirement_v1"`, `"mode":"original_guest_retirement_v1","mode":"original_guest_retirement_v1"`, 1) + `}`},
		{"duplicate_nested_profile", `{"guest_retirement_binding":` + strings.Replace(binding, `"profile":"source-shape"`, `"profile":"source-shape","profile":"source-shape"`, 1) + `}`},
		{"case_outer_binding", `{"Guest_Retirement_Binding":` + binding + `}`},
		{"case_nested_mode", `{"guest_retirement_binding":` + strings.Replace(binding, `"mode":`, `"Mode":`, 1) + `}`},
		{"fold_duplicate_nested_mode", `{"guest_retirement_binding":` + strings.Replace(binding, `"mode":"original_guest_retirement_v1"`, `"mode":"original_guest_retirement_v1","Mode":"original_guest_retirement_v1"`, 1) + `}`},
		{"null_binding", `{"guest_retirement_binding":null}`},
		{"null_nested_profile", `{"guest_retirement_binding":` + nullProfile + `}`},
		{"unknown_nested_authority", `{"guest_retirement_binding":` + strings.Replace(binding, `"members":[]`, `"members":[],"production_approved":true`, 1) + `}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := manifestDocumentFromPayload("capacity_policy", consoleCreateManifestRequest{Name: "source", Spec: json.RawMessage(test.raw)}); err == nil {
				t.Fatal("raw ambiguity was collapsed before the capacity policy parser")
			}
		})
	}
	t.Run("literal_binding_shape_preserved", func(t *testing.T) {
		raw := `{"execution_enabled":false,"guest_retirement_binding":` + binding + `}`
		doc, err := manifestDocumentFromPayload("capacity_policy", consoleCreateManifestRequest{Name: "source", Spec: json.RawMessage(raw)})
		if err != nil {
			t.Fatal(err)
		}
		p, err := manifestengine.ParseCapacityPolicySpec(doc.Spec)
		if err != nil || p.GuestRetirementBinding == nil || p.ExecutionEnabled || p.GuestRetirementBinding.ProfileManifest.OriginalProvisioningBudgetSeconds != 420 {
			t.Fatal("literal closed binding lost", err)
		}
		if capacity.GuestOriginalProfileEnabled(p, *p.GuestRetirementBinding, "fixture") {
			t.Fatal("wire shape became production qualification")
		}
	})
	t.Run("absent_binding_remains_default_off", func(t *testing.T) {
		doc, err := manifestDocumentFromPayload("capacity_policy", consoleCreateManifestRequest{Name: "source", Spec: json.RawMessage(`{"execution_enabled":false}`)})
		if err != nil {
			t.Fatal(err)
		}
		p, err := manifestengine.ParseCapacityPolicySpec(doc.Spec)
		if err != nil || p.GuestRetirementBinding != nil || p.ExecutionEnabled {
			t.Fatal("legacy absence changed", err)
		}
	})
	t.Run("other_kind_keeps_generic_normalization", func(t *testing.T) {
		doc, err := manifestDocumentFromPayload("product", consoleCreateManifestRequest{Name: "source", Spec: json.RawMessage(`{"unrelated":1,"unrelated":2}`)})
		if err != nil || string(doc.Spec) != `{"unrelated":2}` {
			t.Fatal("unrelated manifest normalization changed", err)
		}
	})
}

func TestCapacityGuestOriginalManifestPublicBoundary(t *testing.T) {
	// Exercise the real handler/auth/parser boundary in its explicit existing
	// credential-free development posture; no claims are attached to context.
	// Production anonymous and workflow-token refusals are checked separately.
	for _, name := range []string{"duplicate_outer_before_sql", "duplicate_nested_before_sql"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("YGGDRASIL_ENV", "test")
			unsetEnvForTest(t, workflowMachinePrincipalsEnv)
			t.Setenv(legacyScopedWorkflowTokensEnv, "")
			t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
			t.Setenv("YGGDRASIL_WORKFLOW_RUN_LEGACY_ENABLED", "")
			unsetEnvForTest(t, workflowdispatchlock.EnvName)
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			binding := guestOriginalManifestBindingLiteral
			spec := `{"guest_retirement_binding":` + binding + `,"guest_retirement_binding":` + binding + `}`
			if name == "duplicate_nested_before_sql" {
				spec = `{"guest_retirement_binding":` + strings.Replace(binding, `"mode":"original_guest_retirement_v1"`, `"mode":"original_guest_retirement_v1","mode":"original_guest_retirement_v1"`, 1) + `}`
			}
			s := &Server{db: db}
			mux := http.NewServeMux()
			mux.HandleFunc("POST /api/v1/manifests", s.handleManifestCreateGeneric)
			r := httptest.NewRequest(http.MethodPost, "/api/v1/manifests?kind=capacity_policy", strings.NewReader(`{"name":"original-policy","namespace":"dakasa","spec":`+spec+`}`))
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code == http.StatusUnauthorized || w.Code < 400 || !strings.Contains(w.Body.String(), "closed nonnull original Guest retirement binding") {
				t.Fatal("public manifest did not reach/refuse raw duplicate boundary", w.Code, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("production_anonymous_refused", func(t *testing.T) {
		t.Setenv("YGGDRASIL_ENV", "production")
		unsetEnvForTest(t, workflowMachinePrincipalsEnv)
		t.Setenv(legacyScopedWorkflowTokensEnv, "")
		t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
		s := &Server{}
		r := httptest.NewRequest("POST", "/api/v1/manifests?kind=capacity_policy", strings.NewReader(`{"spec":{}}`))
		w := httptest.NewRecorder()
		s.handleManifestCreateGeneric(w, r)
		if w.Code != 401 {
			t.Fatal("production manifest write opened", w.Code)
		}
	})
	t.Run("workflow_principal_cannot_write_policy", func(t *testing.T) {
		t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, "original-workflow-token", "original-native-source-caller", machineWorkflowRef{Namespace: "dakasa", Name: "original-native-qemu"}))
		s := &Server{}
		r := httptest.NewRequest("POST", "https://core.invalid/api/v1/manifests?kind=capacity_policy", strings.NewReader(`{"spec":{}}`))
		r.Header.Set("Authorization", "Bearer original-workflow-token")
		w := httptest.NewRecorder()
		s.handleManifestCreateGeneric(w, r)
		if w.Code != 401 {
			t.Fatal("workflow principal escaped to policy write", w.Code)
		}
	})
}

// Complete six-step source graph at the PUBLIC authenticated dispatcher. SQL
// deliberately refuses the durable INSERT after validation; no original
// native work/phase/permission or successful async supplier is manufactured.
func TestCapacityGuestOriginalPublicWorkflowAdmission(t *testing.T) {
	for _, name := range []string{"complete_graph_reaches_durable_boundary", "unknown_guest_operation_before_insert", "missing_authorization_refused", "wrong_principal_scope_refused", "rbac_denial_refused"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("BROKER_URL", "amqp://source-shape-only")
			t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
			t.Setenv("YGGDRASIL_WORKFLOW_RUN_LEGACY_ENABLED", "")
			t.Setenv(legacyScopedWorkflowTokensEnv, "")
			unsetEnvForTest(t, workflowdispatchlock.EnvName)
			allowed := machineWorkflowRef{Namespace: "dakasa", Name: "original-native-qemu"}
			if name == "wrong_principal_scope_refused" {
				allowed.Name = "different-original"
			}
			t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, "original-workflow-token", "original-native-source-caller", allowed))
			graph := model.WorkflowManifestSpec{DispatchMode: "async", Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: "dakasa", Name: "original-native-rbac"}}}
			closed := false
			graph.InputSchema = model.WorkflowInputSchemaSpec{Required: []string{"mode", "slot", "assessment"}, AdditionalProperties: &closed, Properties: map[string]model.IntegrationSchemaProperty{"mode": {Type: "string", Enum: []any{"baseline", "burst", "observe_reduction_demand", "retire"}}, "slot": {Type: "integer"}, "assessment": {Type: "object"}, "preregistration_id": {Type: "string"}}}
			ids := []string{"original_assess", "original_claim", "original-native-qemu-create", "original_echo_qualified", "original_burst_retire", "original_burst_native_off"}
			ops := []string{"capacity.assess", "capacity.claim", "capacity.provision_original_guest", "capacity.qualify_original_guest_echo", "capacity.retire_original_guest", "capacity.finish_original_guest_retirement"}
			for n, operation := range ops {
				step := model.WorkflowStepSpec{ID: ids[n], Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: operation}, With: map[string]any{"policy": map[string]any{"namespace": "dakasa", "name": "original-native-qemu"}}, TimeoutSeconds: 600, Retry: model.WorkflowRetrySpec{MaxAttempts: 1}}
				if n < 2 {
					step.With["assessment"] = "{{ inputs.assessment }}"
				}
				if n == 1 {
					step.With["generation"] = "{{ steps.original_assess.metadata.generation }}"
					step.Condition = "{{ inputs.mode }} != observe_reduction_demand"
					step.DependsOn = []string{ids[0]}
				}
				if n >= 2 {
					for key, value := range map[string]any{"binding_name": "native-qemu", "slot": "{{ inputs.slot }}", "generation": "{{ steps.original_claim.metadata.generation }}", "fencing_token": "{{ steps.original_claim.metadata.fencing_token }}", "lease_owner": "{{ steps.original_claim.metadata.lease_owner }}"} {
						step.With[key] = value
					}
					step.Condition = "{{ inputs.mode }} == baseline || {{ inputs.mode }} == burst"
					step.DependsOn = []string{ids[1]}
					if n == 3 {
						step.DependsOn = []string{ids[2]}
					}
					if n >= 4 {
						step.Condition = "{{ inputs.mode }} == retire"
						step.With["preregistration_id"] = "{{ inputs.preregistration_id }}"
					}
					if n == 5 {
						step.DependsOn = []string{ids[4]}
						step.With["request_id"] = "{{ steps.original_burst_retire.metadata.request_id }}"
					}
				}
				graph.Steps = append(graph.Steps, step)
			}
			if name == "unknown_guest_operation_before_insert" {
				graph.Steps[2].Use.Operation = "capacity.provision_original_guest_unapproved"
			}
			if name == "missing_authorization_refused" {
				graph.Authorization = nil
			}
			raw, err := json.Marshal(graph)
			if err != nil {
				t.Fatal(err)
			}
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			expect := func(kind, manifestName string, body []byte) {
				now := time.Now().UTC()
				rows := sqlmock.NewRows([]string{"id", "api_version", "kind", "namespace", "name", "version", "active", "description", "labels", "spec", "checksum", "created_at", "updated_at"}).AddRow(uuid.MustParse("11111111-1111-4111-8111-111111111111"), "yggdrasil.io/v1alpha1", kind, "dakasa", manifestName, 1, true, "", []byte(`{}`), body, "source-shape-only", now, now)
				mock.ExpectQuery(`FROM public\.manifests`).WithArgs(kind, "dakasa", manifestName).WillReturnRows(rows)
			}
			expect("workflow", "original-native-qemu", raw)
			if name != "missing_authorization_refused" && name != "wrong_principal_scope_refused" {
				resource := "workflow:dakasa:original-native-qemu"
				if name == "rbac_denial_refused" {
					resource = "workflow:dakasa:different-original"
				}
				expect("rbac", "original-native-rbac", []byte(`{"roles":[{"name":"original-caller","rules":[{"effect":"allow","resources":["`+resource+`"],"actions":["run"]}]}],"bindings":[{"name":"original-caller","subjects":[{"type":"service","id":"original-native-source-caller"}],"roles":["original-caller"]}]}`))
				mock.ExpectBegin().WillReturnError(errors.New("source audit boundary unavailable"))
				if name != "rbac_denial_refused" {
					expect("workflow", "original-native-qemu", raw)
				}
				if name == "complete_graph_reaches_durable_boundary" {
					mock.ExpectExec(`INSERT INTO public\.workflow_runs`).WillReturnError(errors.New("original-source-durable-boundary-reached"))
				}
			}
			s := &Server{db: db, rabbitmq: &amqp.Connection{}, logger: zap.NewNop()}
			mux := http.NewServeMux()
			mux.HandleFunc("POST /api/v1/workflow-runs", s.handleWorkflowRun)
			r := httptest.NewRequest("POST", "https://core.invalid/api/v1/workflow-runs", strings.NewReader(`{"workflow":{"namespace":"dakasa","name":"original-native-qemu"},"inputs":{"mode":"baseline","slot":1,"assessment":{}}}`))
			r.Header.Set("Authorization", "Bearer original-workflow-token")
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			switch name {
			case "complete_graph_reaches_durable_boundary":
				if w.Code < 400 || !strings.Contains(w.Body.String(), "original-source-durable-boundary-reached") {
					t.Fatal("approved four operations did not cross actual public validation", w.Code, w.Body.String())
				}
			case "unknown_guest_operation_before_insert":
				if w.Code < 400 || !strings.Contains(w.Body.String(), "unsupported") {
					t.Fatal("unapproved operation crossed public source admission", w.Code, w.Body.String())
				}
			default:
				if w.Code != 403 {
					t.Fatal("public source authentication/RBAC weakened", w.Code, w.Body.String())
				}
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCapacityGuestOriginalBootstrapBoundary(t *testing.T) {
	t.Setenv("YGGDRASIL_ENV", "production")
	t.Setenv("YGGDRASIL_DEPLOY_TOKEN", "original-deploy-source-token")
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, "original-workflow-token", "original-native-source-caller", machineWorkflowRef{Namespace: "dakasa", Name: "original-native-qemu"}))
	for _, test := range []struct {
		name, token string
		status      int
	}{{"anonymous_refused", "", 401}, {"workflow_token_is_not_deploy", "original-workflow-token", 401}, {"dedicated_deploy_keeps_legacy_gone", "original-deploy-source-token", 410}} {
		t.Run(test.name, func(t *testing.T) {
			s := &Server{}
			mux := http.NewServeMux()
			mux.HandleFunc("POST /api/v1/bootstrap", requireDeployToken(s.handleBootstrap))
			r := httptest.NewRequest("POST", "/api/v1/bootstrap", strings.NewReader(`{"original_guest":true}`))
			if test.token != "" {
				r.Header.Set("Authorization", "Bearer "+test.token)
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != test.status {
				t.Fatal("public bootstrap authority/status changed", w.Code, w.Body.String())
			}
		})
	}
}
