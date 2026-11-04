package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestOriginalDispositionRequestAcceptsOnlyOneOriginalGrantIdentity(t *testing.T) {
	id := "220f344f-4ea9-4fbc-a195-2c1b1c5212b6"
	good := `{"grant_id":"` + id + `"}`
	got, err := decodeOriginalDispositionGrant(strings.NewReader(good))
	if err != nil || got != id {
		t.Fatal("exact original identity refused", err)
	}
	for _, raw := range []string{`{}`, `null`, `[]`, `{"grant_id":null}`, `{"grant_id":"00000000-0000-0000-0000-000000000000"}`, `{"grant_id":"` + strings.ToUpper(id) + `"}`, `{"grant_id":"` + id + `","grant_id":"` + id + `"}`, `{"grant_id":"` + id + `","resource_absent":true}`, `{"grant_id":"` + id + `","issuer":"root"}`, good + good, good + strings.Repeat(" ", 4097)} {
		if _, err := decodeOriginalDispositionGrant(strings.NewReader(raw)); err == nil {
			t.Fatalf("foreign or ambiguous request accepted: %.120s", raw)
		}
	}
}

func TestOriginalDispositionNeverInheritsMachineOrWarnModeActorBypass(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")
	server := &Server{}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		r := httptest.NewRequest(method, "/api/v1/ops/capacity/original-create-dispositions", strings.NewReader(`{"grant_id":"220f344f-4ea9-4fbc-a195-2c1b1c5212b6"}`))
		w := httptest.NewRecorder()
		if method == http.MethodPost {
			server.handleOpsOriginalCreateDisposition(w, r)
		} else {
			server.handleOpsOriginalCreateDispositionRead(w, r)
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("no-claims actor reached nil DB/native: %d", w.Code)
		}
	}
}

func TestOriginalDispositionHTTPProjectionRetainsNoNativeBodiesOrCapacityAuthority(t *testing.T) {
	record := model.CapacityOriginalCreateDisposition{ID: "declared-disposition", GrantID: "declared-original", OriginalAcceptedUnchanged: true,
		Observation: model.CapacityOriginalCreateDispositionObservation{InventoryBasis: "aws_original_run_instances_cloudtrail_root_snapshot_absence_v1", NativeReads: []model.CapacityOriginalCreateDispositionNativeRead{{ResponseBodyBase64: "DECLARED_PRIVATE_NATIVE_BODY"}}}}
	raw, err := json.Marshal(dispositionSummary(record))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "DECLARED_PRIVATE_NATIVE_BODY") || strings.Contains(string(raw), "response_body_base64") {
		t.Fatal("private native evidence leaked into HTTP projection")
	}
	if !strings.Contains(string(raw), `"serving_or_business_or_savings_authority":false`) || !strings.Contains(string(raw), `"original_accepted_unchanged":true`) || !strings.Contains(string(raw), `"original_auxiliary_inventory_complete":false`) || !strings.Contains(string(raw), `"inventory_basis":"aws_original_run_instances_cloudtrail_root_snapshot_absence_v1"`) {
		t.Fatal("disposition relabelled the original or claimed capacity")
	}
}

func TestOriginalDispositionRequiresActualAdministrativeGrantEvenInWarnMode(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")
	for _, admin := range []bool{false, true} {
		server, mock := rbacTestSetup(t)
		actor := uuid.New()
		permissions := []string{"yggdrasil:manage_workflows"}
		if admin {
			permissions = []string{"yggdrasil:*"}
		}
		programCollaboratorWithPermissions(mock, actor, permissions)
		request := rbacTestRequestWithClaims(http.MethodPost, "/api/v1/ops/capacity/original-create-dispositions", actor)
		response := httptest.NewRecorder()
		issuer, ok := server.originalDispositionIssuer(response, request)
		if ok != admin || admin && issuer != "collaborator:"+actor.String() || !admin && response.Code != http.StatusForbidden {
			t.Fatal("administrative boundary changed", admin, issuer, ok, response.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	}
}
