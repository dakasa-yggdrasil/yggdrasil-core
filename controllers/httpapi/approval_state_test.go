package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestValidateGuardianApprovalDecisionTransition(t *testing.T) {
	for _, decision := range []string{model.GuardianApprovalStatusApproved, model.GuardianApprovalStatusRejected} {
		if err := validateGuardianApprovalDecisionTransition(model.GuardianApprovalStatusPending, decision); err != nil {
			t.Fatalf("pending -> %s: %v", decision, err)
		}
	}
	if err := validateGuardianApprovalDecisionTransition(model.GuardianApprovalStatusApproved, model.GuardianApprovalStatusRejected); !errors.Is(err, errGuardianApprovalAlreadyDecided) {
		t.Fatalf("terminal decision must be immutable, got %v", err)
	}
	if err := validateGuardianApprovalDecisionTransition(model.GuardianApprovalStatusPending, model.GuardianApprovalStatusExecuted); err == nil {
		t.Fatal("human decision cannot jump directly to executed")
	}
}

func TestHandleOpsApprovalDecideRequiresPendingRow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectExec(`UPDATE public\.guardian_approvals`).
		WithArgs("approval-1", "approved").
		WillReturnResult(sqlmock.NewResult(0, 0))

	srv := &Server{db: db}
	handler := srv.handleOpsApprovalDecide("approved")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ops/approvals/approval-1/approve", nil)
	req.SetPathValue("id", "approval-1")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("zero updated rows: expected 404, got %d (%s)", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
