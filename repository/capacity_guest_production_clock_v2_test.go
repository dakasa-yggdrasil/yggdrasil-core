package repository

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestGuestProductionClockV2RepositoryRefusesMissingAuthority(t *testing.T) {
	for _, mode := range []string{"nil_db", "nil_context", "no_deadline", "long_deadline", "canceled", "bad_boot", "bad_nonce", "bad_key", "missing_original"} {
		t.Run(mode, func(t *testing.T) {
			db, mock, e := sqlmock.New()
			if e != nil {
				t.Fatal(e)
			}
			defer db.Close()
			s := CapacityStore{DB: db}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			boot, nonce := "10000000-0000-4000-8000-000000000001", strings.Repeat("a", 64)
			key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("c", 32)))
			switch mode {
			case "nil_db":
				s.DB = nil
			case "nil_context":
				ctx = nil
			case "no_deadline":
				ctx = context.Background()
			case "long_deadline":
				ctx, cancel = context.WithTimeout(t.Context(), time.Hour)
				defer cancel()
			case "canceled":
				cancel()
			case "bad_boot":
				boot = "bad"
			case "bad_nonce":
				nonce = "bad"
			case "bad_key":
				key = nil
			case "missing_original":
				mock.ExpectBegin()
				mock.ExpectQuery("SELECT m.namespace,m.environment,m.domain,m.dimension").WillReturnError(errors.New("synthetic original read failure"))
				mock.ExpectRollback()
			}
			v, e := s.GuestOriginalProfileAuthorityV2(ctx, "synthetic", "10000000-0000-4000-8000-000000000002", "member", 1, strings.Repeat("a", 64), "123", boot, nonce, key)
			if e == nil || v.Schema != "" || v.Signature != "" {
				t.Fatal("absent/late original gained authority")
			}
			if e = mock.ExpectationsWereMet(); e != nil {
				t.Fatal(e)
			}
		})
	}
}

// Native PostgreSQL representation/immutable-wire coverage ONLY. These expired,
// unsigned rows roll back and do not pass current policy, enrollment signature,
// compiled approval, original provider or native-process authority.
func TestGuestProductionClockV2PostgresImmutableReceiptHashDomains(t *testing.T) {
	db := guestOriginalPostgres(t)
	for _, mode := range []string{"exact_separate_objects", "registration_hash_conflated", "result_hash_conflated", "foreign_statement"} {
		t.Run(mode, func(t *testing.T) {
			tx, ctx := guestOriginalStorageTx(t, db)
			f := guestOriginalStorageRecords(t)
			guestOriginalStoragePre(t, tx, ctx, f, f.wire, f.wire, f.pre.OriginalDeadline)
			r := model.CapacityGuestOriginalProvisioningRegistration{Result: model.CapacityGuestOriginalProvisioningResult{Schema: "unqualified_expired_storage_only", PreregistrationID: f.pre.PreregistrationID, Writers: []model.CapacityGuestRetirementWriter{}}, EnrollmentStatement: model.CapacityGuestRetirementEnrollmentStatement{Writers: []model.CapacityGuestRetirementWriter{}}}
			if json.Unmarshal([]byte(`[]`), &r.Result.WriterPlacements) != nil {
				t.Fatal("fixture allocation")
			}
			r.Result.ProtectedCensus.Processes = []model.CapacityGuestRetirementNativeProcess{}
			r.Result.BootstrapOriginalJournal.ParentAncestry = []int{}
			r.Result.BootstrapOriginalObservation.Journal.ParentAncestry = []int{}
			r.EnrollmentStatement.OriginalNativeResultSHA256 = capacity.GuestRetirementSHA(r.Result)
			receipt := model.CapacityGuestOriginalProvisioningReceipt{PreregistrationID: f.pre.PreregistrationID, OriginalProvisioningSHA256: capacity.GuestRetirementSHA(r), Enrollment: model.CapacityGuestRetirementEnrollment{Statement: r.EnrollmentStatement}, RecordedAt: f.pre.ReservedAt}
			if capacity.GuestRetirementSHA(r) == capacity.GuestRetirementSHA(r.Result) {
				t.Fatal("different object domains collapsed")
			}
			switch mode {
			case "registration_hash_conflated":
				receipt.OriginalProvisioningSHA256 = capacity.GuestRetirementSHA(r.Result)
			case "result_hash_conflated":
				receipt.Enrollment.Statement.OriginalNativeResultSHA256 = capacity.GuestRetirementSHA(r)
			case "foreign_statement":
				receipt.Enrollment.Statement.BindingName = "foreign-storage-member"
			}
			raw, _ := json.Marshal(r)
			wire, _ := json.Marshal(receipt)
			enrollment, _ := json.Marshal(receipt.Enrollment)
			_, e := tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_original_enrollments(preregistration_id,resource_tuple_sha256,enrollment_sha256,original_provisioning_sha256,enrollment_record,recorded_at,registration_wire,receipt_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8)`, f.pre.PreregistrationID, capacity.GuestRetirementSHA(r.Result.Tuple), capacity.GuestRetirementSHA(receipt.Enrollment), receipt.OriginalProvisioningSHA256, string(enrollment), receipt.RecordedAt, raw, wire)
			if e != nil {
				t.Fatal(e)
			}
			actual, digest, e := loadGuestReceiptTx(ctx, tx, f.pre.PreregistrationID)
			if (e == nil) != (mode == "exact_separate_objects") {
				t.Fatal("immutable registration/result domains changed", e)
			}
			if e == nil && (digest != capacity.GuestRetirementSHA(r) || capacity.GuestRetirementSHA(actual) != capacity.GuestRetirementSHA(receipt)) {
				t.Fatal("native BYTEA receipt did not preserve exact objects")
			}
		})
	}
}
