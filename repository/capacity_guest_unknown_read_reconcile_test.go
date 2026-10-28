package repository

import (
	"context"
	"encoding/json"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestHistoricalUnknownReadTransportKeepsUncertainty(t *testing.T) {
	now := time.Now().UTC()
	start := now.Add(-10 * time.Second)
	row := model.CapacityInstalledGuestPreviousCanary{ChallengeID: "11111111-1111-4111-8111-111111111111", Phase: "read", PossibleSend: true, Outcome: "held"}
	original := capacity.GuestOriginalHTTPReturn{StartedAt: start, DoStartedAt: start.Add(time.Millisecond), DoReturnedAt: start.Add(5 * time.Second), DriverReturnedAt: start.Add(5*time.Second + time.Millisecond), DoFailed: true, OriginalContextFailed: true, ResponseBodyScope: capacity.GuestOriginalBodyNoRead, RetainedPrefixSHA256: capacity.BusinessCreationSHA256(nil)}
	for _, name := range []string{"original", "publication", "unsent", "accepted", "preflight", "do_success", "read_failed", "close_failed", "context_alive", "status", "body_scope", "body_bytes", "close_return", "missing_hash", "future", "reversed_start", "reversed_do", "reversed_driver"} {
		t.Run(name, func(t *testing.T) {
			r, o := row, original
			switch name {
			case "publication":
				r.Phase = "publish"
			case "unsent":
				r.PossibleSend = false
			case "accepted":
				r.Outcome = "accepted"
			case "preflight":
				o.PreflightFailed = true
			case "do_success":
				o.DoFailed = false
			case "read_failed":
				o.ReadFailed = true
			case "close_failed":
				o.CloseFailed = true
			case "context_alive":
				o.OriginalContextFailed = false
			case "status":
				o.Status = 200
			case "body_scope":
				o.ResponseBodyScope = capacity.GuestOriginalBodyCompleteRead
			case "body_bytes":
				o.Body = []byte("unexpected")
			case "close_return":
				o.CloseReturnedAt = start
			case "missing_hash":
				o.RetainedPrefixSHA256 = ""
			case "future":
				o.DriverReturnedAt = now.Add(time.Second)
			case "reversed_start":
				o.DoStartedAt = start.Add(-time.Second)
			case "reversed_do":
				o.DoReturnedAt = start
			case "reversed_driver":
				o.DriverReturnedAt = start
			}
			if got := historicalUnknownReadTransport(r, o, now); got != (name == "original") {
				t.Fatal("incomplete original read was relabeled or unsafe input admitted", name, got)
			}
		})
	}
}

func TestHistoricalUnknownReadRetainsOriginalAndVerifierIsRequired(t *testing.T) {
	now := time.Now().UTC()
	at := now.Add(-time.Minute)
	id := "11111111-1111-4111-8111-111111111111"
	original := capacity.GuestOriginalHTTPReturn{StartedAt: at, DoStartedAt: at.Add(time.Millisecond), DoReturnedAt: at.Add(5 * time.Second), DriverReturnedAt: at.Add(5*time.Second + time.Millisecond), DoFailed: true, OriginalContextFailed: true, ResponseBodyScope: capacity.GuestOriginalBodyNoRead, RetainedPrefixSHA256: capacity.BusinessCreationSHA256(nil)}
	wire, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"verified", "missing_verifier", "refused_verifier", "changed_digest", "extra_field"} {
		t.Run(mode, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectBegin()
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			policy := model.Manifest{ID: uuid.New()}
			old := model.CapacityIntent{Generation: 8, FencingToken: 20}
			dbWire, returnSHA := wire, capacity.BusinessCreationSHA256(wire)
			if mode == "changed_digest" {
				returnSHA = capacity.BusinessCreationSHA256([]byte("changed"))
			}
			if mode == "extra_field" {
				var v map[string]any
				_ = json.Unmarshal(wire, &v)
				v["unexpected"] = true
				dbWire, _ = json.Marshal(v)
			}
			mock.ExpectQuery("SELECT c.id::text,c.phase").WithArgs(policy.ID, old.Generation, old.FencingToken).WillReturnRows(sqlmock.NewRows([]string{"id", "phase", "deadline", "send", "outcome", "transport", "return_sha"}).AddRow(id, "read", at.Add(5*time.Second), true, "held", dbWire, returnSHA))
			var verify installedUncertainReadVerifier
			if mode != "missing_verifier" {
				verify = func(gotID string, row model.CapacityInstalledGuestPreviousCanary, raw []byte, transport capacity.GuestOriginalHTTPReturn) error {
					if mode == "refused_verifier" {
						return ErrCapacityConflict
					}
					if gotID != id || string(raw) != string(wire) || !historicalUnknownReadTransport(row, transport, now) {
						return ErrCapacityConflict
					}
					return nil
				}
			}
			got, err := previousInstalledCanariesWithReadVerifier(context.Background(), tx, policy, old, now, verify)
			if mode == "verified" {
				if err != nil || len(got) != 1 || got[0].Outcome != "held" || got[0].OriginalTransportState != "unknown_read_timeout" || got[0].OriginalTransportSHA256 != capacity.BusinessCreationSHA256(wire) || got[0].ClosedHTTPStatus != 0 {
					t.Fatal("original uncertainty was not preserved", got, err)
				}
			} else if err == nil {
				t.Fatal("unverified incomplete read admitted")
			}
			mock.ExpectRollback()
			_ = tx.Rollback()
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Exercises the real verifier with source-derived signed challenge and accepted
// publication operands through the real SQL readers. SQL rows are unit test
// operands; this never asserts a real Guest, provider, or production authority.
func TestHistoricalUnknownReadVerifiesSignedSQLLineage(t *testing.T) {
	p, read, enrollment, publication, publicationReturn, at := recoveryPublicationFixture(t)
	p.GuestRetirementBinding.GuestSourceCommit = originalReadGuestSource
	p.GuestRetirementBinding.CoreAuthoritySourceCommit = originalReadCoreSource
	if p.GuestNotifyCanaryBinding.NotifySourceCommit != originalReadNotifySource || p.GuestNotifyCanaryBinding.QuerySHA256 != originalReadQuerySHA256 {
		t.Fatal("source fixture differs")
	}
	policy := model.Manifest{ID: uuid.MustParse(read.PolicyID), Checksum: read.PolicyChecksum}
	workflowID := uuid.MustParse(read.WorkflowID)
	store := CapacityStore{WorkflowID: workflowID, guestReconcile: &guestReconcileSource{workflow: model.Manifest{Checksum: read.WorkflowChecksum}}}
	old := model.CapacityIntent{Generation: int64(read.Generation), FencingToken: int64(read.Fence), LeaseOwner: read.LeaseOwner, LeaseExecutorID: "unit-executor", InstalledGuestReconcile: &model.CapacityInstalledGuestReconcile{Attempt: 1, NewFence: int64(read.Fence), OriginalFailurePreserved: true}}
	stored := guestOriginalStored{binding: *p.GuestRetirementBinding, pre: model.CapacityGuestOriginalProvisioningPreregistration{PreregistrationID: read.PreregistrationID}}
	row := model.CapacityInstalledGuestPreviousCanary{ChallengeID: read.ChallengeID, Phase: "read", PossibleSend: true, Outcome: "held"}
	returned := capacity.GuestOriginalHTTPReturn{StartedAt: read.IssuedAt.Add(2 * time.Millisecond), DoStartedAt: read.IssuedAt.Add(3 * time.Millisecond), DoReturnedAt: read.OriginalDeadline.Add(time.Millisecond), DriverReturnedAt: read.OriginalDeadline.Add(2 * time.Millisecond), DoFailed: true, OriginalContextFailed: true, ResponseBodyScope: capacity.GuestOriginalBodyNoRead, RetainedPrefixSHA256: capacity.BusinessCreationSHA256(nil)}
	marshal := func(v any) []byte {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	originalPubWire := marshal(publicationReturn)
	digest := capacity.BusinessCreationSHA256(originalPubWire)
	originalPub := capacity.GuestOriginalHTTPReturn{StartedAt: at.Add(-10 * time.Millisecond), DoStartedAt: at.Add(-9 * time.Millisecond), DoReturnedAt: at.Add(-2 * time.Millisecond), ReadReturnedAt: at.Add(-time.Millisecond), CloseReturnedAt: at, DriverReturnedAt: at.Add(500 * time.Microsecond), Status: 200, ReceivedBodyBytes: len(originalPubWire), ResponseSHA256: digest, ResponseBodyScope: capacity.GuestOriginalBodyCompleteRead, RetainedPrefixBytes: len(originalPubWire), RetainedPrefixSHA256: digest}
	if capacity.ValidateGuestNotifyCanaryEnvelope(publication, enrollment, publicationReturn, originalPub.DriverReturnedAt) != nil {
		t.Fatal("signed publication invalid")
	}
	for _, mode := range []string{"valid", "wrong_executor", "tampered_nonce", "bad_parent_digest", "wrong_source"} {
		t.Run(mode, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectBegin()
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			localRead, localStore := read, store
			if mode == "wrong_source" {
				cp := p
				binding := *p.GuestRetirementBinding
				binding.GuestSourceCommit = "wrong"
				cp.GuestRetirementBinding = &binding
				err = localStore.verifyHistoricalUnknownReadTx(context.Background(), tx, policy, cp, old, stored, enrollment, at.Add(10*time.Second), read.ChallengeID, row, returned)
				if err == nil {
					t.Fatal("wrong source accepted")
				}
				mock.ExpectRollback()
				_ = tx.Rollback()
				if err = mock.ExpectationsWereMet(); err != nil {
					t.Fatal(err)
				}
				return
			}
			expectChallenge := func(c model.CapacityGuestNotifyCanaryChallenge, tamper bool) {
				pre := c
				pre.GuestNonce = model.CapacityGuestNotifyCanaryNonce{}
				pre.Signature = ""
				nonce := c.GuestNonce
				if tamper {
					nonce.NonceSHA256 = capacity.BusinessCreationSHA256([]byte("tampered"))
				}
				mock.ExpectQuery("SELECT original_wire,challenge_sha256").WithArgs(c.ChallengeID).WillReturnRows(sqlmock.NewRows([]string{"wire", "sha", "consistent"}).AddRow(marshal(pre), capacity.GuestRetirementSHA(pre), true))
				mock.ExpectQuery("SELECT final_challenge_wire,nonce_wire,final_challenge_sha256").WithArgs(c.ChallengeID).WillReturnRows(sqlmock.NewRows([]string{"wire", "nonce", "sha"}).AddRow(marshal(c), marshal(nonce), capacity.GuestRetirementSHA(c)))
			}
			expectChallenge(localRead, mode == "tampered_nonce")
			if mode != "tampered_nonce" {
				executor := old.LeaseExecutorID
				if mode == "wrong_executor" {
					executor = "different-executor"
				}
				mock.ExpectQuery("SELECT c.executor_id,a.issuer_actual_source_commit").WithArgs(read.ChallengeID).WillReturnRows(sqlmock.NewRows([]string{"executor", "issuer", "issued", "challenge"}).AddRow(executor, originalReadCoreSource, capacity.GuestRetirementSHA(read), capacity.GuestRetirementSHA(read)))
				if mode != "wrong_executor" {
					request := marshal(model.CapacityGuestNotifyCanaryRequest{Challenge: read})
					mock.ExpectQuery("SELECT request_sha256,possible_send_at,original_deadline").WithArgs(read.ChallengeID).WillReturnRows(sqlmock.NewRows([]string{"sha", "sent", "deadline"}).AddRow(capacity.BusinessCreationSHA256(request), read.IssuedAt.Add(time.Millisecond), read.OriginalDeadline))
					expectChallenge(publication, false)
					mock.ExpectQuery("SELECT p.executor_id=r.executor_id").WithArgs(publication.ChallengeID, read.ChallengeID).WillReturnRows(sqlmock.NewRows([]string{"same"}).AddRow(true))
					pubDigest := digest
					if mode == "bad_parent_digest" {
						pubDigest = capacity.BusinessCreationSHA256([]byte("tampered"))
					}
					mock.ExpectQuery("SELECT original_wire,original_transport,return_sha256").WithArgs(publication.ChallengeID).WillReturnRows(sqlmock.NewRows([]string{"wire", "transport", "sha"}).AddRow(originalPubWire, marshal(originalPub), pubDigest))
				}
			}
			err = localStore.verifyHistoricalUnknownReadTx(context.Background(), tx, policy, p, old, stored, enrollment, at.Add(10*time.Second), read.ChallengeID, row, returned)
			if (err == nil) != (mode == "valid") {
				t.Fatalf("mode %s: %v", mode, err)
			}
			mock.ExpectRollback()
			_ = tx.Rollback()
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
