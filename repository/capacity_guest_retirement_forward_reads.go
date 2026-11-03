package repository

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var ErrGuestRetirementForwardNativePending = errors.New("authenticated original native OFF observation is pending")

func (s CapacityStore) PrepareGuestRetirementForwardRead(ctx context.Context, id, kind, destroy string) (GuestRetirementForwardRead, error) {
	var out GuestRetirementForwardRead
	if kind != "off" && kind != "absence" || !forwardSourceOrigin(s, "capacity.finish_original_guest_retirement") {
		return out, ErrCapacityConflict
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	x, r, sha, err := s.retirementForwardCurrentTx(ctx, tx, id)
	if err != nil {
		return out, err
	}
	if kind == "off" && destroy != "" {
		return out, ErrCapacityConflict
	}
	if kind == "absence" {
		original, err := retirementForwardDestroyRecordTx(ctx, tx, r, destroy)
		if err != nil || (original.Grant.State != "settled" && original.Grant.State != "confirmed") {
			return out, ErrCapacityConflict
		}
	}
	deadline, ok := ctx.Deadline()
	issued := time.Now()
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return out, err
	}
	budget := min(5*time.Second, time.Until(deadline), x.current.LeaseExpiresAt.Sub(now)-time.Since(issued))
	if !ok || ctx.Err() != nil || budget <= 0 {
		return out, ErrCapacityLease
	}
	issued = time.Now().UTC()
	out = GuestRetirementForwardRead{Schema: GuestRetirementForwardReadSchema, ReadID: uuid.NewString(), AdmissionID: r.ID, RetirementRequestID: id, Kind: kind, AdmissionSHA256: sha, PrefixSHA256: r.PrefixSHA256, OriginalCallerSHA256: r.OriginalCallerSHA256, MutationBindingSHA256: capacity.GuestRetirementSHA(x.binding), AdapterSourceCommit: x.binding.OriginalProviderSourceCommit, Tuple: x.original.Request.Intent.Tuple, DestroyGrantID: destroy, IssuedAtCore: issued, OriginalDeadlineCore: issued.Add(budget)}
	raw, err := json.Marshal(out)
	if err != nil {
		return out, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_retirement_forward_reads(id,admission_id,retirement_request_id,kind,stage,record_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,'prepared',$5,$6,$7::jsonb,clock_timestamp())`, out.ReadID, r.ID, id, kind, capacity.BusinessCreationSHA256(raw), raw, string(raw))
	if err != nil {
		return out, err
	}
	if ctx.Err() != nil {
		return out, ErrCapacityLease
	}
	err = tx.Commit()
	return out, err
}

func forwardReadTransportValid(r GuestRetirementForwardReadReturn) bool {
	c := r.Read
	return r.Schema == GuestRetirementForwardReadReturnSchema && c.Schema == GuestRetirementForwardReadSchema && validCapacityExecutor(c.ReadID) && validCapacityExecutor(c.AdmissionID) && validCapacityExecutor(c.RetirementRequestID) && capacity.ValidDigest(c.AdmissionSHA256) && capacity.ValidDigest(c.PrefixSHA256) && capacity.ValidDigest(c.OriginalCallerSHA256) && !c.IssuedAtCore.IsZero() && c.OriginalDeadlineCore.After(c.IssuedAtCore) && c.OriginalDeadlineCore.Sub(c.IssuedAtCore) <= 5*time.Second && r.Status == "observed" && !r.CallFailed && !r.OriginalContextFailed && !r.StartedAtCore.Before(c.IssuedAtCore) && !r.OriginalReturnedAtCore.Before(r.StartedAtCore) && r.OriginalReturnedAtCore.Before(c.OriginalDeadlineCore)
}

func (s CapacityStore) RecordGuestRetirementForwardRead(ctx context.Context, returned GuestRetirementForwardReadReturn) (model.CapacityMutationProof, error) {
	var proof model.CapacityMutationProof
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return proof, err
	}
	defer tx.Rollback()
	var raw []byte
	var digest string
	var same bool
	var issuedPG time.Time
	err = tx.QueryRowContext(ctx, `SELECT original_wire,record_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb,recorded_at FROM public.capacity_guest_retirement_forward_reads WHERE id=$1 AND admission_id=$2 AND stage='prepared' FOR SHARE`, returned.Read.ReadID, returned.Read.AdmissionID).Scan(&raw, &digest, &same, &issuedPG)
	var challenge GuestRetirementForwardRead
	if err != nil || !same || capacity.BusinessCreationSHA256(raw) != digest || decodeRetirementForward(raw, &challenge) != nil || !reflect.DeepEqual(challenge, returned.Read) {
		return proof, ErrCapacityConflict
	}
	// Persist the actual return before evaluating current-epoch authority. A
	// stale/failed/canceled read remains a diagnostic, never a retry permission.
	wire, err := json.Marshal(returned)
	if err != nil || len(wire) > 2<<20 {
		return proof, ErrCapacityConflict
	}
	var recordedPG time.Time
	err = tx.QueryRowContext(ctx, `INSERT INTO public.capacity_guest_retirement_forward_reads(id,admission_id,retirement_request_id,kind,stage,record_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,'returned',$5,$6,$7::jsonb,clock_timestamp()) RETURNING recorded_at`, challenge.ReadID, challenge.AdmissionID, challenge.RetirementRequestID, challenge.Kind, capacity.BusinessCreationSHA256(wire), wire, string(wire)).Scan(&recordedPG)
	if err != nil {
		return proof, err
	}
	// Commit the actual diagnostic independently before acquiring scope/profile
	// locks. Qualification cannot erase a stale/failed read or invert the ordinary
	// scope -> profile -> current-row lock order.
	if err = tx.Commit(); err != nil {
		return proof, err
	}
	tx, err = s.DB.BeginTx(ctx, nil)
	if err != nil {
		return proof, err
	}
	defer tx.Rollback()
	x, r, sha, currentErr := s.retirementForwardCurrentTx(ctx, tx, challenge.RetirementRequestID)
	accepted, pending := false, false
	if currentErr == nil && r.ID == challenge.AdmissionID && sha == challenge.AdmissionSHA256 && r.PrefixSHA256 == challenge.PrefixSHA256 && r.OriginalCallerSHA256 == challenge.OriginalCallerSHA256 && challenge.Tuple == x.original.Request.Intent.Tuple && challenge.MutationBindingSHA256 == capacity.GuestRetirementSHA(x.binding) && challenge.AdapterSourceCommit == x.binding.OriginalProviderSourceCommit && recordedPG.Sub(issuedPG) >= 0 && recordedPG.Sub(issuedPG)+5*time.Second <= time.Duration(x.spec.MaxEvidenceAgeSeconds)*time.Second && forwardReadTransportValid(returned) {
		switch challenge.Kind {
		case "off":
			original, e := guestOriginalCreateReceiptV2Tx(ctx, tx, x.original)
			if e == nil && returned.Plan != nil && returned.Plan.Server != nil && returned.Observation == nil && returned.OriginalDestroyReceipt == nil && challenge.DestroyGrantID == "" && returned.Plan.Server.Labels["yggdrasil.io/owner"] == x.spec.Owner {
				accepted = capacity.GuestRetirementV2NativeOffPlanContent(x.spec, x.binding, *returned.Plan, original) == nil
				if !accepted && returned.Plan.Server.Status == "stopping" {
					copyPlan := *returned.Plan
					copyServer := *returned.Plan.Server
					copyPlan.Server = &copyServer
					copyServer.Status = "off"
					if challenge.Tuple.Provider == "aws" {
						copyServer.Status = "stopped"
					}
					pending = capacity.GuestRetirementV2NativeOffPlanContent(x.spec, x.binding, copyPlan, original) == nil
				}
			}
			if accepted {
				qualified := r
				qualified.Stage = "off_qualified"
				qualified.AdmissionSHA256 = sha
				qualified.RecordedAt = recordedPG
				qualified.NativeOffReadID = challenge.ReadID
				qualified.NativeOffSHA256 = capacity.BusinessCreationSHA256(wire)
				// Repeated fresh OFF reads do not rewrite the first immutable qualification.
				var exists bool
				if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forwards WHERE id=$1 AND stage='off_qualified')`, r.ID).Scan(&exists); err != nil {
					return proof, err
				}
				if !exists {
					if _, err = insertRetirementForwardTx(ctx, tx, qualified); err != nil {
						return proof, err
					}
					next := x.current
					next.RetirementForward = retirementForwardMarker(qualified)
					next.UpdatedAt = recordedPG
					if err = persistRetirementForwardIntentTx(ctx, tx, x.current, next, "retirement-forward:"+r.ID+":off_qualified"); err != nil {
						return proof, err
					}
				}
			}
		case "absence":
			original, e := retirementForwardDestroyRecordTx(ctx, tx, r, challenge.DestroyGrantID)
			if e == nil {
				proof, e = retirementForwardAbsenceContent(returned, x.spec, original)
				accepted = e == nil
				if accepted {
					proof.ObservedAt = recordedPG
				} else if returned.Observation != nil && returned.OriginalDestroyReceipt != nil && reflect.DeepEqual(*returned.OriginalDestroyReceipt, guestMutationReceiptV2(original)) {
					if challenge.Tuple.Provider == "aws" {
						pending = guestForwardAWSAbsencePending(*returned.Observation, *returned.OriginalDestroyReceipt)
					} else {
						pending = guestForwardHetznerAbsencePending(*returned.Observation, *returned.OriginalDestroyReceipt)
					}
				}
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return model.CapacityMutationProof{}, err
	}
	if pending {
		return proof, ErrGuestRetirementForwardNativePending
	}
	if !accepted {
		return model.CapacityMutationProof{}, ErrCapacityConflict
	}
	return proof, nil
}

func retirementForwardAbsenceContent(r GuestRetirementForwardReadReturn, p model.CapacityPolicySpec, original capacityMutationRecord) (model.CapacityMutationProof, error) {
	var empty model.CapacityMutationProof
	if !forwardReadTransportValid(r) || r.Read.Kind != "absence" || r.Plan != nil || r.Observation == nil || r.OriginalDestroyReceipt == nil || r.Read.DestroyGrantID != original.Grant.GrantID || original.Settlement == nil || !original.Settlement.TransportCompleted || original.Settlement.Outcome != "accepted" {
		return empty, ErrCapacityConflict
	}
	receipt := *r.OriginalDestroyReceipt
	expectedCurrent := receipt
	if original.Grant.State == "confirmed" && receipt.Grant.State == "settled" {
		expectedCurrent.Grant.State = "confirmed"
	}
	if original.Grant.State != "settled" && original.Grant.State != "confirmed" || !reflect.DeepEqual(expectedCurrent, guestMutationReceiptV2(original)) {
		return empty, ErrCapacityConflict
	}
	if capacity.AWSOriginalMutationPair(original.Binding) {
		x := original.Settlement.OriginalProviderDestroyReturn
		if x == nil || x.Schema != "aws_original_terminate_instances_return_v1" || x.Provider != "aws" || x.AdapterSourceCommit != original.Binding.OriginalProviderSourceCommit || x.GrantID != receipt.Grant.GrantID || x.AttemptID != original.AttemptID || x.RequestSHA256 != receipt.Grant.RequestSHA256 || x.ResourceID != receipt.Grant.ExpectedResourceID || x.ResourceCreatedAt != receipt.Grant.ExpectedResourceCreatedAt || x.ActionID != receipt.ActionID || x.NextActionIDs == nil || len(x.NextActionIDs) != 0 || x.ResponseStatus != 200 || !capacity.ValidDigest(x.ResponseBodySHA256) || x.ResponseBytes < 2 || x.ResponseBytes > 2<<20 {
			return empty, ErrCapacityConflict
		}
		called, a := time.Parse(time.RFC3339Nano, x.CalledAt)
		returned, b := time.Parse(time.RFC3339Nano, x.ReturnedAt)
		deadline, c := time.Parse(time.RFC3339Nano, x.ContextDeadline)
		if a != nil || b != nil || c != nil || called.IsZero() || returned.Before(called) || !returned.Before(deadline) || deadline.Sub(called) > 60*time.Second {
			return empty, ErrCapacityConflict
		}
	}
	return capacity.GuestRetirementV2NativeAbsenceContent(p, original.Binding, receipt, *r.Observation, "original-forward-native-absence:"+r.Read.ReadID)
}
