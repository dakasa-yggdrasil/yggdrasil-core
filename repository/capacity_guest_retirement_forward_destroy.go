package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const retirementForwardEligibilitySchema = "original_guest_partial_poweroff_delete_eligibility_v1"

type retirementForwardEligibility struct {
	Schema          string `json:"schema"`
	AdmissionID     string `json:"admission_id"`
	AdmissionSHA256 string `json:"admission_sha256"`
	NativeOffReadID string `json:"native_off_read_id"`
	NativeOffSHA256 string `json:"native_off_sha256"`
}

func loadForwardReadReturnTx(ctx context.Context, tx *sql.Tx, id string) (GuestRetirementForwardReadReturn, time.Time, string, error) {
	var r GuestRetirementForwardReadReturn
	var raw, challengeRaw []byte
	var sha, challengeSHA string
	var when, issued time.Time
	var same, challengeSame bool
	err := tx.QueryRowContext(ctx, `SELECT v.original_wire,v.record_sha256,v.recorded_at,v.original_record=convert_from(v.original_wire,'UTF8')::jsonb,c.original_wire,c.record_sha256,c.original_record=convert_from(c.original_wire,'UTF8')::jsonb,c.recorded_at FROM public.capacity_guest_retirement_forward_reads v JOIN public.capacity_guest_retirement_forward_reads c ON c.id=v.id AND c.stage='prepared' WHERE v.id=$1 AND v.stage='returned'`, id).Scan(&raw, &sha, &when, &same, &challengeRaw, &challengeSHA, &challengeSame, &issued)
	var c GuestRetirementForwardRead
	if err != nil {
		return r, when, "", err
	}
	if !same || !challengeSame || capacity.BusinessCreationSHA256(raw) != sha || capacity.BusinessCreationSHA256(challengeRaw) != challengeSHA || decodeRetirementForward(raw, &r) != nil || decodeRetirementForward(challengeRaw, &c) != nil || !reflect.DeepEqual(c, r.Read) || when.Before(issued) || !forwardReadTransportValid(r) {
		return r, when, "", ErrCapacityConflict
	}
	return r, issued, sha, nil
}
func (s CapacityStore) retirementForwardOffTx(ctx context.Context, tx *sql.Tx, x retirementForwardSnapshot, r GuestRetirementForward, admissionSHA string, now time.Time) (retirementForwardEligibility, error) {
	var out retirementForwardEligibility
	var id string
	// Newest actual return, including failure/pending, must itself qualify. No
	// filtering chooses an older favorable return after an uncertain newer read.
	err := tx.QueryRowContext(ctx, `SELECT id::text FROM public.capacity_guest_retirement_forward_reads WHERE admission_id=$1 AND kind='off' AND stage='returned' ORDER BY recorded_at DESC,id DESC LIMIT 1`, r.ID).Scan(&id)
	if err != nil {
		return out, err
	}
	read, issued, sha, err := loadForwardReadReturnTx(ctx, tx, id)
	if err != nil || read.Read.AdmissionID != r.ID || read.Read.AdmissionSHA256 != admissionSHA || read.Read.PrefixSHA256 != r.PrefixSHA256 || read.Read.OriginalCallerSHA256 != r.OriginalCallerSHA256 || read.Read.Tuple != x.original.Request.Intent.Tuple || read.Read.MutationBindingSHA256 != capacity.GuestRetirementSHA(x.binding) || read.Read.AdapterSourceCommit != x.binding.OriginalProviderSourceCommit || now.Sub(issued) < 0 || now.Sub(issued)+5*time.Second > time.Duration(x.spec.MaxEvidenceAgeSeconds)*time.Second || read.Plan == nil || read.Plan.Server == nil || read.Plan.Server.Labels["yggdrasil.io/owner"] != x.spec.Owner {
		return out, ErrCapacityConflict
	}
	create, err := guestOriginalCreateReceiptV2Tx(ctx, tx, x.original)
	if err != nil || capacity.GuestRetirementV2NativeOffPlanContent(x.spec, x.binding, *read.Plan, create) != nil {
		return out, ErrCapacityConflict
	}
	return retirementForwardEligibility{Schema: retirementForwardEligibilitySchema, AdmissionID: r.ID, AdmissionSHA256: admissionSHA, NativeOffReadID: id, NativeOffSHA256: sha}, nil
}
func (s CapacityStore) retirementForwardFloorTx(ctx context.Context, tx *sql.Tx, x retirementForwardSnapshot, r GuestRetirementForward) error {
	adopted := r.DestroyGrantID
	var err error
	if adopted != "" {
		g, e := retirementForwardDestroyRecordTx(ctx, tx, r, adopted)
		if e != nil || g.Settlement == nil || (g.Grant.State != "settled" && g.Grant.State != "confirmed") || g.Settlement.Outcome != "accepted" || !g.Settlement.TransportCompleted {
			return ErrCapacityConflict
		}
	}
	if adopted == "" {
		if err = s.guestRetirementFloorTx(ctx, tx, x.policy.Metadata.Namespace, x.spec, x.current, x.binding, x.original.Request.Intent.Slot, x.now); err != nil {
			return err
		}
	} else {
		var live, fresh, pending int
		err = tx.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE (slot_record->>'observed_at')::timestamptz BETWEEN $6 AND $7) FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND slot<>$5 AND resource_id<>''`, x.policy.Metadata.Namespace, x.spec.Environment, x.spec.Domain, x.spec.Dimension, x.original.Request.Intent.Slot, x.now.Add(-time.Duration(x.spec.MaxEvidenceAgeSeconds)*time.Second), x.now).Scan(&live, &fresh)
		if err != nil || live != fresh || live < x.spec.Floor || live < x.current.Decision.Units {
			return ErrCapacityConflict
		}
		err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE `+capacityGrantUndisposedSQL+` AND integration_instance_id=$1 AND scope_checksum=$2 AND profile_name=$3 AND state IN('issued','redeemed','settled','compensating') AND id::text<>$4`, x.binding.IntegrationInstanceID, x.binding.ScopeChecksum, x.binding.ProfileName, adopted).Scan(&pending)
		if err != nil || pending != 0 {
			return ErrCapacityConflict
		}
	}
	return s.retirementForwardUsefulFloorTx(ctx, tx, x, r)
}
func (s CapacityStore) retirementForwardUsefulFloorTx(ctx context.Context, tx *sql.Tx, x retirementForwardSnapshot, r GuestRetirementForward) error {
	barrier := r.RecordedAt
	if r.DestroyGrantID == "" {
		var offPG time.Time
		if err := tx.QueryRowContext(ctx, `SELECT recorded_at FROM public.capacity_guest_retirement_forward_reads WHERE admission_id=$1 AND kind='off' AND stage='returned' ORDER BY recorded_at DESC,id DESC LIMIT 1`, r.ID).Scan(&offPG); err != nil {
			return err
		}
		if offPG.After(barrier) {
			barrier = offPG
		}
	}
	useful, err := s.guestNotifyUsefulMembersTx(ctx, tx, x.policy, x.spec, x.current, x.original.Request.Intent.Slot, x.now, "after_retirement_floor", barrier)
	if err != nil || useful < x.spec.Floor || useful < x.current.Decision.Units {
		return ErrCapacityConflict
	}
	return nil
}
func (s CapacityStore) AdvanceGuestRetirementForwardDrained(ctx context.Context, policy model.Manifest, generation, fence int64, owner, id string) (model.CapacityIntent, error) {
	var out model.CapacityIntent
	if !forwardSourceOrigin(s, "capacity.finish_original_guest_retirement") {
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
	if x.policy.ID != policy.ID || x.policy.Checksum != policy.Checksum || r.Generation != generation || r.Fence != fence || r.LeaseOwner != owner {
		return out, ErrCapacityConflict
	}
	if _, err = s.retirementForwardOffTx(ctx, tx, x, r, sha, x.now); err != nil {
		return out, err
	}
	if err = s.retirementForwardFloorTx(ctx, tx, x, r); err != nil {
		return out, err
	}
	out = x.current
	if out.Phase == "drained" {
		return out, nil
	}
	out.Phase = "drained"
	out.UpdatedAt = x.now
	if err = persistRetirementForwardIntentTx(ctx, tx, x.current, out, "retirement-forward:"+r.ID+":drained"); err != nil {
		return out, err
	}
	if ctx.Err() != nil {
		return out, ErrCapacityLease
	}
	err = tx.Commit()
	return out, err
}

func (s CapacityStore) guestForwardDestroyEligibilityTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, current model.CapacityIntent, b model.CapacityMutationBinding, slot int, resourceID, created string, now time.Time, grantID string) error {
	if current.RetirementForward == nil {
		return ErrCapacityConflict
	}
	// Adapter redemption has no workflow request context. Derive the owning
	// run exclusively from this grant's immutable server-side admission after
	// the ordinary callback has authenticated its principal/epoch/lease.
	if grantID != "" {
		admission, _, err := loadRetirementForwardTx(ctx, tx, current.RetirementForward.ID, "admitted")
		if err != nil || admission.Generation != current.Generation || admission.Fence != current.FencingToken || admission.ExecutorID != s.ExecutorID || admission.LeaseOwner != current.LeaseOwner {
			return ErrCapacityConflict
		}
		if _, err = retirementForwardDestroyRecordTx(ctx, tx, admission, grantID); err != nil {
			return err
		}
		s.OriginalRunID, err = uuid.Parse(admission.RunID)
		if err != nil || s.OriginalRunID == uuid.Nil {
			return ErrCapacityConflict
		}
	}
	x, r, sha, err := s.retirementForwardCurrentTx(ctx, tx, current.RetirementForward.RetirementRequestID)
	if err != nil || x.policy.ID != policy.ID || x.policy.Checksum != policy.Checksum || !reflect.DeepEqual(x.binding, b) || slot != x.original.Request.Intent.Slot || resourceID != x.original.Request.Intent.Tuple.ResourceID || created != x.original.Request.Intent.Tuple.CreatedAt || current.Phase != "drained" {
		return ErrCapacityConflict
	}
	if _, err = s.retirementForwardOffTx(ctx, tx, x, r, sha, now); err != nil {
		return err
	}
	if err = s.retirementForwardFloorTx(ctx, tx, x, r); err != nil {
		return err
	}
	if grantID != "" {
		_, err = retirementForwardDestroyRecordTx(ctx, tx, r, grantID)
	}
	return err
}
func (s CapacityStore) bindGuestForwardDestroyTx(ctx context.Context, tx *sql.Tx, original capacityMutationRecord, now time.Time) (bool, error) {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT c.intent#>>'{retirement_forward,retirement_request_id}' FROM public.capacity_intents c JOIN public.manifests p ON p.id=$1 AND c.namespace=p.namespace AND c.environment=p.spec->>'environment' AND c.domain=p.spec->>'domain' AND c.dimension=p.spec->>'dimension' WHERE c.intent ? 'retirement_forward' AND c.intent#>>'{retirement_forward,stage}'<>'terminal'`, original.PolicyID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) || err == nil && id == "" {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	x, r, sha, err := s.retirementForwardCurrentTx(ctx, tx, id)
	if err != nil {
		return true, err
	}
	if original.PolicyID != x.policy.ID || original.WorkflowID != s.WorkflowID || original.Generation != r.Generation || original.FencingToken != r.Fence || original.ExecutorID != r.ExecutorID || original.LeaseOwner != r.LeaseOwner || original.Grant.Capability != x.binding.DestroyCapability || original.Grant.ExpectedResourceID != x.original.Request.Intent.Tuple.ResourceID || original.Grant.ExpectedResourceCreatedAt != x.original.Request.Intent.Tuple.CreatedAt {
		return true, ErrCapacityConflict
	}
	eligibility, err := s.retirementForwardOffTx(ctx, tx, x, r, sha, now)
	if err != nil {
		return true, err
	}
	raw, err := json.Marshal(eligibility)
	if err != nil {
		return true, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_retirement_delete_bindings(destroy_grant_id,intent_id,eligibility_sha256,original_eligibility_record,recorded_at,original_wire) VALUES($1,$2,$3,$4::jsonb,$5,$6)`, original.Grant.GrantID, id, capacity.BusinessCreationSHA256(raw), string(raw), now, raw)
	return true, err
}

func retirementForwardDestroyRecordTx(ctx context.Context, tx *sql.Tx, r GuestRetirementForward, id string) (capacityMutationRecord, error) {
	var original capacityMutationRecord
	var raw, binding []byte
	var sha string
	var boundPG time.Time
	err := tx.QueryRowContext(ctx, `SELECT g.grant_record,b.original_wire,b.eligibility_sha256,b.recorded_at FROM public.capacity_vm_retirement_delete_bindings b JOIN public.capacity_mutation_grants g ON g.id=b.destroy_grant_id WHERE b.intent_id=$1 AND b.destroy_grant_id=$2 FOR SHARE OF b,g`, r.RetirementRequestID, id).Scan(&raw, &binding, &sha, &boundPG)
	if err != nil {
		return original, err
	}
	var eligibility retirementForwardEligibility
	if decodeRetirementForward(binding, &eligibility) != nil {
		return original, ErrCapacityConflict
	}
	authority, authoritySHA, e := loadRetirementForwardTx(ctx, tx, eligibility.AdmissionID, "admitted")
	if e != nil || authority.RootAdmissionID != r.RootAdmissionID || authority.RetirementRequestID != r.RetirementRequestID || !reflect.DeepEqual(authority.Evidence, r.Evidence) || eligibility.AdmissionSHA256 != authoritySHA {
		return original, ErrCapacityConflict
	}
	if capacity.BusinessCreationSHA256(binding) != sha || decodeRetirementForward(binding, &eligibility) != nil || eligibility.Schema != retirementForwardEligibilitySchema || json.Unmarshal(raw, &original) != nil || original.PolicyID.String() != r.Original.Request.Intent.PolicyID || original.PolicyChecksum != r.Original.Request.Intent.PolicyChecksum || original.WorkflowID.String() != r.Original.Request.Intent.WorkflowID || original.Generation != authority.Generation || original.FencingToken != authority.Fence || original.ExecutorID != authority.ExecutorID || original.LeaseOwner != authority.LeaseOwner || original.Grant.Capability == original.Binding.EnsureCapability || original.Grant.CompensationOf != "" || original.Grant.Slot != r.Original.Request.Intent.Slot || original.Grant.ExpectedResourceID != r.Original.Request.Intent.Tuple.ResourceID || original.Grant.ExpectedResourceCreatedAt != r.Original.Request.Intent.Tuple.CreatedAt {
		return original, ErrCapacityConflict
	}
	// Revalidate the ORIGINAL eligibility at its immutable binding time, not
	// against a fresh substituted clock after the target has been deleted.
	read, issuedPG, readSHA, err := loadForwardReadReturnTx(ctx, tx, eligibility.NativeOffReadID)
	policy := model.Manifest{ID: original.PolicyID, Checksum: original.PolicyChecksum, Metadata: model.ManifestMetadata{Namespace: authority.Namespace}}
	var active bool
	if err != nil || tx.QueryRowContext(ctx, `SELECT spec,active FROM public.manifests WHERE id=$1 AND checksum=$2 AND kind='capacity_policy'`, policy.ID, policy.Checksum).Scan(&policy.Spec, &active) != nil || !active {
		return original, ErrCapacityConflict
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil || readSHA != eligibility.NativeOffSHA256 || read.Read.Kind != "off" || read.Read.AdmissionID != authority.ID || read.Read.AdmissionSHA256 != authoritySHA || read.Read.PrefixSHA256 != authority.PrefixSHA256 || read.Read.OriginalCallerSHA256 != authority.OriginalCallerSHA256 || read.Read.Tuple != authority.Original.Request.Intent.Tuple || read.Read.MutationBindingSHA256 != capacity.GuestRetirementSHA(original.Binding) || read.Read.AdapterSourceCommit != original.Binding.OriginalProviderSourceCommit || boundPG.Before(issuedPG) || boundPG.Sub(issuedPG)+5*time.Second > time.Duration(p.MaxEvidenceAgeSeconds)*time.Second || read.Plan == nil || read.Plan.Server == nil || read.Plan.Server.Labels["yggdrasil.io/owner"] != p.Owner {
		return original, ErrCapacityConflict
	}
	create, err := guestOriginalCreateReceiptV2Tx(ctx, tx, authority.Original)
	if err != nil || capacity.GuestRetirementV2NativeOffPlanContent(p, original.Binding, *read.Plan, create) != nil {
		return original, ErrCapacityConflict
	}
	return original, nil
}
func (s CapacityStore) GuestRetirementForwardDestroyReceipt(ctx context.Context, id string) (model.CapacityMutationReceipt, bool, error) {
	var receipt model.CapacityMutationReceipt
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return receipt, false, err
	}
	defer tx.Rollback()
	_, r, _, err := s.retirementForwardCurrentTx(ctx, tx, id)
	if err != nil {
		return receipt, false, err
	}
	var grant string
	err = tx.QueryRowContext(ctx, `SELECT destroy_grant_id::text FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1`, id).Scan(&grant)
	if errors.Is(err, sql.ErrNoRows) {
		return receipt, false, nil
	}
	if err != nil {
		return receipt, false, err
	}
	original, err := retirementForwardDestroyRecordTx(ctx, tx, r, grant)
	if err != nil {
		return receipt, false, err
	}
	return guestMutationReceiptV2(original), true, nil
}
func (s CapacityStore) guestForwardConfirmedDestroyTx(ctx context.Context, tx *sql.Tx, p model.CapacityPolicySpec, original capacityMutationRecord, proof model.CapacityMutationProof, now time.Time) (bool, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_vm_retirement_delete_bindings WHERE destroy_grant_id=$1 AND original_eligibility_record->>'schema'=$2`, original.Grant.GrantID, retirementForwardEligibilitySchema).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	var binding retirementForwardEligibility
	if decodeRetirementForward(raw, &binding) != nil {
		return true, ErrCapacityConflict
	}
	r, sha, err := loadRetirementForwardTx(ctx, tx, binding.AdmissionID, "admitted")
	if err != nil || binding.AdmissionSHA256 != sha {
		return true, ErrCapacityConflict
	}
	// ReadID selects the actual new read claimant. Its immutable admission must
	// be a verified descendant of the binding's original authority.
	if strings.HasPrefix(proof.ReceiptRef, "original-forward-native-absence:") {
		var claimant string
		if e := tx.QueryRowContext(ctx, `SELECT admission_id::text FROM public.capacity_guest_retirement_forward_reads WHERE id=$1 AND stage='returned'`, strings.TrimPrefix(proof.ReceiptRef, "original-forward-native-absence:")).Scan(&claimant); e != nil {
			return true, e
		}
		child, childSHA, e := loadRetirementForwardTx(ctx, tx, claimant, "admitted")
		if e != nil || child.RootAdmissionID != r.RootAdmissionID || child.RetirementRequestID != r.RetirementRequestID || !reflect.DeepEqual(child.Evidence, r.Evidence) {
			return true, ErrCapacityConflict
		}
		r, sha = child, childSHA
	}
	stored, err := retirementForwardDestroyRecordTx(ctx, tx, r, original.Grant.GrantID)
	if err != nil || !reflect.DeepEqual(stored, original) {
		return true, ErrCapacityConflict
	}
	if !strings.HasPrefix(proof.ReceiptRef, "original-forward-native-absence:") {
		return true, ErrCapacityConflict
	}
	id := strings.TrimPrefix(proof.ReceiptRef, "original-forward-native-absence:")
	observed, issued, _, err := loadForwardReadReturnTx(ctx, tx, id)
	if err != nil || observed.Read.AdmissionID != r.ID || observed.Read.AdmissionSHA256 != sha || observed.Read.PrefixSHA256 != r.PrefixSHA256 || observed.Read.OriginalCallerSHA256 != r.OriginalCallerSHA256 || observed.Read.Tuple != r.Original.Request.Intent.Tuple || now.Sub(issued) < 0 || now.Sub(issued)+5*time.Second > time.Duration(p.MaxEvidenceAgeSeconds)*time.Second {
		return true, ErrCapacityConflict
	}
	expected, err := retirementForwardAbsenceContent(observed, p, original)
	if err != nil {
		return true, err
	}
	var recorded time.Time
	if err = tx.QueryRowContext(ctx, `SELECT recorded_at FROM public.capacity_guest_retirement_forward_reads WHERE id=$1 AND stage='returned'`, id).Scan(&recorded); err != nil {
		return true, err
	}
	expected.ObservedAt = recorded
	if !reflect.DeepEqual(expected, proof) {
		return true, ErrCapacityConflict
	}
	return true, nil
}

// Only an immutable already accepted owning DELETE may be carried across a
// claim boundary. This does not redeem, reissue, rebind or send it again.
func forwardAdoptableDestroyTx(ctx context.Context, tx *sql.Tx, x retirementForwardSnapshot) (string, error) {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT destroy_grant_id::text FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1`, x.original.Request.Intent.RequestID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if x.current.RetirementForward == nil {
		return "", ErrCapacityConflict
	}
	r, _, err := loadRetirementForwardTx(ctx, tx, x.current.RetirementForward.ID, "admitted")
	if err != nil {
		return "", err
	}
	original, err := retirementForwardDestroyRecordTx(ctx, tx, r, id)
	if err != nil || original.Settlement == nil || (original.Grant.State != "settled" && original.Grant.State != "confirmed") || original.Settlement.Outcome != "accepted" || !original.Settlement.TransportCompleted || !original.Settlement.AuxiliaryInventoryComplete {
		return "", ErrCapacityConflict
	}
	return id, nil
}

func (s CapacityStore) retirementForwardLatestAbsenceTx(ctx context.Context, tx *sql.Tx, r GuestRetirementForward, p model.CapacityPolicySpec, original capacityMutationRecord, now time.Time) (model.CapacityMutationProof, string, error) {
	var proof model.CapacityMutationProof
	var id string
	err := tx.QueryRowContext(ctx, `SELECT id::text FROM public.capacity_guest_retirement_forward_reads WHERE admission_id=$1 AND kind='absence' AND stage='returned' ORDER BY recorded_at DESC,id DESC LIMIT 1`, r.ID).Scan(&id)
	if err != nil {
		return proof, "", err
	}
	actual, issued, sha, err := loadForwardReadReturnTx(ctx, tx, id)
	_, admissionSHA, e := loadRetirementForwardTx(ctx, tx, r.ID, "admitted")
	if err != nil || e != nil || actual.Read.AdmissionID != r.ID || actual.Read.AdmissionSHA256 != admissionSHA || actual.Read.PrefixSHA256 != r.PrefixSHA256 || actual.Read.OriginalCallerSHA256 != r.OriginalCallerSHA256 || actual.Read.Tuple != r.Original.Request.Intent.Tuple || now.Sub(issued) < 0 || now.Sub(issued)+5*time.Second > time.Duration(p.MaxEvidenceAgeSeconds)*time.Second {
		return proof, "", ErrCapacityConflict
	}
	proof, err = retirementForwardAbsenceContent(actual, p, original)
	if err != nil {
		return proof, "", err
	}
	if err = tx.QueryRowContext(ctx, `SELECT recorded_at FROM public.capacity_guest_retirement_forward_reads WHERE id=$1 AND stage='returned'`, id).Scan(&proof.ObservedAt); err != nil {
		return proof, "", err
	}
	return proof, sha, nil
}
