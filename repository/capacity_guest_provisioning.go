package repository

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type guestOriginalProvisioningContext struct {
	step     model.WorkflowStepSpec
	source   string
	nonceSHA string
}

// Called only by the source-owned in-process protected step. Inputs cannot
// provide the resolved step, runtime source identity or original context.
func (s CapacityStore) WithOriginalGuestProvisioning(step model.WorkflowStepSpec, source, nonceSHA string) CapacityStore {
	s.guestOriginal = &guestOriginalProvisioningContext{step: step, source: source, nonceSHA: nonceSHA}
	return s
}

type guestOriginalStored struct {
	pre     model.CapacityGuestOriginalProvisioningPreregistration
	binding model.CapacityGuestRetirementBinding
	witness model.CapacityGuestOriginalCreateWitness
	member  model.CapacityGuestRetirementMemberBinding
}

// OriginalGuestCreateWitnessProviderEnabled describes implemented original
// return sources, independently of profile approval. A registry entry cannot
// turn a provider settlement/readback into a missing owning create return.
func OriginalGuestCreateWitnessProviderEnabled(provider string) bool {
	return provider == "hetzner" || provider == "aws" || provider == "native-qemu" && capacity.GuestOriginalNativeQEMUProviderEnabled(provider)
}

func guestMember(binding model.CapacityGuestRetirementBinding, slot int) (model.CapacityGuestRetirementMemberBinding, error) {
	for _, member := range binding.Members {
		if member.Slot == slot {
			return member, nil
		}
	}
	return model.CapacityGuestRetirementMemberBinding{}, ErrCapacityMutationAuthorization
}

// This runs inside the ORIGINAL provider grant transaction, before COMMIT.
// No provider send or WAN read is performed while holding the scope lock.
func (s CapacityStore) reserveGuestOriginalTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, intent model.CapacityIntent, record capacityMutationRecord, now time.Time, originalGrantRaw ...[]byte) error {
	b := p.GuestRetirementBinding
	if b == nil || capacity.ValidateGuestRetirementBinding(p, b) != nil || b.MutationBindingName != record.Binding.Name || !capacity.GuestOriginalProfileEnabled(p, *b, record.EventProvider) || s.guestOriginal == nil || s.guestOriginal.source != b.CoreAuthoritySourceCommit || s.guestOriginal.source != capacity.CurrentGuestCoreSource() || !capacity.ValidDigest(s.guestOriginal.nonceSHA) {
		return fmt.Errorf("%w: complete original protected Guest preregistration required", ErrCapacityConflict)
	}
	member, err := guestMember(*b, record.Grant.Slot)
	if err != nil {
		return err
	}
	var checksum string
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT checksum,spec FROM public.manifests WHERE id=$1 AND kind='workflow' AND active FOR SHARE`, s.WorkflowID).Scan(&checksum, &raw); err != nil {
		return err
	}
	wf, err := manifest.ParseWorkflowSpec(raw)
	if err != nil || wf.Authorization == nil {
		return ErrCapacityMutationAuthorization
	}
	var matched bool
	for _, step := range wf.Steps {
		matched = matched || reflect.DeepEqual(step, s.guestOriginal.step)
	}
	if !matched {
		return ErrCapacityMutationAuthorization
	}
	deadline, err := capacity.GuestOriginalProvisioningDeadline(ctx, b.ProfileManifest, s.guestOriginal.step, now)
	if err != nil {
		return err
	}
	contextDeadline, _ := ctx.Deadline()
	pre := model.CapacityGuestOriginalProvisioningPreregistration{Schema: capacity.GuestPreregistrationSchema, PreregistrationID: uuid.NewString(), BindingName: member.Name, OriginalCreateGrantID: record.Grant.GrantID, OriginalCreateRequestSHA256: record.Grant.RequestSHA256, NonceSHA256: s.guestOriginal.nonceSHA, ProfileManifestSHA256: b.ProfileManifestSHA256, PolicyID: policy.ID.String(), PolicyChecksum: policy.Checksum, WorkflowID: s.WorkflowID.String(), WorkflowChecksum: checksum, OriginalWorkflowStepID: s.guestOriginal.step.ID, OriginalWorkflowStepTimeoutSeconds: s.guestOriginal.step.TimeoutSeconds, OriginalWorkflowContextDeadline: contextDeadline, CoreSourceCommit: s.guestOriginal.source, Generation: intent.Generation, Fence: intent.FencingToken, LeaseOwner: intent.LeaseOwner, ExecutorID: s.ExecutorID, Slot: record.Grant.Slot, OriginalDeadline: deadline, ReservedAt: now}
	if !capacity.GuestOriginalProvisioningDeadlineMatches(pre, b.ProfileManifest) {
		return ErrCapacityConflict
	}
	wire, err := json.Marshal(pre)
	if err != nil {
		return err
	}
	bindingWire, err := json.Marshal(b)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_provisioning_preregistrations(id,create_grant_id,nonce_sha256,profile_manifest_sha256,preregistration_record,original_deadline,created_at,original_wire,binding_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9)`, pre.PreregistrationID, pre.OriginalCreateGrantID, pre.NonceSHA256, pre.ProfileManifestSHA256, wire, pre.OriginalDeadline, now, wire, bindingWire)
	if err == nil {
		if s.hostOriginalFactory != nil || s.hostOriginalOrdinary != nil {
			if len(originalGrantRaw) != 1 {
				return ErrHostFactoryHold
			}
			if s.hostOriginalOrdinary != nil {
				err = s.attachOriginalOrdinaryGrantTx(ctx, tx, record, originalGrantRaw[0], pre, wire)
			} else {
				err = s.attachOriginalHostGrantTx(ctx, tx, record, originalGrantRaw[0], pre, wire)
			}
		}
	}
	return err
}

func loadGuestOriginalTx(ctx context.Context, tx *sql.Tx, id string) (guestOriginalStored, error) {
	var result guestOriginalStored
	if !validCapacityExecutor(id) {
		return result, ErrCapacityMutationAuthorization
	}
	var wire, binding []byte
	var consistent bool
	err := tx.QueryRowContext(ctx, `SELECT original_wire,binding_wire,original_deadline=(preregistration_record->>'original_deadline')::timestamptz AND created_at=(preregistration_record->>'reserved_at')::timestamptz AND id::text=preregistration_record->>'preregistration_id' AND create_grant_id::text=preregistration_record->>'original_create_grant_id' AND nonce_sha256=preregistration_record->>'nonce_sha256' AND profile_manifest_sha256=preregistration_record->>'profile_manifest_sha256' AND preregistration_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_vm_provisioning_preregistrations WHERE id=$1 FOR SHARE`, id).Scan(&wire, &binding, &consistent)
	if err != nil {
		return result, err
	}
	if !consistent || capacity.DecodeGuestLifecycle(wire, &result.pre) != nil || capacity.DecodeGuestLifecycle(binding, &result.binding) != nil || !capacity.GuestOriginalProvisioningDeadlineMatches(result.pre, result.binding.ProfileManifest) {
		return result, ErrCapacityConflict
	}
	result.member, err = guestMember(result.binding, result.pre.Slot)
	return result, err
}

func loadGuestWitnessTx(ctx context.Context, tx *sql.Tx, stored *guestOriginalStored) error {
	var raw []byte
	var digest string
	var consistent bool
	if err := tx.QueryRowContext(ctx, `SELECT original_wire,witness_sha256,original_record=convert_from(original_wire,'UTF8')::jsonb AND original_create_attempt_id::text=original_record->>'original_create_attempt_id' FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$1 FOR SHARE`, stored.pre.PreregistrationID).Scan(&raw, &digest, &consistent); err != nil {
		return err
	}
	if !consistent || capacity.DecodeGuestLifecycle(raw, &stored.witness) != nil || capacity.GuestRetirementSHA(stored.witness) != digest || stored.witness.PreregistrationID != stored.pre.PreregistrationID {
		return ErrCapacityConflict
	}
	return nil
}

// New admission rechecks the CURRENT policy/workflow/source/owner/fence/lease.
// Original bytes are immutable; a current read never extends the old deadline.
func (s CapacityStore) guestCurrentTx(ctx context.Context, tx *sql.Tx, stored guestOriginalStored, now time.Time, originalDeadline bool) (model.CapacityPolicySpec, model.CapacityIntent, error) {
	var p model.CapacityPolicySpec
	var intent model.CapacityIntent
	var namespace, name, checksum string
	var raw []byte
	var active bool
	err := tx.QueryRowContext(ctx, `SELECT namespace,name,checksum,active,spec FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, stored.pre.PolicyID).Scan(&namespace, &name, &checksum, &active, &raw)
	if err != nil {
		return p, intent, err
	}
	policy := model.Manifest{ID: uuid.MustParse(stored.pre.PolicyID), Kind: "capacity_policy", Checksum: checksum, Metadata: model.ManifestMetadata{Namespace: namespace, Name: name}, Spec: raw}
	p, err = parseCapacityPolicy(policy)
	if err != nil || !active || checksum != stored.pre.PolicyChecksum || stored.binding.CoreAuthoritySourceCommit != capacity.CurrentGuestCoreSource() || p.GuestRetirementBinding == nil || !reflect.DeepEqual(*p.GuestRetirementBinding, stored.binding) || capacity.ValidateGuestRetirementBinding(p, p.GuestRetirementBinding) != nil || (originalDeadline && !now.Before(stored.pre.OriginalDeadline)) {
		return p, intent, ErrCapacityConflict
	}
	if err = tx.QueryRowContext(ctx, `SELECT checksum,active FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2 AND name=$3 AND jsonb_typeof(spec->'authorization')='object' FOR SHARE`, stored.pre.WorkflowID, p.Workflow.Namespace, p.Workflow.Name).Scan(&checksum, &active); err != nil {
		return p, intent, err
	}
	if !active || checksum != stored.pre.WorkflowChecksum {
		return p, intent, ErrCapacityConflict
	}
	intent, err = loadCapacityIntent(ctx, tx, namespace, p, true)
	if err != nil {
		return p, intent, err
	}
	current := s
	current.ExecutorID = stored.pre.ExecutorID
	if err = current.checkLease(p, policy, &intent, stored.pre.Generation, stored.pre.Fence, stored.pre.LeaseOwner, now); err != nil {
		return p, intent, err
	}
	b, err := capacity.VMObservationBinding(p, stored.binding.MutationBindingName)
	provider, _, providerErr := capacityMutationEventIdentity(ctx, tx, b)
	if err != nil || providerErr != nil || !capacity.GuestOriginalProfileEnabled(p, stored.binding, provider) || checkMutationIntegration(ctx, tx, b) != nil || !capacityProfileCurrent(p, intent.Decision, now) {
		return p, intent, ErrCapacityConflict
	}
	return p, intent, nil
}

func (s CapacityStore) guestStoredTransaction(ctx context.Context, id string, fn func(*sql.Tx, guestOriginalStored, time.Time) error) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Locate the original logical scope without taking row locks first.
	var namespace, environment, domain, dimension string
	if err = tx.QueryRowContext(ctx, `SELECT m.namespace,m.environment,m.domain,m.dimension FROM public.capacity_vm_provisioning_preregistrations p JOIN public.capacity_mutation_grants m ON m.id=p.create_grant_id WHERE p.id=$1`, id).Scan(&namespace, &environment, &domain, &dimension); err != nil {
		return err
	}
	if err = lockMutationScope(ctx, tx, namespace, model.CapacityPolicySpec{Environment: environment, Domain: domain, Dimension: dimension}); err != nil {
		return err
	}
	stored, err := loadGuestOriginalTx(ctx, tx, id)
	if err != nil {
		return err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if err = fn(tx, stored, now.UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

// The actual owning ensure settlement and independent native identity proof
// precede this signature. No native tuple can be configured before create.
func (s CapacityStore) RecordGuestCreateWitness(ctx context.Context, preregistrationID string, proof model.CapacityMutationProof, intentKey ed25519.PrivateKey) (model.CapacityGuestOriginalCreateWitness, error) {
	var result model.CapacityGuestOriginalCreateWitness
	err := s.guestStoredTransaction(ctx, preregistrationID, func(tx *sql.Tx, stored guestOriginalStored, now time.Time) error {
		p, _, err := s.guestCurrentTx(ctx, tx, stored, now, true)
		if err != nil {
			return err
		}
		var raw []byte
		if err = tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, stored.pre.OriginalCreateGrantID).Scan(&raw); err != nil {
			return err
		}
		var factoryBindings int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_factory_original_grant_bindings WHERE grant_id=$1`, stored.pre.OriginalCreateGrantID).Scan(&factoryBindings); err != nil {
			return err
		}
		if factoryBindings != 0 && s.hostOriginalOrdinary == nil {
			return ErrHostFactoryHold
		}
		var original capacityMutationRecord
		if json.Unmarshal(raw, &original) != nil || original.Settlement == nil || original.Grant.State != "settled" || original.Settlement.Outcome != "accepted" || !original.Settlement.TransportCompleted || original.Grant.Capability != original.Binding.EnsureCapability || original.Grant.CompensationOf != "" || original.AttemptID == "" || original.PolicyChecksum != stored.pre.PolicyChecksum || original.Generation != stored.pre.Generation || original.FencingToken != stored.pre.Fence || original.ExecutorID != stored.pre.ExecutorID || proof.GrantID != original.Grant.GrantID || proof.RequestSHA256 != original.Grant.RequestSHA256 || proof.ObservedCreationGrantID != original.Grant.GrantID || proof.ResourceAbsent || !validMutationProof(p, proof, now) || !successfulOriginalMutationProof(original, proof, now) || proof.ResourceID != original.Settlement.ResourceID || proof.ResourceCreatedAt != original.Settlement.ResourceCreatedAt {
			return ErrCapacityConflict
		}
		if h := s.hostOriginalOrdinary; h != nil {
			if factoryBindings != 1 || !reflect.DeepEqual(p, h.policySpec) || !reflect.DeepEqual(original.Binding, h.mutationBinding) {
				return ErrHostFactoryHold
			}
			if err = lockNativeMutationSlot(ctx, tx, original.Binding, original.Grant.Slot); err != nil {
				return err
			}
			if err = lockOriginalHostTarget(ctx, tx, h.binding.StableOriginalTargetSHA256); err != nil {
				return err
			}
			if err = s.checkOriginalOrdinaryRegisteredTx(ctx, tx, h); err != nil {
				return err
			}
		}
		var lockedRaw []byte
		if err = tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 FOR SHARE`, stored.pre.OriginalCreateGrantID).Scan(&lockedRaw); err != nil {
			return err
		}
		if !bytes.Equal(lockedRaw, raw) {
			return ErrCapacityConflict
		}
		var slot model.CapacityMutationSlotBinding
		for _, approved := range original.Binding.Slots {
			if approved.Slot == stored.pre.Slot {
				slot = approved
			}
		}
		if slot.DesiredSpec == nil || slot.Slot != stored.pre.Slot {
			return ErrCapacityConflict
		}
		provider := ""
		for _, profile := range p.Profiles {
			if profile.Name == original.Binding.ProfileName {
				provider = profile.Provider
			}
		}
		if !OriginalGuestCreateWitnessProviderEnabled(provider) {
			return ErrCapacityConflict
		}
		var returned time.Time
		if provider == "hetzner" || provider == "aws" {
			if stored.binding.EvidenceClass != "owned_provisioner_original" || s.hostOriginalOrdinary != nil || s.hostOriginalFactory != nil {
				return ErrCapacityConflict
			}
			validateReturn := capacity.ValidateOriginalHetznerCreateReturn
			if provider == "aws" {
				validateReturn = capacity.ValidateOriginalAWSCreateReturn
			}
			returned, err = validateReturn(original.Binding, original.Grant, original.AttemptID, *original.Settlement, stored.pre.ReservedAt, now)
			if err != nil || returned.After(proof.ObservedAt) || !returned.Before(stored.pre.OriginalDeadline) {
				return ErrCapacityConflict
			}
		} else {
			// A later QMP read is not Popen's original return. Qualification
			// continues to use its original separately owned source identity.
			if stored.binding.EvidenceClass != "native_qemu_qualification" {
				return ErrCapacityConflict
			}
			native, err := guestNativeQEMUIdentityTx(ctx, tx, stored.pre.PreregistrationID)
			if err != nil {
				return err
			}
			returned = native.Original.OriginalCreateReturnedAt
			observed, err := time.Parse(time.RFC3339Nano, original.Settlement.ObservedAt)
			creatorSourceMatches := native.Original.OriginalSourceCommit == stored.binding.GuestSourceCommit
			if s.hostOriginalOrdinary != nil {
				// The new compiled creator has the actual Core PUB epoch. Guest
				// image/bootstrap/Actor epoch remains the separate original binding.
				// Only this private actual Realm and exact original Continue/SQL raw
				// join admits that branch; caller labels/flags/keys do not select it.
				if native.Original.OriginalSourceCommit != capacity.CurrentGuestCoreSource() || s.verifyOriginalOrdinaryCreateTx(ctx, tx, stored.pre, proof) != nil {
					return ErrHostFactoryHold
				}
				creatorSourceMatches = true
			}
			if err != nil || native.Original.ResourceID != proof.ResourceID || native.Original.Slot != stored.pre.Slot || !creatorSourceMatches || native.Original.OriginalCreateStartedAt.Before(stored.pre.ReservedAt) || returned.Before(native.Original.OriginalCreateStartedAt) || returned.After(proof.ObservedAt) || returned.UTC().Format(time.RFC3339Nano) != proof.ResourceCreatedAt || !observed.Equal(native.CloseReturnedAt) || !proof.ObservedAt.Equal(native.CloseReturnedAt) {
				return ErrCapacityConflict
			}
		}
		result = model.CapacityGuestOriginalCreateWitness{Schema: capacity.GuestCreateWitnessSchema, BindingName: stored.pre.BindingName, PreregistrationID: stored.pre.PreregistrationID, PreregistrationNonceSHA256: stored.pre.NonceSHA256, Tuple: model.CapacityGuestNativeTuple{Provider: provider, InstanceID: original.Binding.IntegrationInstanceID, InstanceChecksum: original.Binding.IntegrationChecksum, TypeID: original.Binding.IntegrationTypeID, TypeChecksum: original.Binding.IntegrationTypeChecksum, ScopeChecksum: original.Binding.ScopeChecksum, ProfileChecksum: slot.DesiredSpec.ProfileChecksum, Profile: original.Binding.ProfileName, Slot: original.Grant.Slot, ResourceID: proof.ResourceID, CreatedAt: proof.ResourceCreatedAt}, OriginalCreateGrantID: original.Grant.GrantID, OriginalCreateAttemptID: original.AttemptID, OriginalCreateRequestSHA256: original.Grant.RequestSHA256, OriginalCreateSettlementSHA256: capacity.GuestRetirementSHA(*original.Settlement), ProfileManifestSHA256: stored.pre.ProfileManifestSHA256, BootstrapSHA256: stored.binding.ProfileManifest.BootstrapSHA256, CoreSourceCommit: stored.pre.CoreSourceCommit, OriginalDeadline: stored.pre.OriginalDeadline, OriginalCreateReturnedAt: returned, ObservedAt: now}
		result.Signature, err = capacity.GuestLifecycleSignature(intentKey, result)
		if err != nil {
			return err
		}
		wire, err := json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_create_witnesses(preregistration_id,original_create_attempt_id,resource_tuple_sha256,witness_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)`, preregistrationID, original.AttemptID, capacity.GuestRetirementSHA(result.Tuple), capacity.GuestRetirementSHA(result), wire, string(wire), now)
		return err
	})
	return result, err
}

func (s CapacityStore) GuestPreregistration(ctx context.Context, principal, id, nonceSHA string) (model.CapacityGuestOriginalProvisioningPreregistration, error) {
	var result model.CapacityGuestOriginalProvisioningPreregistration
	err := s.guestStoredTransaction(ctx, id, func(_ *sql.Tx, stored guestOriginalStored, _ time.Time) error {
		if principal != stored.member.ProvisionerClientPrincipal || nonceSHA != stored.pre.NonceSHA256 {
			return ErrCapacityMutationAuthorization
		}
		result = stored.pre
		return nil
	})
	return result, err
}

func (s CapacityStore) GuestCreateWitness(ctx context.Context, principal, id, nonceSHA string) (model.CapacityGuestOriginalCreateWitness, error) {
	var result model.CapacityGuestOriginalCreateWitness
	err := s.guestStoredTransaction(ctx, id, func(tx *sql.Tx, stored guestOriginalStored, _ time.Time) error {
		if principal != stored.member.ProvisionerClientPrincipal || nonceSHA != stored.pre.NonceSHA256 {
			return ErrCapacityMutationAuthorization
		}
		if err := loadGuestWitnessTx(ctx, tx, &stored); err != nil {
			return err
		}
		result = stored.witness
		return nil
	})
	return result, err
}

// One POST, including after a lost reply: duplicate callback returns conflict;
// only GET of the same durable preregistration recovers the original receipt.
func (s CapacityStore) RegisterOriginalGuest(ctx context.Context, principal string, registration model.CapacityGuestOriginalProvisioningRegistration, intentKey, enrollmentKey ed25519.PrivateKey) (model.CapacityGuestOriginalProvisioningReceipt, error) {
	var result model.CapacityGuestOriginalProvisioningReceipt
	err := s.guestStoredTransaction(ctx, registration.Result.PreregistrationID, func(tx *sql.Tx, stored guestOriginalStored, now time.Time) error {
		if principal != stored.member.ProvisionerClientPrincipal {
			return ErrCapacityMutationAuthorization
		}
		p, _, err := s.guestCurrentTx(ctx, tx, stored, now, true)
		if err != nil {
			return err
		}
		if err = loadGuestWitnessTx(ctx, tx, &stored); err != nil {
			return err
		}
		corePublic := registration.EnrollmentStatement.CoreIntentPublicKey
		if !capacity.GuestLifecycleKeyMatches(intentKey, corePublic) || !capacity.GuestLifecycleKeyMatches(enrollmentKey, stored.binding.EnrollmentIssuerPublicKey) || bytes.Equal(intentKey, enrollmentKey) || capacity.GuestOriginalCreateWitness(p, stored.binding, stored.member, stored.pre, stored.witness, corePublic, now) != nil || capacity.GuestOriginalRegistration(p, stored.binding, stored.member, stored.witness, registration, now) != nil {
			return ErrCapacityConflict
		}
		e := model.CapacityGuestRetirementEnrollment{Statement: registration.EnrollmentStatement}
		e.Signature, err = capacity.GuestLifecycleSignature(enrollmentKey, e.Statement)
		if err != nil || capacity.GuestRetirementEnrollment(p, stored.binding, stored.member, e, now) != nil {
			return ErrCapacityConflict
		}
		result = model.CapacityGuestOriginalProvisioningReceipt{PreregistrationID: stored.pre.PreregistrationID, OriginalProvisioningSHA256: capacity.GuestRetirementSHA(registration), Enrollment: e, RecordedAt: now}
		registrationWire, err := json.Marshal(registration)
		if err != nil {
			return err
		}
		receiptWire, err := json.Marshal(result)
		if err != nil {
			return err
		}
		enrollmentWire, err := json.Marshal(e)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_original_enrollments(preregistration_id,resource_tuple_sha256,enrollment_sha256,original_provisioning_sha256,enrollment_record,recorded_at,registration_wire,receipt_wire) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8)`, stored.pre.PreregistrationID, capacity.GuestRetirementSHA(e.Statement.Tuple), capacity.GuestRetirementSHA(e), result.OriginalProvisioningSHA256, enrollmentWire, now, registrationWire, receiptWire)
		return err
	})
	return result, err
}

func loadGuestReceiptTx(ctx context.Context, tx *sql.Tx, id string) (model.CapacityGuestOriginalProvisioningReceipt, string, error) {
	var result model.CapacityGuestOriginalProvisioningReceipt
	var wire, registration []byte
	var digest string
	var consistent bool
	err := tx.QueryRowContext(ctx, `SELECT receipt_wire,registration_wire,enrollment_sha256,enrollment_record=convert_from(receipt_wire,'UTF8')::jsonb->'enrollment' AND recorded_at=(convert_from(receipt_wire,'UTF8')::jsonb->>'recorded_at')::timestamptz FROM public.capacity_vm_original_enrollments WHERE preregistration_id=$1 FOR SHARE`, id).Scan(&wire, &registration, &digest, &consistent)
	if err != nil {
		return result, "", err
	}
	var original model.CapacityGuestOriginalProvisioningRegistration
	if !consistent || capacity.DecodeGuestLifecycle(wire, &result) != nil || capacity.DecodeGuestLifecycle(registration, &original) != nil || result.PreregistrationID != id || capacity.GuestRetirementSHA(result.Enrollment) != digest || result.OriginalProvisioningSHA256 != capacity.GuestRetirementSHA(original) || result.Enrollment.Statement.OriginalNativeResultSHA256 != capacity.GuestRetirementSHA(original.Result) {
		return result, "", ErrCapacityConflict
	}
	return result, capacity.GuestRetirementSHA(original), nil
}

func (s CapacityStore) GuestProvisioningReceipt(ctx context.Context, principal, id, nonceSHA string) (model.CapacityGuestOriginalProvisioningReceipt, error) {
	var result model.CapacityGuestOriginalProvisioningReceipt
	err := s.guestStoredTransaction(ctx, id, func(tx *sql.Tx, stored guestOriginalStored, _ time.Time) error {
		if principal != stored.member.ProvisionerClientPrincipal || nonceSHA != stored.pre.NonceSHA256 {
			return ErrCapacityMutationAuthorization
		}
		var err error
		result, _, err = loadGuestReceiptTx(ctx, tx, id)
		return err
	})
	return result, err
}

func (s CapacityStore) GuestProvisioningCallbackScope(ctx context.Context, principal, id string) (model.CapacityGuestRetirementBinding, model.CapacityGuestRetirementMemberBinding, error) {
	var binding model.CapacityGuestRetirementBinding
	var member model.CapacityGuestRetirementMemberBinding
	err := s.guestStoredTransaction(ctx, id, func(_ *sql.Tx, stored guestOriginalStored, _ time.Time) error {
		if principal != stored.member.ProvisionerClientPrincipal {
			return ErrCapacityMutationAuthorization
		}
		binding, member = stored.binding, stored.member
		return nil
	})
	return binding, member, err
}

// The selector is not native proof. This lookup exists ONLY after the owning
// create settlement AND independent native join produced an immutable witness.
// Guest separately reads the current kernel/native identity before calling it.
// Slot, latest timestamp, configured Node or guessed resource names cannot
// select an original. Ambiguous IDs remain HOLD, including retained history.
func (s CapacityStore) GuestExactOriginalLookup(ctx context.Context, principal, memberName string, slot int, profileSHA, nativeResourceID string) (model.CapacityGuestOriginalProvisioningPreregistration, error) {
	var result model.CapacityGuestOriginalProvisioningPreregistration
	if memberName == "" || slot < 1 || slot > 64 || !capacity.ValidDigest(profileSHA) || nativeResourceID == "" || len(nativeResourceID) > 128 {
		return result, ErrCapacityMutationAuthorization
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT p.id::text,p.nonce_sha256 FROM public.capacity_vm_provisioning_preregistrations p JOIN public.capacity_guest_original_create_witnesses w ON w.preregistration_id=p.id WHERE p.preregistration_record->>'binding_name'=$1 AND p.preregistration_record->>'slot'=$2 AND p.profile_manifest_sha256=$3 AND w.original_record->'tuple'->>'resource_id'=$4`, memberName, fmt.Sprint(slot), profileSHA, nativeResourceID)
	if err != nil {
		return result, err
	}
	var id, nonceSHA string
	count := 0
	for rows.Next() {
		if err = rows.Scan(&id, &nonceSHA); err != nil {
			rows.Close()
			return result, err
		}
		count++
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return result, err
	}
	if count != 1 {
		return result, ErrCapacityMutationAuthorization
	}
	return s.GuestPreregistration(ctx, principal, id, nonceSHA)
}
