//go:build linux && nativequalification

package repository

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"reflect"
	"time"
)

func canonicalPostlossCase(c string) bool { return capacity.GuestPostlossQualificationSlot(c) != 0 }

type postlossReplyRead struct {
	Schema          string    `json:"schema"`
	Class           string    `json:"class"`
	BodyBytes       int       `json:"body_bytes"`
	BodySHA256      string    `json:"body_sha256"`
	ReadStartedAt   time.Time `json:"read_started_at"`
	EOFReturnedAt   time.Time `json:"eof_returned_at"`
	CloseReturnedAt time.Time `json:"close_returned_at"`
	Complete        bool      `json:"complete"`
}

func (v postlossReplyRead) valid(reserved, now time.Time) bool {
	return v.Schema == "original_source_create_reply_v1" && v.Class == "owning_reply_empty_eof_uncertain" && v.BodyBytes == 0 && v.BodySHA256 == capacity.BusinessCreationSHA256(nil) && !v.Complete && !v.ReadStartedAt.Before(reserved) && !v.EOFReturnedAt.Before(v.ReadStartedAt) && !v.CloseReturnedAt.Before(v.EOFReturnedAt) && !v.CloseReturnedAt.After(now)
}
func readPostlossOriginalFact(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	var before, after unix.Stat_t
	first := unix.Fstat(fd, &before)
	raw, readErr := io.ReadAll(io.LimitReader(f, 65537))
	last := unix.Fstat(fd, &after)
	closeErr := f.Close()
	if first != nil || readErr != nil || last != nil || closeErr != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size != int64(len(raw)) || len(raw) > 65536 || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, ErrCapacityConflict
	}
	return raw, nil
}
func (s CapacityStore) RecordGuestPostlossObservedWitness(ctx context.Context, preregistrationID string, proof model.CapacityMutationProof, intentKey ed25519.PrivateKey, nativeCase, transportPath string) (model.CapacityGuestOriginalCreateWitness, error) {
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
		if json.Unmarshal(raw, &original) != nil || original.Settlement == nil || original.Grant.State != "settled" || original.Settlement.Outcome != "uncertain" || !original.Settlement.TransportCompleted || original.Grant.Capability != original.Binding.EnsureCapability || original.Grant.CompensationOf != "" || original.AttemptID == "" || original.PolicyChecksum != stored.pre.PolicyChecksum || original.Generation != stored.pre.Generation || original.FencingToken != stored.pre.Fence || original.ExecutorID != stored.pre.ExecutorID || proof.GrantID != original.Grant.GrantID || proof.RequestSHA256 != original.Grant.RequestSHA256 || proof.ObservedCreationGrantID != original.Grant.GrantID || proof.ResourceAbsent || !validMutationProof(p, proof, now) || !completeMutationActionProof(original, proof) || !proof.ActionsSuccessful || proof.ActionsFailed || original.Settlement.ResourceID != "" || original.Settlement.ResourceCreatedAt != "" || original.Settlement.ActionID != "" {
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
		// The later QMP Read/Close observation is not Popen's return. Only
		// this compiled qualification producer supplies an owning native
		// create return; unsupported production producers remain HOLD.
		if provider != "native-qemu" || stored.binding.EvidenceClass != "native_qemu_qualification" || !capacity.GuestOriginalNativeQEMUProviderEnabled(provider) {
			return ErrCapacityConflict
		}
		native, err := guestNativeQEMUIdentityTx(ctx, tx, stored.pre.PreregistrationID)
		if err != nil {
			return err
		}
		returned := native.Original.OriginalCreateReturnedAt
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
		result = model.CapacityGuestOriginalCreateWitness{Schema: capacity.GuestCreateWitnessSchema, BindingName: stored.pre.BindingName, PreregistrationID: stored.pre.PreregistrationID, PreregistrationNonceSHA256: stored.pre.NonceSHA256, Tuple: model.CapacityGuestNativeTuple{Provider: provider, InstanceID: original.Binding.IntegrationInstanceID, InstanceChecksum: original.Binding.IntegrationChecksum, TypeID: original.Binding.IntegrationTypeID, TypeChecksum: original.Binding.IntegrationTypeChecksum, ScopeChecksum: original.Binding.ScopeChecksum, ProfileChecksum: slot.DesiredSpec.ProfileChecksum, Profile: original.Binding.ProfileName, Slot: original.Grant.Slot, ResourceID: proof.ResourceID, CreatedAt: proof.ResourceCreatedAt}, OriginalCreateGrantID: original.Grant.GrantID, OriginalCreateAttemptID: original.AttemptID, OriginalCreateRequestSHA256: original.Grant.RequestSHA256, OriginalCreateSettlementSHA256: capacity.GuestRetirementSHA(*original.Settlement), ProfileManifestSHA256: stored.pre.ProfileManifestSHA256, BootstrapSHA256: stored.binding.ProfileManifest.BootstrapSHA256, CoreSourceCommit: stored.pre.CoreSourceCommit, OriginalDeadline: stored.pre.OriginalDeadline, OriginalCreateReturnedAt: returned, ObservedAt: now}

		if !canonicalPostlossCase(nativeCase) || stored.pre.Slot != capacity.GuestPostlossQualificationSlot(nativeCase) || stored.binding.ProfileManifest.Profile != "qualification-original-echo-writer-v1" || original.Grant.CompensationOf != "" || s.hostOriginalOrdinary != nil {
			return ErrCapacityDisabled
		}
		transportWire, readErr := readPostlossOriginalFact(transportPath)
		if readErr != nil {
			return readErr
		}
		var transport postlossReplyRead
		if capacity.DecodeGuestLifecycle(transportWire, &transport) != nil || !transport.valid(stored.pre.ReservedAt, now) {
			return ErrCapacityConflict
		}
		var nativeWire []byte
		if err = tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='native_read' AND original_record=convert_from(original_wire,'UTF8')::jsonb`, preregistrationID).Scan(&nativeWire); err != nil {
			return err
		}
		result.SourceObservation = &model.CapacityGuestPostlossObservation{Schema: "canonical_postloss_observed_create_v1", Scope: "SOURCE_ONLY_OBSERVED_SAME_CREATE_NOT_ACCEPTED_TRANSPORT", Case: nativeCase, OriginalOutcome: "uncertain", OwningReplySHA256: capacity.BusinessCreationSHA256(nil), OwningReplyReadSHA256: capacity.BusinessCreationSHA256(transportWire), IndependentNativeReadSHA256: capacity.BusinessCreationSHA256(nativeWire), OriginalCreatorSHA256: native.OriginalCreatorSHA256, ProductionQualified: false}
		result.Signature, err = capacity.GuestLifecycleSignature(intentKey, result)
		if err != nil {
			return err
		}
		wire, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `CREATE TABLE public.capacity_canonical_postloss_originals(preregistration_id uuid PRIMARY KEY,parent_grant_id uuid UNIQUE NOT NULL,original_grant_wire bytea NOT NULL,transport_read_wire bytea NOT NULL,transport_read_sha256 text NOT NULL,native_read_sha256 text NOT NULL,witness_wire bytea NOT NULL,witness_sha256 text UNIQUE NOT NULL); CREATE FUNCTION public.postloss_original_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable postloss original'; END $$; CREATE TRIGGER postloss_original_immutable BEFORE UPDATE OR DELETE ON public.capacity_canonical_postloss_originals FOR EACH ROW EXECUTE FUNCTION public.postloss_original_immutable(); CREATE TABLE public.capacity_canonical_postloss_confirmations(preregistration_id uuid PRIMARY KEY,parent_grant_id uuid UNIQUE NOT NULL,native_wire bytea NOT NULL,native_sha256 text NOT NULL,proof_wire bytea NOT NULL,proof_sha256 text NOT NULL,recorded_at timestamptz NOT NULL); CREATE TRIGGER postloss_confirmation_immutable BEFORE UPDATE OR DELETE ON public.capacity_canonical_postloss_confirmations FOR EACH ROW EXECUTE FUNCTION public.postloss_original_immutable()`); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_canonical_postloss_originals VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, preregistrationID, original.Grant.GrantID, raw, transportWire, capacity.BusinessCreationSHA256(transportWire), capacity.BusinessCreationSHA256(nativeWire), wire, capacity.BusinessCreationSHA256(wire)); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_create_witnesses(preregistration_id,original_create_attempt_id,resource_tuple_sha256,witness_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)`, preregistrationID, original.AttemptID, capacity.GuestRetirementSHA(result.Tuple), capacity.GuestRetirementSHA(result), wire, string(wire), now)
		return err
	})
	return result, err
}

func (s CapacityStore) canonicalPostlossParentTx(ctx context.Context, tx *sql.Tx, stored guestOriginalStored, parent capacityMutationRecord, nativeCase string) bool {
	if !canonicalPostlossCase(nativeCase) || parent.Settlement == nil || parent.Settlement.Outcome != "uncertain" || !parent.Settlement.TransportCompleted || parent.Settlement.ResourceID != "" || parent.Settlement.ResourceCreatedAt != "" || parent.Settlement.ActionID != "" || stored.pre.Slot != capacity.GuestPostlossQualificationSlot(nativeCase) || stored.pre.PolicyID != parent.PolicyID.String() || stored.pre.PolicyChecksum != parent.PolicyChecksum {
		return false
	}
	var witnessWire, originalGrant, transportWire []byte
	var transportSHA, nativeSHA, witnessSHA string
	if tx.QueryRowContext(ctx, `SELECT original_grant_wire,transport_read_wire,transport_read_sha256,native_read_sha256,witness_wire,witness_sha256 FROM public.capacity_canonical_postloss_originals WHERE preregistration_id=$1 AND parent_grant_id=$2`, stored.pre.PreregistrationID, parent.Grant.GrantID).Scan(&originalGrant, &transportWire, &transportSHA, &nativeSHA, &witnessWire, &witnessSHA) != nil {
		return false
	}
	var witness model.CapacityGuestOriginalCreateWitness
	var original capacityMutationRecord
	var fact postlossReplyRead
	if capacity.DecodeGuestLifecycle(witnessWire, &witness) != nil || witness.SourceObservation == nil || json.Unmarshal(originalGrant, &original) != nil || original.Settlement == nil || capacity.GuestRetirementSHA(*original.Settlement) != capacity.GuestRetirementSHA(*parent.Settlement) || capacity.DecodeGuestLifecycle(transportWire, &fact) != nil || !fact.valid(stored.pre.ReservedAt, witness.ObservedAt) || witnessSHA != capacity.BusinessCreationSHA256(witnessWire) || transportSHA != capacity.BusinessCreationSHA256(transportWire) {
		return false
	}
	o := witness.SourceObservation
	if o.Case != nativeCase || o.OwningReplyReadSHA256 != transportSHA || o.IndependentNativeReadSHA256 != nativeSHA || witness.OriginalCreateGrantID != parent.Grant.GrantID || witness.OriginalCreateAttemptID != parent.AttemptID || witness.OriginalCreateRequestSHA256 != parent.Grant.RequestSHA256 || witness.OriginalCreateSettlementSHA256 != capacity.GuestRetirementSHA(*parent.Settlement) {
		return false
	}
	resolved, err := ResolveSecretRef(ctx, s.DB, stored.binding.IntentSigningKeyRef)
	if err != nil {
		return false
	}
	encoded, ok := resolved.(string)
	if !ok {
		return false
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return false
	}
	var policyWire []byte
	var policySpec model.CapacityPolicySpec
	if tx.QueryRowContext(ctx, `SELECT spec FROM public.manifests WHERE id=$1 AND checksum=$2`, stored.pre.PolicyID, stored.pre.PolicyChecksum).Scan(&policyWire) != nil || json.Unmarshal(policyWire, &policySpec) != nil {
		return false
	}
	return capacity.GuestOriginalCreateWitness(policySpec, stored.binding, stored.member, stored.pre, witness, base64.StdEncoding.EncodeToString(ed25519.PrivateKey(key).Public().(ed25519.PublicKey)), witness.ObservedAt) == nil
}
