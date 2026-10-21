//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path/filepath"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func (r *Realm) OriginalEnrollment(slot int) (model.CapacityGuestOriginalProvisioningPreregistration, model.CapacityGuestOriginalProvisioningReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pre, found := r.preregistrations[slot]
	receipt, admitted := r.enrollments[slot]
	if !found || !admitted {
		return pre, receipt, ErrOriginalUnknown
	}
	return pre, receipt, nil
}

func (r *Realm) Probe(ctx context.Context, store repository.CapacityStore, policy model.Manifest, generation, fence int64, owner string, slot int, key ed25519.PrivateKey, client *capacity.GuestOriginalHTTPClient, leaseUntil time.Time) (QualificationProbeReceipt, error) {
	return r.probe(ctx, store, policy, generation, fence, owner, slot, key, client, leaseUntil, false)
}
func (r *Realm) DiagnosticProbe(ctx context.Context, store repository.CapacityStore, slot int, key ed25519.PrivateKey, client *capacity.GuestOriginalHTTPClient) (QualificationProbeReceipt, error) {
	return r.probe(ctx, store, model.Manifest{}, 0, 0, "", slot, key, client, r.Request.OriginalContextDeadline, true)
}
func (r *Realm) probe(ctx context.Context, store repository.CapacityStore, policy model.Manifest, generation, fence int64, owner string, slot int, key ed25519.PrivateKey, client *capacity.GuestOriginalHTTPClient, leaseUntil time.Time, diagnostic bool) (QualificationProbeReceipt, error) {
	var result QualificationProbeReceipt
	pre, receipt, err := r.OriginalEnrollment(slot)
	if err != nil {
		return result, capacity.GuestQualificationRefusal("enrollment", err)
	}
	if !capacity.GuestLifecycleKeyMatches(key, receipt.Enrollment.Statement.CoreIntentPublicKey) || len(receipt.Enrollment.Statement.Writers) != 1 {
		return result, capacity.GuestQualificationRefusal("key_writers", ErrOriginalUnknown)
	}
	now := time.Now()
	deadline := now.Add(5 * time.Second)
	contextDeadline, exists := ctx.Deadline()
	if !exists {
		return result, capacity.GuestQualificationRefusal("deadline", ErrOriginalUnknown)
	}
	for _, limit := range []time.Time{contextDeadline, leaseUntil} {
		if limit.Before(deadline) {
			deadline = now.Add(limit.Sub(now))
		}
	}
	original, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return result, capacity.GuestQualificationRefusal("nonce", err)
	}
	c := QualificationProbeChallenge{qualificationProbeSchema, qualificationProbePurpose, uuid.NewString(), capacity.GuestRetirementSHA(receipt.Enrollment), receipt.Enrollment.Statement.Tuple, receipt.Enrollment.Statement.Actor, receipt.Enrollment.Statement.Runtime, receipt.Enrollment.Statement.Writers[0], capacity.BusinessCreationSHA256([]byte(hex.EncodeToString(nonce[:]))), capacity.QualificationProbeNonce{}, now.UTC(), deadline.UTC()}
	c, err = capacity.AcquireQualificationProbeNonce(original, client, key, c, receipt.Enrollment)
	if err == nil {
		err = original.Err()
	}
	if err != nil {
		return result, capacity.GuestQualificationRefusal("nonce_preflight", err)
	}
	request := QualificationProbeRequest{Challenge: c}
	request.Signature, err = capacity.GuestLifecycleSignature(key, c)
	if err != nil {
		return result, capacity.GuestQualificationRefusal("signature", err)
	}
	requestWire, err := json.Marshal(request)
	if err != nil {
		return result, capacity.GuestQualificationRefusal("request_encode", err)
	}
	if diagnostic {
		err = store.ReserveGuestQualificationDiagnosticProbe(original, pre.PreregistrationID, requestWire)
	} else {
		err = store.ReserveGuestQualificationProbe(original, policy, generation, fence, owner, pre.PreregistrationID, requestWire)
	}
	if err != nil {
		return result, capacity.GuestQualificationRefusal("reserve_probe", err)
	}
	returned, err := client.Original(original, http.MethodGet, "/v1/qualification-serving-probe", requestWire)
	if diagnosticErr := r.publishProbeDiagnostic(ctx, slot, "normal", returned); diagnosticErr != nil && err == nil {
		return result, diagnosticErr
	}
	if err != nil {
		return result, capacity.GuestQualificationHTTPRefusal(returned, ErrOriginalUnknown)
	}
	if capacity.GuestOriginalHTTPDecode(returned, &result) != nil {
		return result, capacity.GuestQualificationRefusal("probe_decode", ErrOriginalUnknown)
	}
	if original.Err() != nil || ValidateProbeReturn(request, result, receipt.Enrollment, receipt.OriginalProvisioningSHA256, returned.DriverReturnedAt) != nil {
		return result, capacity.GuestQualificationRefusal("probe_validate", ErrOriginalUnknown)
	}
	if diagnostic {
		err = store.RecordGuestQualificationSourceReturn(original, pre.PreregistrationID, "diagnostic_serving_probe", returned.Body)
	} else {
		err = store.FinishGuestQualificationProbe(original, policy, generation, fence, owner, pre.PreregistrationID, returned.Body)
	}
	if err != nil {
		return result, capacity.GuestQualificationRefusal("finish_probe", err)
	}
	if _, err = Publish(original, filepath.Join(SlotDirectory(r.PrivateDirectory, slot), "serving-probe-"+c.ChallengeID+".json"), result); err != nil {
		return result, capacity.GuestQualificationRefusal("publish_probe", err)
	}
	return result, nil
}

func (r *Realm) FreshNativeMember(ctx context.Context, slot int, b model.CapacityMutationBinding) (model.CapacityMutationProof, error) {
	var proof model.CapacityMutationProof
	r.mu.Lock()
	native, exists := r.originals[slot]
	pre := r.preregistrations[slot]
	r.mu.Unlock()
	if !exists {
		return proof, ErrOriginalUnknown
	}
	read, cancel := context.WithTimeout(ctx, 5*time.Second)
	fresh, err := Observe(read, SlotDirectory(r.PrivateDirectory, slot), native.Original, r.QEMUBinarySHA256)
	cancel()
	if err != nil {
		return proof, err
	}
	if r.verifyFixedCommand(ctx, slot, fresh) != nil {
		return proof, ErrOriginalUnknown
	}
	proof = model.CapacityMutationProof{BindingName: b.Name, Slot: slot, ResourceID: native.Original.ResourceID, ResourceCreatedAt: native.Original.OriginalCreateReturnedAt.UTC().Format(time.RFC3339Nano), RequestSHA256: pre.OriginalCreateRequestSHA256, ObservedAt: fresh.CloseReturnedAt, ReceiptRef: "original-native-qemu-fresh:" + capacity.GuestRetirementSHA(fresh), OwnerVerified: true, SpecVerified: true, ObservedCreationGrantID: pre.OriginalCreateGrantID}
	return proof, nil
}

func (r *Realm) OwnedSlots() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	var slots []int
	for slot := 1; slot <= 2; slot++ {
		if _, exists := r.enrollments[slot]; exists {
			slots = append(slots, slot)
		}
	}
	return slots
}

func (r *Realm) RecoveryProbe(ctx context.Context, store repository.CapacityStore, policy model.Manifest, generation, fence int64, owner string, slot int, key ed25519.PrivateKey, client *capacity.GuestOriginalHTTPClient, leaseUntil time.Time) (QualificationProbeReceipt, error) {
	diagnostic := false
	var result QualificationProbeReceipt
	if !SourceLivePartialCase(r.Request.NativeCase) && !SourceTerminalCase(r.Request.NativeCase) {
		return result, ErrOriginalUnknown
	}
	pre, receipt, err := r.OriginalEnrollment(slot)
	if err != nil {
		return result, err
	}
	if !capacity.GuestLifecycleKeyMatches(key, receipt.Enrollment.Statement.CoreIntentPublicKey) || len(receipt.Enrollment.Statement.Writers) != 1 {
		return result, ErrOriginalUnknown
	}
	now := time.Now()
	deadline := now.Add(5 * time.Second)
	contextDeadline, exists := ctx.Deadline()
	if !exists {
		return result, ErrOriginalUnknown
	}
	for _, limit := range []time.Time{contextDeadline, leaseUntil} {
		if limit.Before(deadline) {
			deadline = now.Add(limit.Sub(now))
		}
	}
	original, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return result, err
	}
	c := QualificationProbeChallenge{qualificationProbeSchema, qualificationProbePurpose, uuid.NewString(), capacity.GuestRetirementSHA(receipt.Enrollment), receipt.Enrollment.Statement.Tuple, receipt.Enrollment.Statement.Actor, receipt.Enrollment.Statement.Runtime, receipt.Enrollment.Statement.Writers[0], capacity.BusinessCreationSHA256([]byte(hex.EncodeToString(nonce[:]))), capacity.QualificationProbeNonce{}, now.UTC(), deadline.UTC()}
	c, err = capacity.AcquireQualificationProbeNonce(original, client, key, c, receipt.Enrollment)
	if err == nil {
		err = original.Err()
	}
	if err != nil {
		return result, capacity.GuestQualificationRefusal("nonce_preflight", err)
	}
	request := QualificationProbeRequest{Challenge: c}
	request.Signature, err = capacity.GuestLifecycleSignature(key, c)
	if err != nil {
		return result, err
	}
	requestWire, err := json.Marshal(request)
	if err != nil {
		return result, err
	}
	if diagnostic {
		err = store.ReserveGuestQualificationDiagnosticProbe(original, pre.PreregistrationID, requestWire)
	} else {
		err = store.ReserveGuestQualificationRecoveryProbe(original, policy, generation, fence, owner, pre.PreregistrationID, requestWire)
	}
	if err != nil {
		return result, err
	}
	returned, err := client.Original(original, http.MethodGet, "/v1/qualification-serving-probe", requestWire)
	if diagnosticErr := r.publishProbeDiagnostic(ctx, slot, "recovery", returned); diagnosticErr != nil && err == nil {
		return result, diagnosticErr
	}
	if original.Err() != nil || err != nil || capacity.GuestOriginalHTTPDecode(returned, &result) != nil || ValidateProbeReturn(request, result, receipt.Enrollment, receipt.OriginalProvisioningSHA256, returned.DriverReturnedAt) != nil {
		return result, ErrOriginalUnknown
	}
	if diagnostic {
		err = store.RecordGuestQualificationSourceReturn(original, pre.PreregistrationID, "diagnostic_serving_probe", returned.Body)
	} else {
		err = store.FinishGuestQualificationRecoveryProbe(original, policy, generation, fence, owner, pre.PreregistrationID, returned.Body)
	}
	if err != nil {
		return result, err
	}
	if _, err = Publish(original, filepath.Join(SlotDirectory(r.PrivateDirectory, slot), "recovery-serving-probe-"+c.ChallengeID+".json"), result); err != nil {
		return result, err
	}
	return result, nil
}
