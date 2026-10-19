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
func (r *Realm) FloorSourceProbe(ctx context.Context, store repository.CapacityStore, policy model.Manifest, generation, fence int64, owner string, slot int, key ed25519.PrivateKey, client *capacity.GuestOriginalHTTPClient, leaseUntil time.Time) (QualificationProbeReceipt, error) {
	diagnostic := false
	var result QualificationProbeReceipt
	if !SourceFailedFloorCase(r.Request.NativeCase) { return result, ErrOriginalUnknown }
	pre, receipt, err := r.OriginalEnrollment(slot)
	if err != nil {
		return result, err
	}
	if !capacity.GuestLifecycleKeyMatches(key, receipt.Enrollment.Statement.CoreIntentPublicKey) || len(receipt.Enrollment.Statement.Writers) != 1 {
		return result, ErrOriginalUnknown
	}
	now := time.Now().UTC()
	deadline := now.Add(5 * time.Second)
	contextDeadline, exists := ctx.Deadline()
	if !exists {
		return result, ErrOriginalUnknown
	}
	for _, limit := range []time.Time{contextDeadline, leaseUntil} {
		if limit.Before(deadline) {
			deadline = limit
		}
	}
	original, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return result, err
	}
	c := QualificationProbeChallenge{qualificationProbeSchema, qualificationProbePurpose, uuid.NewString(), capacity.GuestRetirementSHA(receipt.Enrollment), receipt.Enrollment.Statement.Tuple, receipt.Enrollment.Statement.Actor, receipt.Enrollment.Statement.Runtime, receipt.Enrollment.Statement.Writers[0], capacity.BusinessCreationSHA256([]byte(hex.EncodeToString(nonce[:]))), now, deadline}
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
		err = store.ReserveGuestQualificationFloorProbe(original, policy, generation, fence, owner, pre.PreregistrationID, requestWire)
	}
	if err != nil {
		return result, err
	}
	returned, err := client.Original(original, http.MethodGet, "/v1/qualification-serving-probe", requestWire)
	if err != nil || capacity.GuestOriginalHTTPDecode(returned, &result) != nil || ValidateProbeReturn(request, result, receipt.Enrollment, receipt.OriginalProvisioningSHA256, returned.DriverReturnedAt) != nil {
		return result, ErrOriginalUnknown
	}
	if diagnostic {
		err = store.RecordGuestQualificationSourceReturn(original, pre.PreregistrationID, "diagnostic_serving_probe", returned.Body)
	} else {
		err = store.FinishGuestQualificationFloorProbe(original, policy, generation, fence, owner, pre.PreregistrationID, returned.Body)
	}
	if err != nil {
		return result, err
	}
	if _, err = Publish(original, filepath.Join(SlotDirectory(r.PrivateDirectory, slot), "floor-serving-probe-"+c.ChallengeID+".json"), result); err != nil {
		return result, err
	}
	return result, nil
}

