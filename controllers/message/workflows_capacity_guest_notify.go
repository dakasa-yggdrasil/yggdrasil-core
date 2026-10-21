package message

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// This is an actual production workflow operation, separate from qualification
// echo. Only the current compiled production profile can enter its repository
// issuer. Neither input nor a package-global hook supplies transport or proof.
func executeOriginalGuestNotifyProbe(ctx context.Context, db *sql.DB, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput, key ed25519.PrivateKey) (any, error) {
	originalProbe, cancelProbe := context.WithTimeout(ctx, 5*time.Second)
	defer cancelProbe()
	ctx = originalProbe
	if capacity.GuestOriginalNativeQEMUProviderEnabled("native-qemu") || p.GuestNotifyCanaryBinding == nil || capacity.ValidateGuestNotifyCanaryBinding(p) != nil || input.RequestID != "" {
		return nil, errOriginalGuestStep
	}
	if _, err := uuid.Parse(input.PreregistrationID); err != nil {
		return nil, errOriginalGuestStep
	}
	publication, err := store.IssueGuestNotifyCanaryPublication(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, input.PreregistrationID, "initial_useful_membership", key)
	if err != nil || publication.Slot != input.Slot {
		return nil, errOriginalGuestStep
	}
	if _, err = originalGuestNotifyCall(ctx, db, store, policy, p, input, publication, key); err != nil {
		return nil, err
	}
	read, err := store.IssueGuestNotifyCanaryRead(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, input.PreregistrationID, "initial_useful_membership", publication.ChallengeID, key)
	if err != nil || read.Slot != input.Slot {
		return nil, errOriginalGuestStep
	}
	business, err := originalGuestNotifyCall(ctx, db, store, policy, p, input, read, key)
	if err != nil {
		return nil, err
	}
	return struct {
		ChallengeID             string                                       `json:"challenge_id"`
		PublicationChallengeID  string                                       `json:"publication_challenge_id"`
		EnrollmentSHA256        string                                       `json:"enrollment_sha256"`
		Business                model.CapacityGuestNotifyBusinessObservation `json:"business"`
		PhysicalRetirementKnown bool                                         `json:"physical_retirement_known"`
	}{read.ChallengeID, publication.ChallengeID, read.EnrollmentSHA256, business, false}, nil
}

func originalGuestNotifyCall(ctx context.Context, db *sql.DB, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput, c model.CapacityGuestNotifyCanaryChallenge, key ed25519.PrivateKey) (model.CapacityGuestNotifyBusinessObservation, error) {
	var empty model.CapacityGuestNotifyBusinessObservation
	if p.GuestRetirementBinding == nil || c.PolicyID != policy.ID.String() || c.PolicyChecksum != policy.Checksum || c.Slot != input.Slot || c.PreregistrationID != input.PreregistrationID || ctx.Err() != nil {
		return empty, errOriginalGuestStep
	}
	var member model.CapacityGuestRetirementMemberBinding
	for _, candidate := range p.GuestRetirementBinding.Members {
		if candidate.Name == c.BindingName && candidate.Slot == c.Slot {
			member = candidate
		}
	}
	if member.Name == "" {
		return empty, errOriginalGuestStep
	}
	original, stop := context.WithDeadline(ctx, c.OriginalDeadline)
	defer stop()
	client, err := sourceGuestClient(original, db, member)
	if err != nil {
		return empty, err
	}
	defer client.Close()
	enrollment, err := store.GuestNotifyCanaryEnrollment(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, c.PreregistrationID)
	if err != nil {
		return empty, err
	}
	finalized, nonceReturn, err := capacity.AcquireGuestNotifyCanaryNonce(original, client, key, c, enrollment)
	if err != nil {
		return empty, err
	}
	if err = store.FinalizeGuestNotifyCanaryNonce(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, finalized, nonceReturn); err != nil {
		return empty, err
	}
	c = finalized
	if err = store.ReserveGuestNotifyCanarySend(original, policy, input.Generation, input.FencingToken, input.LeaseOwner, c); err != nil {
		return empty, err
	}
	body, err := json.Marshal(model.CapacityGuestNotifyCanaryRequest{Challenge: c})
	if err != nil {
		return empty, err
	}
	method, path := http.MethodGet, capacity.GuestNotifyCanaryPath
	if capacity.GuestNotifyCanaryPublication(c) {
		method, path = http.MethodPost, capacity.GuestNotifyCanaryPublicationPath
	}
	returned, callErr := client.Original(original, method, path, body)
	// A lost original is retained once as diagnostic evidence under the SAME
	// source scope. This does not retry a POST or renew its original deadline.
	retain, cancel := context.WithTimeout(context.WithoutCancel(original), 5*time.Second)
	defer cancel()
	business, recordErr := store.RecordGuestNotifyCanaryReturn(retain, policy, input.Generation, input.FencingToken, input.LeaseOwner, c, returned)
	if callErr != nil || recordErr != nil {
		return empty, errOriginalGuestStep
	}
	return business, nil
}
