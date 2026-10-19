//go:build linux && nativequalification

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"net/http"
	"path/filepath"
	"reflect"
	"time"
)

func (f *fixture) reissueCanonicalPostlossChild(ctx context.Context, issuer repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, pre model.CapacityGuestOriginalProvisioningPreregistration, first model.CapacityMutationGrant, issue model.CapacityCompensationIssue) (model.CapacityMutationGrant, error) {
	var none model.CapacityMutationGrant
	initialBinding, bindingErr := capacity.VMObservationBinding(p, f.binding.MutationBindingName)
	if !q.PostlossSourceCase(f.request.NativeCase) || bindingErr != nil || !initialBinding.CompensationEnabled || first.CompensationOf != pre.OriginalCreateGrantID || first.State != "issued" {
		return none, q.ErrOriginalUnknown
	}
	initial, err := issuer.CanonicalSourceEligibilityWire(ctx, pre.OriginalCreateGrantID)
	if err != nil {
		return none, err
	}
	if _, err = q.PublishBytes(ctx, filepath.Join(f.private, "canonical-postloss-initial-eligibility.json"), initial); err != nil {
		return none, err
	}
	var before []byte
	if err = f.db.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, first.GrantID).Scan(&before); err != nil {
		return none, err
	}
	var record struct {
		Grant                 model.CapacityMutationGrant          `json:"grant"`
		AttemptID             string                               `json:"attempt_id"`
		SettlementTokenSHA256 string                               `json:"settlement_token_sha256"`
		Settlement            *model.CapacityMutationSettleRequest `json:"settlement"`
		Proof                 *model.CapacityMutationProof         `json:"proof"`
	}
	if json.Unmarshal(before, &record) != nil || record.Grant != first || record.AttemptID != "" || record.SettlementTokenSHA256 != "" || record.Settlement != nil || record.Proof != nil {
		return none, q.ErrOriginalUnknown
	}
	if _, err = q.PublishBytes(ctx, filepath.Join(f.private, "canonical-postloss-child-first-before.json"), before); err != nil {
		return none, err
	}
	// Wait actual DB wall clock, never edit expires_at or renew a lease. Child1
	// cannot own any effect: no redemption or signed effect authority exists.
	var expiredAt time.Time
	for {
		if ctx.Err() != nil {
			return none, q.ErrOriginalUnknown
		}
		if err = f.db.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&expiredAt); err != nil {
			return none, err
		}
		if !expiredAt.Before(first.ExpiresAt) {
			break
		}
		wait := time.Until(first.ExpiresAt)
		if wait > 250*time.Millisecond {
			wait = 250 * time.Millisecond
		}
		if wait <= 0 {
			wait = 10 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return none, q.ErrOriginalUnknown
		case <-time.After(wait):
		}
	}
	denied, err := f.realm.ExpireCanonicalPostlossUnusedChild(ctx, first)
	if err != nil {
		return none, err
	}
	deniedWire, err := q.Publish(ctx, filepath.Join(f.private, "canonical-postloss-expired-redeem-return.json"), denied)
	if err != nil {
		return none, err
	}
	var after []byte
	if err = f.db.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, first.GrantID).Scan(&after); err != nil {
		return none, err
	}
	var expired = record
	if json.Unmarshal(after, &expired) != nil || expired.Grant.State != "expired" || expired.AttemptID != "" || expired.SettlementTokenSHA256 != "" || expired.Settlement != nil || expired.Proof != nil {
		return none, q.ErrOriginalUnknown
	}
	compare := expired
	compare.Grant.State = "issued"
	if !reflect.DeepEqual(record, compare) {
		return none, q.ErrOriginalUnknown
	}
	if !postlossOnlyExpiredStateChange(before, after) {
		return none, q.ErrOriginalUnknown
	}
	var authorities int
	if err = f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_canonical_source_effect_authorities WHERE child_grant_id=$1`, first.GrantID).Scan(&authorities); err != nil || authorities != 0 {
		return none, q.ErrOriginalUnknown
	}
	if _, err = q.PublishBytes(ctx, filepath.Join(f.private, "canonical-postloss-child-first-after.json"), after); err != nil {
		return none, err
	}
	// Generate challenge BEFORE both new current reads. Original failure/witness
	// and first child are immutable; only append a freshness revision.
	var entropy [32]byte
	if _, err = rand.Read(entropy[:]); err != nil {
		return none, err
	}
	nonce := hex.EncodeToString(entropy[:])
	nonceSHA := capacity.BusinessCreationSHA256([]byte(nonce))
	readStart := time.Now().UTC()
	request := struct {
		Schema      string `json:"schema"`
		NonceSHA256 string `json:"nonce_sha256"`
	}{"canonical_postloss_fresh_failure_request_v1", nonceSHA}
	if err = issuer.PrepareCanonicalPostlossReadChallenge(ctx, policy, pre.OriginalCreateGrantID, first.GrantID, nonceSHA); err != nil {
		return none, err
	}
	if _, err = q.Publish(ctx, filepath.Join(f.private, "canonical-postloss-fresh-read-request.json"), request); err != nil {
		return none, err
	}
	_, nativeWire, err := f.realm.FreshCanonicalPostlossNative(ctx)
	if err != nil {
		return none, err
	}
	client, err := f.sourceClient(2)
	if err != nil {
		return none, err
	}
	defer client.Close()
	requestWire, err := json.Marshal(request)
	if err != nil {
		return none, err
	}
	read, cancel := context.WithTimeout(ctx, 5*time.Second)
	returned, callErr := client.Original(read, http.MethodGet, "/v1/qualification-source-refusal", requestWire)
	cancel()
	if callErr != nil || returned.Status != 200 {
		return none, q.ErrOriginalUnknown
	}
	var freshFailure repository.CanonicalPostlossFreshFailureRead
	if capacity.GuestOriginalHTTPDecode(returned, &freshFailure) != nil || freshFailure.ReadNonceSHA256 != nonceSHA {
		return none, q.ErrOriginalUnknown
	}
	if _, err = q.PublishBytes(ctx, filepath.Join(q.SlotDirectory(f.private, 2), "core-postloss-fresh-failure-read.json"), returned.Body); err != nil {
		return none, err
	}
	fresh, err := issuer.AppendCanonicalPostlossFreshRead(ctx, policy, pre.OriginalCreateGrantID, first.GrantID, nonceSHA, nativeWire, returned.Body)
	if err != nil {
		return none, err
	}
	freshWire, err := issuer.CanonicalSourceEligibilityWire(ctx, pre.OriginalCreateGrantID)
	if err != nil {
		return none, err
	}
	if _, err = q.PublishBytes(ctx, filepath.Join(f.private, "canonical-postloss-fresh-eligibility.json"), freshWire); err != nil {
		return none, err
	}
	baselineClient, err := f.sourceClient(1)
	if err != nil {
		return none, err
	}
	defer baselineClient.Close()
	var currentWire []byte
	var intent model.CapacityIntent
	if err = f.db.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, f.namespace, p.Environment, p.Domain, p.Dimension).Scan(&currentWire); err != nil || capacity.DecodeGuestLifecycle(currentWire, &intent) != nil {
		return none, q.ErrOriginalUnknown
	}
	parentStore := issuer
	parentStore.ExecutorID = intent.LeaseExecutorID
	probe, err := f.realm.DiagnosticProbe(ctx, parentStore, 1, f.corePrivate, baselineClient)
	if err != nil {
		return none, err
	}
	probeWire, err := q.Publish(ctx, filepath.Join(f.private, "canonical-postloss-fresh-baseline-probe.json"), probe)
	if err != nil {
		return none, err
	}
	binding, err := capacity.VMObservationBinding(p, f.binding.MutationBindingName)
	if err != nil {
		return none, err
	}
	native, err := f.realm.FreshNativeMember(ctx, 1, binding)
	if err != nil {
		return none, err
	}
	var desired []byte
	for _, slot := range binding.Slots {
		if slot.Slot == 1 {
			desired, err = json.Marshal(slot.DesiredSpec)
		}
	}
	if err != nil || len(desired) == 0 {
		return none, q.ErrOriginalUnknown
	}
	if err = parentStore.RecordMutationSlot(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, model.CapacityMutationIssue{BindingName: binding.Name, DesiredSpec: desired}, native); err != nil {
		return none, err
	}
	if err = parentStore.CheckNativeMembershipCoverage(ctx, policy, binding, []model.CapacityMutationProof{native}); err != nil {
		return none, err
	}
	zero := 0
	issue.FailedProof = fresh.Aggregate
	issue.DrainProof = model.CapacityTransitionProof{Assessment: q.QualificationAssessment(p, 1, 0.9, probe.OriginalNativeAfterReturnedAt), ObservedAt: probe.OriginalNativeAfterReturnedAt, ReceiptRef: "canonical-postloss-current-baseline:" + capacity.GuestRetirementSHA(probe), Healthy: true, MembershipComplete: true, AdmissionClosed: true, RoutingWithdrawn: true, Inflight: &zero, NativeActionsInflight: &zero}
	second, err := issuer.IssueCompensation(ctx, policy, issue)
	if err != nil || second.GrantID == first.GrantID || second.CompensationOf != pre.OriginalCreateGrantID || second.State != "issued" {
		return none, q.ErrOriginalUnknown
	}
	var secondIssued time.Time
	if err = f.db.QueryRowContext(ctx, `SELECT (grant_record->>'created_at')::timestamptz FROM public.capacity_mutation_grants WHERE id=$1`, second.GrantID).Scan(&secondIssued); err != nil {
		return none, err
	}
	var witnessWire, replyWire []byte
	if err = f.db.QueryRowContext(ctx, `SELECT witness_wire,transport_read_wire FROM public.capacity_canonical_postloss_originals WHERE parent_grant_id=$1`, pre.OriginalCreateGrantID).Scan(&witnessWire, &replyWire); err != nil {
		return none, err
	}
	var witness model.CapacityGuestOriginalCreateWitness
	if capacity.DecodeGuestLifecycle(witnessWire, &witness) != nil {
		return none, q.ErrOriginalUnknown
	}
	parent, err := f.realm.OriginalMutationReceipt(ctx, pre.OriginalCreateGrantID)
	if err != nil || parent.Outcome != "uncertain" {
		return none, q.ErrOriginalUnknown
	}
	contract := map[string]any{"schema": "canonical_postloss_child_reissue_v1", "scope": "SOURCE_ONLY_SAME_UNCERTAIN_CREATE_FAILED_PAYLOAD_FRESH_READ_REISSUE", "case": f.request.NativeCase, "core_source": capacity.CurrentGuestCoreSource(), "guest_source": f.request.SourceCommit, "parent_grant_id": pre.OriginalCreateGrantID, "original_settlement_sha256": witness.OriginalCreateSettlementSHA256, "observed_witness_sha256": capacity.BusinessCreationSHA256(witnessWire), "owning_reply_read_sha256": capacity.BusinessCreationSHA256(replyWire), "initial_eligibility_sha256": capacity.BusinessCreationSHA256(initial), "fresh_eligibility_sha256": capacity.BusinessCreationSHA256(freshWire), "first_child_before_sha256": capacity.BusinessCreationSHA256(before), "first_child_after_sha256": capacity.BusinessCreationSHA256(after), "expired_redeem_return_sha256": capacity.BusinessCreationSHA256(deniedWire), "fresh_native_read_sha256": capacity.BusinessCreationSHA256(nativeWire), "fresh_failure_read_sha256": capacity.BusinessCreationSHA256(returned.Body), "fresh_baseline_probe_sha256": capacity.BusinessCreationSHA256(probeWire), "second_child_grant_id": second.GrantID, "first_child_grant_id": first.GrantID, "first_expires_at": first.ExpiresAt, "expiry_observed_at": expiredAt, "fresh_read_started_at": readStart, "fresh_read_returned_at": time.Now().UTC(), "second_issued_at": secondIssued, "first_child_never_redeemed": true, "first_child_effect_authority_absent": true, "original_parent_outcome": "uncertain", "production_qualified": false, "native_qualified": false}
	if _, err = q.Publish(ctx, filepath.Join(f.private, "canonical-postloss-reissue-contract.json"), contract); err != nil {
		return none, err
	}
	return second, nil
}

// Full original DB records may differ only at grant.state. This is not a
// projection that could conceal changes to policy, executor, scope or proof.
func postlossOnlyExpiredStateChange(before, after []byte) bool {
	var original, current map[string]any
	if json.Unmarshal(before, &original) != nil || json.Unmarshal(after, &current) != nil {
		return false
	}
	oldGrant, ok := original["grant"].(map[string]any)
	if !ok {
		return false
	}
	newGrant, ok := current["grant"].(map[string]any)
	if !ok || oldGrant["state"] != "issued" || newGrant["state"] != "expired" {
		return false
	}
	newGrant["state"] = "issued"
	return reflect.DeepEqual(original, current)
}
