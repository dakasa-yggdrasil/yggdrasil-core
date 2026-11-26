package repository

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Read-only routing operand for the private SDK GET. Issuance rechecks this
// exact stored checkpoint under the scope/UID locks after that real RPC.
func (s CapacityStore) UnredeemedProtectRecoveryTarget(ctx context.Context, policy model.Manifest, b model.CapacityUnredeemedProtectRecoveryBinding) (model.CapacityNativePodCheckpoint, error) {
	var cp model.CapacityNativePodCheckpoint
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return cp, err
	}
	if s.DB == nil || s.ExecutorPowerOperator != b.OperatorID || capacity.ValidateUnredeemedProtectRecoveryBinding(policy, p, b) != nil {
		return cp, ErrCapacityMutationAuthorization
	}
	var raw []byte
	if s.DB.QueryRowContext(ctx, `SELECT checkpoint_record FROM public.capacity_native_lifetimes WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND pod_uid=$5`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, b.PodUID).Scan(&raw) != nil || nativeCanonicalArchiveSHA(raw) != b.CheckpointSHA256 || capacity.DecodeNativeCapacity(json.RawMessage(raw), &cp) != nil || cp.PolicyID != policy.ID || cp.PolicyChecksum != policy.Checksum || cp.BindingSHA256 != capacity.NativeLifetimeBindingSHA256(p) || cp.PodUID != b.PodUID {
		return cp, ErrCapacityConflict
	}
	return cp, nil
}

// Unlike normal admission, this authority is one stored, manual, synchronous
// human workflow. Its identity is retained on the child, never impersonated as
// the policy's ordinary admission workflow.
func nativeProtectRecoveryWorkflow(ctx context.Context, tx *sql.Tx, id uuid.UUID, policy model.Manifest, b model.CapacityUnredeemedProtectRecoveryBinding) (model.ManifestReference, string, error) {
	var ref model.ManifestReference
	var raw []byte
	var checksum string
	ref.ID, ref.Kind = id, "workflow"
	if id == uuid.Nil || tx.QueryRowContext(ctx, `SELECT spec,checksum,namespace,name,version FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2 AND active FOR SHARE`, id, policy.Metadata.Namespace).Scan(&raw, &checksum, &ref.Namespace, &ref.Name, &ref.Version) != nil {
		return ref, "", ErrCapacityMutationAuthorization
	}
	var wf map[string]json.RawMessage
	var mode string
	var trigger map[string]string
	var auth map[string]json.RawMessage
	var steps []map[string]json.RawMessage
	if json.Unmarshal(raw, &wf) != nil || json.Unmarshal(wf["dispatch_mode"], &mode) != nil || mode != "sync" || json.Unmarshal(wf["trigger"], &trigger) != nil || len(trigger) != 1 || trigger["mode"] != "manual" || json.Unmarshal(wf["authorization"], &auth) != nil || len(auth) == 0 || json.Unmarshal(wf["steps"], &steps) != nil || len(steps) != 1 {
		return ref, "", ErrCapacityMutationAuthorization
	}
	step := steps[0]
	var name string
	var timeout int
	var retry map[string]int
	var use map[string]string
	var with map[string]json.RawMessage
	if len(step) != 5 || json.Unmarshal(step["id"], &name) != nil || name == "" || json.Unmarshal(step["timeout_seconds"], &timeout) != nil || timeout != 90 || json.Unmarshal(step["retry"], &retry) != nil || len(retry) != 1 || retry["max_attempts"] != 1 || json.Unmarshal(step["use"], &use) != nil || len(use) != 2 || use["kind"] != "yggdrasil" || use["operation"] != capacity.RecoverUnredeemedNativeProtect || json.Unmarshal(step["with"], &with) != nil || len(with) != 2 || bytes.Contains(with["binding"], []byte("{{")) {
		return ref, "", ErrCapacityMutationAuthorization
	}
	var literal model.CapacityUnredeemedProtectRecoveryBinding
	var confirmation string
	left, _ := json.Marshal(b)
	if capacity.DecodeNativeCapacity(with["binding"], &literal) != nil || json.Unmarshal(with["confirmation"], &confirmation) != nil || (confirmation != b.Confirmation && confirmation != "{{ inputs.confirmation }}") {
		return ref, "", ErrCapacityMutationAuthorization
	}
	right, _ := json.Marshal(literal)
	if !bytes.Equal(left, right) {
		return ref, "", ErrCapacityMutationAuthorization
	}
	return ref, checksum, nil
}

// Count permanent identities across all generations/archives, not just hot
// permissions. Even a lost/archived fifth body cannot reopen this one-use path.
func nativeProtectRecoveryOriginals(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, b model.CapacityUnredeemedProtectRecoveryBinding, child *model.CapacityNativeCommand) error {
	var identities, hot, archives, lifetimes, legacy, live int
	if tx.QueryRowContext(ctx, `SELECT
	 (SELECT count(*) FROM public.capacity_native_command_identities WHERE subject_uid=$1),
	 (SELECT count(*) FROM public.capacity_native_commands WHERE subject_uid=$1 OR command_record->'request'->>'expected_pod_uid'=$1),
	 (SELECT count(*) FROM public.capacity_native_command_archive a LEFT JOIN public.capacity_native_command_identities i ON i.id=a.id WHERE i.subject_uid=$1 OR a.command_record->'request'->>'expected_pod_uid'=$1),
	 (SELECT count(*) FROM public.capacity_native_lifetime_archive WHERE pod_uid=$1),
	 (SELECT count(*) FROM public.capacity_native_pod_checkpoints WHERE pod_uid=$1),
 (SELECT count(*) FROM public.capacity_native_lifetimes WHERE pod_uid=$1)`, b.PodUID).Scan(&identities, &hot, &archives, &lifetimes, &legacy, &live) != nil {
		return ErrCapacityConflict
	}
	want := 4
	if child != nil {
		want++
	}
	if identities != want || hot != want || archives != 0 || lifetimes != 0 || legacy != 0 || live != 1 {
		return ErrCapacityConflict
	}
	intent, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, false)
	if err != nil {
		return err
	}
	var originalWorkflow uuid.UUID
	var originalOwner, originalExecutor string
	for n, ref := range b.Commands {
		var raw []byte
		if tx.QueryRowContext(ctx, `SELECT command_record FROM public.capacity_native_commands WHERE id=$1 FOR UPDATE`, ref.CommandID).Scan(&raw) != nil || nativeCanonicalArchiveSHA(raw) != ref.RecordSHA256 {
			return ErrCapacityConflict
		}
		var c model.CapacityNativeCommand
		if capacity.DecodeNativeCapacity(json.RawMessage(raw), &c) != nil || c.CommandID.String() != ref.CommandID || c.PolicyID != policy.ID || c.PolicyChecksum != policy.Checksum || c.Namespace != policy.Metadata.Namespace || c.Environment != p.Environment || c.Domain != p.Domain || c.Dimension != p.Dimension || c.IntentGeneration != b.ExpectedIntentGeneration || c.FencingToken != b.ExpectedIntentFencingToken || c.Operation != capacity.EnsureNativePodDrain || c.Phase != "protect" || c.Sequence != n+1 || c.State != "refused_no_redemption" || !c.AdmissionOnly || c.ProtectRecovery != nil || !nativeAbortRecoveryNoEffect(c) || c.Adapter != p.AssessmentBinding.Snapshot.Adapter || c.AdapterPrincipalID != p.HPAExecutionBinding.AdapterPrincipalID || c.OriginPolicySHA256 != nativeCanonicalArchiveSHA(policy.Spec) || c.OriginPolicySHA256 != nativeCanonicalArchiveSHA(c.OriginPolicy) || nativeAbortRecoveryIdentity(ctx, tx, c, b.PodUID) != nil || nativeAbortRecoveryHotIdentity(ctx, tx, c, b.PodUID) != nil {
			return ErrCapacityConflict
		}
		canonical, phase, err := canonicalNativeCommandRequest(c.Operation, c.Request)
		if err != nil || phase != "protect" || nativeArchiveSHA(canonical) != c.RequestSHA256 {
			return ErrCapacityConflict
		}
		if validateNativeCommandRequest(ctx, tx, p, intent, c.Operation, c.Phase, b.PodUID, c.Request) != nil || c.LeaseOwner == "" || !validCapacityExecutor(c.ExecutorID) {
			return ErrCapacityConflict
		}
		if n == 0 {
			originalWorkflow, originalOwner, originalExecutor = c.WorkflowID, c.LeaseOwner, c.ExecutorID
		}
		if c.WorkflowID != originalWorkflow || c.LeaseOwner != originalOwner || c.ExecutorID != originalExecutor {
			return ErrCapacityConflict
		}
	}
	wf := nativeCapacityWorkflow(p, true)
	var active bool
	if tx.QueryRowContext(ctx, `SELECT active FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2 AND name=$3 AND jsonb_typeof(spec->'authorization')='object' FOR SHARE`, originalWorkflow, wf.Namespace, wf.Name).Scan(&active) != nil || !active {
		return ErrCapacityMutationAuthorization
	}
	return nil
}

func nativeProtectRecoveryCheckpoint(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, intent model.CapacityIntent, b model.CapacityUnredeemedProtectRecoveryBinding) (model.CapacityNativePodCheckpoint, error) {
	cp, err := nativeLifetimeCheckpoint(ctx, tx, p, intent, b.PodUID)
	if err != nil {
		return cp, err
	}
	raw, _ := json.Marshal(cp)
	if nativeCanonicalArchiveSHA(raw) != b.CheckpointSHA256 || cp.IntentGeneration != b.ExpectedIntentGeneration || cp.State != "planned" || cp.ConfirmedAt != nil || !nativeAbortRecoveryAbsent(cp.NativeTerminationReceipt) || !nativeAbortRecoveryAbsent(cp.ProjectionAcknowledgement) || !nativeAbortRecoveryAbsent(cp.RootAcknowledgement) || cp.OriginPolicySHA256 != nativeCanonicalArchiveSHA(policy.Spec) || cp.OriginPolicySHA256 != nativeCanonicalArchiveSHA(cp.OriginPolicy) || cp.OriginChallengeSHA256 != nativeArchiveSHA(cp.OriginChallengeBytes) {
		return cp, ErrCapacityConflict
	}
	return cp, nil
}

// IssueUnredeemedProtectRecovery atomically retains a separate child and new
// lease/generation. Original four permissions and checkpoint are byte-unchanged.
// The boot operand comes only from the controller's actual private SDK RPC.
func (s CapacityStore) IssueUnredeemedProtectRecovery(ctx context.Context, policy model.Manifest, b model.CapacityUnredeemedProtectRecoveryBinding, boot model.AdapterCapacityPodAdmissionResponse) (model.CapacityIntent, model.CapacityNativeCommand, string, error) {
	var current model.CapacityIntent
	var child model.CapacityNativeCommand
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return current, child, "", err
	}
	if s.DB == nil || !s.ExecutionEnabled || !s.AdmissionOnly || s.ExecutorPowerOperator != b.OperatorID || !validCapacityExecutor(s.ExecutorID) || capacity.ValidateUnredeemedProtectRecoveryBinding(policy, p, b) != nil {
		return current, child, "", ErrCapacityMutationAuthorization
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return current, child, "", err
	}
	defer tx.Rollback()
	fail := func(e error) (model.CapacityIntent, model.CapacityNativeCommand, string, error) {
		return model.CapacityIntent{}, model.CapacityNativeCommand{}, "", e
	}
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return fail(err)
	}
	if err = guestContractLockBindingsTx(ctx, tx, policy, p); err != nil {
		return fail(err)
	}
	var checksum string
	var active bool
	if tx.QueryRowContext(ctx, `SELECT checksum,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 AND name=$3 FOR SHARE`, policy.ID, policy.Metadata.Namespace, policy.Metadata.Name).Scan(&checksum, &active) != nil || !active || checksum != policy.Checksum {
		return fail(ErrCapacityConflict)
	}
	wf, wfSHA, err := nativeProtectRecoveryWorkflow(ctx, tx, s.WorkflowID, policy, b)
	if err != nil {
		return fail(err)
	}
	if err = checkMutationIntegration(ctx, tx, nativeObservationMutationBinding(p.AssessmentBinding.Snapshot.Adapter)); err != nil {
		return fail(err)
	}
	if err = lockNativeBoundOwner(ctx, tx, policy, p, b.PodUID); err != nil {
		return fail(err)
	}
	if err = guardNativePreRegistrationAbortTx(ctx, tx, b.PodUID); err != nil {
		return fail(err)
	}
	if err = guardOriginalHostCapacityTx(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return fail(err)
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return fail(err)
	}
	now = now.UTC()
	current, err = loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err != nil {
		return fail(err)
	}
	if failedServingQuarantineBlocks(&current) || current.PolicyID != policy.ID || current.PolicyChecksum != policy.Checksum || current.PolicyName != policy.Metadata.Name || current.Generation != b.ExpectedIntentGeneration || current.FencingToken != b.ExpectedIntentFencingToken || current.Generation >= maxCapacityGeneration || current.FencingToken >= maxCapacityGeneration || current.Phase != "admission_pending" || current.RecoveryOnly || current.WitnessedUnenrolledExpansionCleanupID != "" || current.FailedUnwitnessedExpansionCleanupID != "" || current.WitnessedExpansionTerminalReconcile != nil || current.FailedExpansionTerminalReconcile != nil || current.InstalledReadinessHandoff != nil || current.FailedInstalledDisposal != nil {
		return fail(ErrCapacityConflict)
	}
	if current.LeaseExpiresAt != nil && current.LeaseExpiresAt.After(now) {
		return fail(ErrCapacityLease)
	}
	cp, err := nativeProtectRecoveryCheckpoint(ctx, tx, policy, p, current, b)
	if err != nil {
		return fail(err)
	}
	if capacity.ValidateUnredeemedProtectRecoveryBoot(p, cp, boot, now) != nil {
		return fail(ErrCapacityConflict)
	}
	if err = nativeProtectRecoveryOriginals(ctx, tx, policy, p, b, nil); err != nil {
		return fail(err)
	}
	unsettled, err := nativeActiveUnsettledTx(ctx, tx, policy, p, b.PodUID)
	if err != nil {
		return fail(err)
	}
	if unsettled.ActiveUnsettled != 0 {
		return fail(ErrCapacityConflict)
	}
	var retained int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_commands WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&retained) != nil || retained >= maxNativeRetainedCommands {
		return fail(ErrCapacityConflict)
	}
	var challenge model.NativePodTerminationChallenge
	if capacity.DecodeNativeCapacity(cp.Challenge, &challenge) != nil {
		return fail(ErrCapacityConflict)
	}
	no := false
	req := model.AdapterEnsureCapacityPodDrainRequest{BindingName: p.HPAExecutionBinding.PodTerminationBinding, PodName: cp.PodName, ExpectedPodUID: cp.PodUID, ExpectedPodGeneration: cp.PodGeneration, ExpectedPodResourceVersion: boot.Observation.PodResourceVersion, ExpectedContainerID: cp.ContainerID, ExpectedContainerStartedAt: cp.ContainerStartedAt, ExpectedRestartCount: cp.RestartCount, Challenge: challenge, Phase: "protect", DryRun: &no}
	raw, _ := json.Marshal(req)
	canonical, phase, err := canonicalNativeCommandRequest(capacity.EnsureNativePodDrain, raw)
	if err != nil || phase != "protect" {
		return fail(ErrCapacityConflict)
	}
	if err = validateNativeCommandRequest(ctx, tx, p, current, capacity.EnsureNativePodDrain, phase, b.PodUID, canonical); err != nil {
		return fail(err)
	}
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return fail(err)
	}
	token := hex.EncodeToString(secret)
	current.Generation++
	current.FencingToken++
	current.LeaseOwner, current.LeaseExecutorID, current.UpdatedAt = uuid.NewString(), s.ExecutorID, now
	expires := now.Add(time.Duration(p.LeaseSeconds) * time.Second)
	if deadline, ok := ctx.Deadline(); !ok || !deadline.After(now) {
		return fail(ErrCapacityLease)
	} else if deadline.Before(expires) {
		expires = deadline
	}
	current.LeaseExpiresAt = &expires
	child = model.CapacityNativeCommand{CommandID: uuid.New(), PolicyID: policy.ID, PolicyChecksum: policy.Checksum, WorkflowID: wf.ID, Namespace: current.Namespace, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, IntentGeneration: current.Generation, FencingToken: current.FencingToken, LeaseOwner: current.LeaseOwner, ExecutorID: s.ExecutorID, Adapter: p.AssessmentBinding.Snapshot.Adapter, AdapterPrincipalID: p.HPAExecutionBinding.AdapterPrincipalID, Operation: capacity.EnsureNativePodDrain, Phase: "protect", Sequence: 1, Request: canonical, RequestSHA256: nativeArchiveSHA(canonical), State: "issued", AuthorityTokenSHA256: nativeArchiveSHA([]byte(token)), CreatedAt: now, ExpiresAt: expires, UpdatedAt: now, AdmissionOnly: true, OriginPolicy: append(json.RawMessage(nil), policy.Spec...), OriginPolicySHA256: nativeCanonicalArchiveSHA(policy.Spec)}
	child.ProtectRecovery = &model.CapacityUnredeemedProtectRecoveryProof{Schema: capacity.UnredeemedProtectRecoverySchema, Binding: b, Workflow: wf, WorkflowChecksum: wfSHA, RecoveryID: uuid.NewString(), ChildID: child.CommandID.String(), Generation: current.Generation, Fence: current.FencingToken, Boot: boot, AuthoredAt: now}
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_command_identities(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,authority_token_sha256,request_sha256)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, child.CommandID, child.Namespace, child.Environment, child.Domain, child.Dimension, child.IntentGeneration, child.Operation, b.PodUID, child.Phase, child.Sequence, child.AuthorityTokenSHA256, child.RequestSHA256); err != nil {
		return fail(err)
	}
	record, _ := json.Marshal(child)
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_commands(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,state,authority_token_sha256,command_record,updated_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, child.CommandID, child.Namespace, child.Environment, child.Domain, child.Dimension, child.IntentGeneration, child.Operation, b.PodUID, child.Phase, child.Sequence, child.State, child.AuthorityTokenSHA256, record, now); err != nil {
		return fail(err)
	}
	intentRaw, _ := json.Marshal(current)
	if _, err = tx.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$5,updated_at=$6 WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, current.Namespace, p.Environment, p.Domain, p.Dimension, intentRaw, now); err != nil {
		return fail(err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref)VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, current.Namespace, p.Environment, p.Domain, p.Dimension, current.Generation, current.FencingToken, current.Phase, "native:one-unredeemed-protect-recovery:"+child.CommandID.String()); err != nil {
		return fail(err)
	}
	if ctx.Err() != nil {
		return fail(ctx.Err())
	}
	if err = tx.Commit(); err != nil {
		return fail(err)
	}
	return current, child, token, nil
}

// Revalidate the persisted child and its independent authority before callback
// redemption or settlement. This is not a caller-selectable workflow override.
func nativeProtectRecoveryStored(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, c model.CapacityNativeCommand) error {
	proof := c.ProtectRecovery
	if proof == nil || proof.Schema != capacity.UnredeemedProtectRecoverySchema || capacity.ValidateUnredeemedProtectRecoveryBinding(policy, p, proof.Binding) != nil || !capacity.NativeProcessNonce(proof.RecoveryID) || proof.ChildID != c.CommandID.String() || proof.Generation != c.IntentGeneration || proof.Fence != c.FencingToken || proof.Generation != proof.Binding.ExpectedIntentGeneration+1 || proof.Fence != proof.Binding.ExpectedIntentFencingToken+1 || proof.Workflow.ID != c.WorkflowID || !proof.AuthoredAt.Equal(c.CreatedAt) || c.Phase != "protect" || c.Operation != capacity.EnsureNativePodDrain || c.Sequence != 1 || !c.AdmissionOnly || c.ParentCommandID != "" || c.ParentAttemptID != "" || c.RecoveryDecisionID != "" || c.RecoveryFence != "" || c.ReleaseProtocol != "" || c.AdapterSourceCommit != "" || c.OriginPolicySHA256 != nativeCanonicalArchiveSHA(policy.Spec) || c.OriginPolicySHA256 != nativeCanonicalArchiveSHA(c.OriginPolicy) {
		return ErrCapacityConflict
	}
	wf, sha, err := nativeProtectRecoveryWorkflow(ctx, tx, c.WorkflowID, policy, proof.Binding)
	if err != nil || wf != proof.Workflow || sha != proof.WorkflowChecksum {
		return ErrCapacityMutationAuthorization
	}
	if err = lockNativeBoundOwner(ctx, tx, policy, p, proof.Binding.PodUID); err != nil {
		return err
	}
	if err = guardNativePreRegistrationAbortTx(ctx, tx, proof.Binding.PodUID); err != nil {
		return err
	}
	if err = nativeAbortRecoveryIdentity(ctx, tx, c, proof.Binding.PodUID); err != nil {
		return err
	}
	if err = nativeAbortRecoveryHotIdentity(ctx, tx, c, proof.Binding.PodUID); err != nil {
		return err
	}
	if err = nativeProtectRecoveryOriginals(ctx, tx, policy, p, proof.Binding, &c); err != nil {
		return err
	}
	intent, err := loadCapacityIntent(ctx, tx, c.Namespace, p, false)
	if err != nil {
		return err
	}
	cp, err := nativeProtectRecoveryCheckpoint(ctx, tx, policy, p, intent, proof.Binding)
	if err != nil || capacity.ValidateUnredeemedProtectRecoveryBoot(p, cp, proof.Boot, proof.AuthoredAt) != nil {
		return ErrCapacityConflict
	}
	canonical, phase, err := canonicalNativeCommandRequest(c.Operation, c.Request)
	if err != nil || phase != "protect" || c.RequestSHA256 != nativeArchiveSHA(canonical) || validateNativeCommandRequest(ctx, tx, p, intent, c.Operation, c.Phase, proof.Binding.PodUID, c.Request) != nil {
		return ErrCapacityConflict
	}
	var request model.AdapterEnsureCapacityPodDrainRequest
	if capacity.DecodeNativeCapacity(c.Request, &request) != nil || request.ExpectedPodResourceVersion != proof.Boot.Observation.PodResourceVersion {
		return ErrCapacityConflict
	}
	return nil
}

func (s CapacityStore) nativeProtectRecoverySettlementAuthority(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec) error {
	if s.protectRecovery == nil || !s.AdmissionOnly || !s.ExecutionEnabled {
		return ErrCapacityMutationAuthorization
	}
	var raw []byte
	if tx.QueryRowContext(ctx, `SELECT command_record FROM public.capacity_native_commands WHERE id=$1 FOR UPDATE`, s.protectRecovery.CommandID).Scan(&raw) != nil {
		return ErrCapacityConflict
	}
	var c model.CapacityNativeCommand
	if capacity.DecodeNativeCapacity(json.RawMessage(raw), &c) != nil || c.ProtectRecovery == nil || c.WorkflowID != s.WorkflowID || c.ExecutorID != s.ExecutorID || c.ProtectRecovery.Binding.OperatorID != s.ExecutorPowerOperator {
		return ErrCapacityMutationAuthorization
	}
	return nativeProtectRecoveryStored(ctx, tx, policy, p, c)
}

// Finish exactly this original child. An unredeemed result is terminal and
// gives no further child; a redeemed/unknown result has readback-only recovery.
func (s CapacityStore) SettleUnredeemedProtectRecovery(ctx context.Context, policy model.Manifest, intent model.CapacityIntent, child model.CapacityNativeCommand, readback *model.AdapterCapacityPodTerminationResponse) (bool, error) {
	if child.ProtectRecovery == nil || child.WorkflowID != s.WorkflowID || child.ExecutorID != s.ExecutorID || s.ExecutorPowerOperator != child.ProtectRecovery.Binding.OperatorID {
		return false, ErrCapacityMutationAuthorization
	}
	s.protectRecovery = &child
	refused, err := s.RevokeUnredeemedNativeCommand(ctx, policy, intent, child.CommandID)
	if err != nil || refused {
		return refused, err
	}
	if err = s.MarkNativeCommandUncertain(ctx, child.CommandID); err != nil {
		return false, err
	}
	if readback == nil {
		return false, ErrCapacityConflict
	}
	return false, s.ConfirmNativeCommand(ctx, policy, intent, child.CommandID, *readback)
}
