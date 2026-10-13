package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// This is an oracle over ORIGINAL immutable SQL rows. A second genuine CAS409
// is not a replay, but every intermediate rejection must retain its own result,
// both original acknowledgements and a separately fenced child. No row, failed
// identity or uncertain result may disappear from the permanent four-row budget.
type nativeReleaseChainCensus struct {
	Commands  []nativeReleaseChainCommand  `json:"commands"`
	Results   []nativeReleaseChainResult   `json:"results"`
	Decisions []nativeReleaseChainDecision `json:"decisions"`
}

type nativeReleaseChainCommand struct {
	Identity   json.RawMessage              `json:"identity"`
	Hot        *model.CapacityNativeCommand `json:"hot"`
	Archive    *model.CapacityNativeCommand `json:"archive"`
	ArchiveSHA *string                      `json:"archive_sha256"`
}

type nativeReleaseChainResult struct {
	CommandID             uuid.UUID       `json:"command_id"`
	CommandSequence       int             `json:"command_sequence"`
	AttemptID             uuid.UUID       `json:"attempt_id"`
	Protocol              string          `json:"protocol"`
	Source                string          `json:"adapter_source_commit"`
	ReturnNonceSHA        string          `json:"return_nonce_sha256"`
	Deadline              time.Time       `json:"original_deadline"`
	CommandExpiryJSON     string          `json:"command_expires_at_json"`
	CommandExpirySQL      *time.Time      `json:"command_expires_at_sql"`
	NativeDeadlineMatches *bool           `json:"native_deadline_matches_command"`
	Result                json.RawMessage `json:"adapter_result"`
	ResultSHA             string          `json:"adapter_result_sha256"`
	AdapterACK            *time.Time      `json:"adapter_ack_at"`
	CallerACK             *time.Time      `json:"caller_ack_at"`
}

type nativeReleaseChainDecision struct {
	ID            uuid.UUID `json:"id"`
	ParentID      uuid.UUID `json:"parent_command_id"`
	ParentAttempt uuid.UUID `json:"parent_attempt_id"`
	CommandID     uuid.UUID `json:"command_id"`
	Fence         uuid.UUID `json:"fence"`
	CreatedAt     time.Time `json:"created_at"`
	Record        struct {
		Command         model.CapacityNativeCommand                 `json:"command"`
		ParentResultSHA string                                      `json:"parent_result_sha256"`
		HPA             model.CapacityHPAEnvelopeResponse           `json:"hpa"`
		Inventory       model.AdapterCapacityPodInventoryResponse   `json:"inventory"`
		Witness         model.AdapterCapacityPodTerminationResponse `json:"witness"`
	} `json:"decision_record"`
}

func nativeReleaseChainCanonical(raw []byte) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value any
	if d.Decode(&value) != nil || value == nil || d.Decode(new(any)) != io.EOF {
		return nil, errors.New("complete original chain JSON required")
	}
	return json.Marshal(value)
}

func nativeReleaseChainSHA(raw []byte) string {
	canonical, err := nativeReleaseChainCanonical(raw)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:])
}

func nativeReleaseChainSameJSON(a, b any) bool {
	x, e1 := json.Marshal(a)
	y, e2 := json.Marshal(b)
	x, e3 := nativeReleaseChainCanonical(x)
	y, e4 := nativeReleaseChainCanonical(y)
	return e1 == nil && e2 == nil && e3 == nil && e4 == nil && bytes.Equal(x, y)
}

// JSON retains the original nanosecond context expiry. PostgreSQL's native
// timestamptz column has its own microsecond representation; the exact typed
// equality is collected by PostgreSQL in the SAME original readonly snapshot.
// No tolerance, expiry renewal or guessed client-side rounding is authority.
func nativeReleaseDeadlineExact(r nativeReleaseChainResult, c *model.CapacityNativeCommand) bool {
	original, err := time.Parse(time.RFC3339Nano, r.CommandExpiryJSON)
	return err == nil && original.Equal(c.ExpiresAt) && r.CommandExpirySQL != nil && !r.CommandExpirySQL.IsZero() && r.NativeDeadlineMatches != nil && *r.NativeDeadlineMatches && r.Deadline.Equal(*r.CommandExpirySQL) && r.CommandSequence == c.Sequence
}

func nativeReleaseChainDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

func nativeReleaseIncidentEdgesClosed(census nativeReleaseChainCensus) bool {
	owned := map[uuid.UUID]bool{}
	for _, row := range census.Commands {
		var identity struct {
			ID uuid.UUID `json:"id"`
		}
		if json.Unmarshal(row.Identity, &identity) != nil || identity.ID == uuid.Nil || owned[identity.ID] {
			return false
		}
		owned[identity.ID] = true
	}
	for _, d := range census.Decisions {
		if !owned[d.CommandID] || !owned[d.ParentID] {
			return false
		}
	}
	return true
}

// The checkpoint has already passed the unchanged native release snapshot
// oracle. Read the three complete relations in one read-only snapshot before
// validating the chain, including archived commands and every original ACK.
func nativeReleaseReadChainCensus(t *testing.T, ctx context.Context, db *sql.DB, realm, subject string) nativeReleaseChainCensus {
	t.Helper()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		t.Fatal("original release chain snapshot unavailable", err)
	}
	defer tx.Rollback()
	var raw []byte
	err = tx.QueryRowContext(ctx, `WITH owned AS (
	 SELECT * FROM public.capacity_native_command_identities
	 WHERE namespace=$1 AND subject_uid=$2 AND operation=$3 AND phase='release'
	)
	SELECT json_build_object(
	 'commands',COALESCE((SELECT json_agg(json_build_object('identity',row_to_json(i),'hot',c.command_record,'archive',a.command_record,'archive_sha256',a.record_sha256) ORDER BY i.sequence) FROM owned i LEFT JOIN public.capacity_native_commands c ON c.id=i.id LEFT JOIN public.capacity_native_command_archive a ON a.id=i.id),'[]'::json),
	 'results',COALESCE((SELECT json_agg(row_to_json(projected) ORDER BY projected.command_sequence) FROM (
	  SELECT r.*,i.sequence AS command_sequence,
	   COALESCE(c.command_record,a.command_record)->>'expires_at' AS command_expires_at_json,
	   (COALESCE(c.command_record,a.command_record)->>'expires_at')::timestamptz AS command_expires_at_sql,
	   r.original_deadline=(COALESCE(c.command_record,a.command_record)->>'expires_at')::timestamptz AS native_deadline_matches_command
	  FROM owned i JOIN public.capacity_native_release_results r ON r.command_id=i.id
	  LEFT JOIN public.capacity_native_commands c ON c.id=i.id
	  LEFT JOIN public.capacity_native_command_archive a ON a.id=i.id
	 ) projected),'[]'::json),
	 'decisions',COALESCE((SELECT json_agg(row_to_json(d) ORDER BY d.created_at,d.id) FROM public.capacity_native_release_recovery_decisions d WHERE EXISTS(SELECT 1 FROM owned i WHERE i.id=d.command_id OR i.id=d.parent_command_id)),'[]'::json)
	)`, realm, subject, capacity.DestroyNativePodProtection).Scan(&raw)
	var census nativeReleaseChainCensus
	if err != nil || len(raw) > 8<<20 {
		t.Fatal("bounded original release chain query unavailable", err)
	}
	// Retain the ORIGINAL returned bytes before every decode, transaction and
	// qualification guard, so a later fatal cannot discard this causal census.
	t.Logf("original complete release recovery chain sha256=%x census=%s", sha256.Sum256(raw), raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err != nil || len(raw) > 8<<20 || decoder.Decode(&census) != nil || decoder.Decode(new(any)) != io.EOF || tx.Commit() != nil {
		t.Fatal("complete original release chain snapshot did not return", err)
	}
	// Hashes, private-return nonce hashes and source records only. No plaintext
	// command permission or callback nonce enters durable rows or this artifact.
	return census
}

func validateNativeReleaseChain(census nativeReleaseChainCensus, realm, subject, source string, policy model.Manifest, p model.CapacityPolicySpec, checkpoint model.CapacityNativePodCheckpoint) error {
	refuse := errors.New("original release chain identity, ACK or recovery frame differs")
	if !nativeReleaseIncidentEdgesClosed(census) || len(census.Commands) < 2 || len(census.Commands) > 4 || p.AssessmentBinding == nil || p.HPAExecutionBinding == nil || p.HPAExecutionBinding.ReleaseRecovery == nil || p.HPAExecutionBinding.ReleaseRecovery.Protocol != capacity.NativeReleaseResultProtocol || p.HPAExecutionBinding.ReleaseRecovery.AdapterSourceCommit != source || checkpoint.PodUID != subject {
		return refuse
	}
	results := map[uuid.UUID]nativeReleaseChainResult{}
	nonces := map[string]bool{}
	for _, r := range census.Results {
		if _, seen := results[r.CommandID]; seen || r.CommandID == uuid.Nil || !nativeReleaseChainDigest(r.ReturnNonceSHA) || nonces[r.ReturnNonceSHA] {
			return refuse
		}
		results[r.CommandID], nonces[r.ReturnNonceSHA] = r, true
	}
	decisions := map[uuid.UUID]nativeReleaseChainDecision{}
	fences, decisionIDs := map[uuid.UUID]bool{}, map[uuid.UUID]bool{}
	for _, d := range census.Decisions {
		if _, seen := decisions[d.CommandID]; seen || d.ID == uuid.Nil || d.Fence == uuid.Nil || fences[d.Fence] || decisionIDs[d.ID] {
			return refuse
		}
		decisions[d.CommandID], fences[d.Fence], decisionIDs[d.ID] = d, true, true
	}
	ids, attempts, tokens := map[uuid.UUID]bool{}, map[uuid.UUID]bool{}, map[string]bool{}
	var base, parent *model.CapacityNativeCommand
	confirmed, rejected, redeemed := 0, 0, 0
	for index, row := range census.Commands {
		if (row.Hot == nil) == (row.Archive == nil) {
			return refuse
		}
		c := row.Hot
		if c == nil {
			c = row.Archive
			encoded, _ := json.Marshal(c)
			if row.ArchiveSHA == nil || *row.ArchiveSHA != nativeReleaseChainSHA(encoded) {
				return refuse
			}
		} else if row.ArchiveSHA != nil {
			return refuse
		}
		if c.CommandID == uuid.Nil || ids[c.CommandID] || !nativeReleaseChainDigest(c.AuthorityTokenSHA256) || tokens[c.AuthorityTokenSHA256] || c.Sequence != index+1 || c.PolicyID != policy.ID || c.PolicyChecksum != policy.Checksum || c.Namespace != realm || c.Environment != p.Environment || c.Domain != p.Domain || c.Dimension != p.Dimension || c.WorkflowID == uuid.Nil || c.IntentGeneration < 1 || c.FencingToken < 1 || c.LeaseOwner == "" || c.ExecutorID == "" || c.OriginPolicySHA256 != nativeReleaseChainSHA(c.OriginPolicy) || !nativeReleaseChainSameJSON(c.OriginPolicy, policy.Spec) || c.Operation != capacity.DestroyNativePodProtection || c.Phase != "release" || c.Adapter != p.AssessmentBinding.Snapshot.Adapter || c.AdapterPrincipalID != p.HPAExecutionBinding.AdapterPrincipalID || c.ReleaseProtocol != capacity.NativeReleaseResultProtocol || c.AdapterSourceCommit != source || c.CreatedAt.IsZero() || c.UpdatedAt.Before(c.CreatedAt) || !c.ExpiresAt.After(c.CreatedAt) || c.RequestSHA256 != nativeReleaseChainSHA(c.Request) {
			return refuse
		}
		ids[c.CommandID], tokens[c.AuthorityTokenSHA256] = true, true
		identity := map[string]any{"id": c.CommandID, "namespace": c.Namespace, "environment": c.Environment, "domain": c.Domain, "dimension": c.Dimension, "generation": c.IntentGeneration, "operation": c.Operation, "subject_uid": subject, "phase": c.Phase, "sequence": c.Sequence, "authority_token_sha256": c.AuthorityTokenSHA256, "request_sha256": c.RequestSHA256}
		if !nativeReleaseChainSameJSON(row.Identity, identity) {
			return refuse
		}
		var request model.AdapterDestroyCapacityPodDrainProtectionRequest
		if capacity.DecodeNativeCapacity(c.Request, &request) != nil || request.ExpectedPodUID != subject || request.ExpectedContainerID != checkpoint.ContainerID || !request.ExpectedContainerStartedAt.Equal(checkpoint.ContainerStartedAt) || request.ExpectedRestartCount != checkpoint.RestartCount {
			return refuse
		}
		r, hasResult := results[c.CommandID]
		d, hasDecision := decisions[c.CommandID]
		if c.State == "refused_no_redemption" {
			if base != nil || c.AttemptID != uuid.Nil || c.RedeemedBy != "" || hasResult || hasDecision || c.ParentCommandID != "" || c.ParentAttemptID != "" || c.RecoveryDecisionID != "" || c.RecoveryFence != "" || (len(c.NativeReadback) != 0 && !bytes.Equal(bytes.TrimSpace(c.NativeReadback), []byte("null"))) || len(c.OriginalResult) != 0 || c.OriginalResultSHA256 != "" || c.CallerReturnObservedAt != nil {
				return refuse
			}
			continue
		}
		if c.AttemptID == uuid.Nil || attempts[c.AttemptID] || c.RedeemedBy != p.HPAExecutionBinding.AdapterPrincipalID || !hasResult || r.AttemptID != c.AttemptID || r.Protocol != c.ReleaseProtocol || r.Source != source || !nativeReleaseDeadlineExact(r, c) || r.AdapterACK == nil || r.AdapterACK.Before(c.CreatedAt) || !r.AdapterACK.Before(c.ExpiresAt) || r.ResultSHA != nativeReleaseChainSHA(r.Result) {
			return refuse
		}
		attempts[c.AttemptID] = true
		redeemed++
		var original model.CapacityNativeReleaseResult
		if capacity.DecodeNativeCapacity(r.Result, &original) != nil || original.Protocol != c.ReleaseProtocol || original.CommandID != c.CommandID || original.AttemptID != c.AttemptID || original.IntegrationInstanceID != c.Adapter.IntegrationInstanceID || original.IntegrationTypeID != c.Adapter.IntegrationTypeID || original.Capability != c.Operation || original.RequestSHA256 != c.RequestSHA256 || original.AdapterSourceCommit != source || original.ReturnNonce != "" || !nativeReleaseChainDigest(original.OriginalResponseSHA256) || !original.OneSend || !original.DoReturned || !original.ReadReturned || !original.CloseReturned {
			return refuse
		}
		if base == nil {
			if hasDecision || c.ParentCommandID != "" || c.ParentAttemptID != "" || c.RecoveryDecisionID != "" || c.RecoveryFence != "" {
				return refuse
			}
			base = c
		} else {
			if parent == nil || parent.State != "rejected_no_effect" || parent.CallerReturnObservedAt == nil || !hasDecision || c.ParentCommandID != parent.CommandID.String() || c.ParentAttemptID != parent.AttemptID.String() || c.RecoveryDecisionID != d.ID.String() || c.RecoveryFence != d.Fence.String() || d.ParentID != parent.CommandID || d.ParentAttempt != parent.AttemptID || !d.CreatedAt.Equal(c.CreatedAt) || c.CreatedAt.Before(*parent.CallerReturnObservedAt) || d.Record.ParentResultSHA != parent.OriginalResultSHA256 || !c.ExpiresAt.Equal(base.ExpiresAt) || c.WorkflowID != base.WorkflowID || c.IntentGeneration != base.IntentGeneration || c.FencingToken != base.FencingToken || c.LeaseOwner != base.LeaseOwner || c.ExecutorID != base.ExecutorID || c.OriginPolicySHA256 != base.OriginPolicySHA256 || !nativeReleaseChainSameJSON(c.OriginPolicy, base.OriginPolicy) {
				return refuse
			}
			issued := *c
			issued.State, issued.AttemptID, issued.RedeemedBy, issued.UpdatedAt = "issued", uuid.Nil, "", c.CreatedAt
			issued.NativeReadback, issued.OriginalResult, issued.OriginalResultSHA256, issued.CallerReturnObservedAt = nil, nil, "", nil
			if !nativeReleaseChainSameJSON(issued, d.Record.Command) || d.Record.Witness.Operation != capacity.ObserveNativePodTermination || d.Record.Witness.Status != "observed" || capacity.NativePodWitness(p, checkpoint, d.Record.Witness.Observation, c.CreatedAt) != nil || capacity.NativePodInventory(p, d.Record.Inventory, c.CreatedAt) != nil || d.Record.Witness.Observation.PodResourceVersion != request.ExpectedPodResourceVersion {
				return refuse
			}
			snapshot, err := capacity.BoundHPASnapshot(p, d.Record.HPA, c.CreatedAt)
			if err != nil || snapshot.ResourceUID != p.AssessmentBinding.Snapshot.HPAUID || snapshot.WorkloadUID != checkpoint.WorkloadUID || snapshot.Units < p.Floor || snapshot.Units > p.Ceiling {
				return refuse
			}
			found := false
			for _, pod := range d.Record.Inventory.Pods {
				if pod.PodUID == subject {
					found = capacity.NativePodMatchesCheckpoint(p, checkpoint, pod, c.CreatedAt) == nil && pod.PodResourceVersion == request.ExpectedPodResourceVersion
				}
			}
			if !found {
				return refuse
			}
		}
		switch c.State {
		case "rejected_no_effect":
			if original.OriginalStatus != 409 || original.Outcome != "rejected_no_effect" || r.CallerACK == nil || c.CallerReturnObservedAt == nil || !r.CallerACK.Equal(*c.CallerReturnObservedAt) || r.CallerACK.Before(*r.AdapterACK) || !r.CallerACK.Before(c.ExpiresAt) || c.OriginalResultSHA256 != r.ResultSHA || !nativeReleaseChainSameJSON(c.OriginalResult, r.Result) || index == len(census.Commands)-1 {
				return refuse
			}
			rejected++
		case "confirmed":
			if original.OriginalStatus != 200 || original.Outcome != "applied" || index != len(census.Commands)-1 || len(c.NativeReadback) == 0 {
				return refuse
			}
			confirmed++
		default:
			return refuse
		}
		parent = c
	}
	if rejected < 1 || confirmed != 1 || len(census.Results) != redeemed || len(census.Decisions) != redeemed-1 {
		return refuse
	}
	return nil
}

// Closed protocol rows exercise the same whole-chain oracle used on the remote
// native relations above. They grant no native/provider authority themselves.
func nativeReleaseChainProtocolFixture(t *testing.T, count int) (nativeReleaseChainCensus, model.Manifest, model.CapacityPolicySpec, model.CapacityNativePodCheckpoint, string) {
	t.Helper()
	now := time.Date(2026, 10, 12, 20, 0, 0, 0, time.UTC)
	realm, subject, source := "original-chain", uuid.NewString(), strings.Repeat("a", 40)
	adapter := model.CapacityObservationAdapterBinding{IntegrationInstanceID: uuid.NewString(), InstanceChecksum: strings.Repeat("b", 64), IntegrationTypeID: uuid.NewString(), TypeChecksum: strings.Repeat("c", 64)}
	hpaUID, workloadUID := uuid.NewString(), uuid.NewString()
	p := model.CapacityPolicySpec{Environment: "production", Domain: "native-chain", Dimension: capacity.ReservedPodEnvelopeUnit, TargetIdentity: "fixture/original-chain", Owner: "original-owner", Floor: 2, Ceiling: 4, MaxEvidenceAgeSeconds: 180, ExecutionEnabled: true, Workflow: model.ManifestSelector{Namespace: realm, Name: "execute"}, Profiles: []model.CapacityProfile{{Name: "reserved"}}, Signals: []model.CapacitySignalRule{{Name: "pressure"}}}
	p.AssessmentBinding = &model.CapacityBoundAssessmentBinding{Snapshot: model.CapacityHPAMinimumBinding{Mode: capacity.HPAMinimumSnapshotMode, Unit: capacity.ReservedPodEnvelopeUnit, Adapter: adapter, Namespace: realm, HPAName: "api", HPAUID: hpaUID, WorkloadName: "api", WorkloadUID: workloadUID, Owner: p.Owner, Profile: "reserved", ProtectedFloor: p.Floor, MaximumReplicas: p.Ceiling}, Signals: []model.CapacityMetricSignalBinding{{Name: "pressure", Adapter: adapter, BindingName: "pressure", BindingSHA256: strings.Repeat("d", 64)}}}
	p.HPAExecutionBinding = &model.CapacityHPAExecutionBinding{AdapterPrincipalID: "native-adapter", Mode: capacity.HPALifetimeExecutionMode, PodTerminationBinding: "api-native", ContainerName: "api", ImageDigest: "sha256:" + strings.Repeat("e", 64), Lanes: []string{"listener"}, ProjectionDirectory: "/native", AdmissionMode: "process_v2", AdmissionPort: 8080, AdmissionWorkflow: model.ManifestSelector{Namespace: realm, Name: "admit"}, BirthGuardBinding: "birth", BirthGuardSHA256: strings.Repeat("f", 64), ReleaseRecovery: &model.CapacityNativeReleaseRecoveryBinding{Protocol: capacity.NativeReleaseResultProtocol, AdapterSourceCommit: source}}
	policyRaw, _ := json.Marshal(p)
	policy := model.Manifest{ID: uuid.New(), Checksum: nativeReleaseChainSHA(policyRaw), Spec: policyRaw}
	start, finish, deleted := now.Add(-time.Minute), now.Add(-time.Second), now.Add(-2*time.Second)
	challenge := model.NativePodTerminationChallenge{SchemaVersion: 2, Namespace: realm, PodName: "api-original", PodUID: subject, WorkloadUID: workloadUID, ContainerName: "api", ImageDigest: p.HPAExecutionBinding.ImageDigest, IntentGeneration: 1, DrainNonce: uuid.NewString(), IssuedAt: now.Add(-3 * time.Second), LaneRosterSHA256: capacity.NativeRosterDigest(p.HPAExecutionBinding.Lanes), ProcessNonce: uuid.NewString()}
	challengeRaw, _ := json.Marshal(challenge)
	checkpoint := model.CapacityNativePodCheckpoint{Namespace: realm, PodName: challenge.PodName, PodUID: subject, WorkloadUID: workloadUID, ContainerName: "api", ContainerID: "containerd://original", ContainerStartedAt: start, ImageDigest: challenge.ImageDigest, IntentGeneration: 1, DrainNonce: challenge.DrainNonce, Challenge: challengeRaw, ProcessNonce: challenge.ProcessNonce, State: "released"}
	workflowID, executor, lease := uuid.New(), uuid.NewString(), uuid.NewString()
	census := nativeReleaseChainCensus{}
	for i := 0; i < count; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		rv := fmt.Sprint(100 + i)
		requestRaw, _ := json.Marshal(model.AdapterDestroyCapacityPodDrainProtectionRequest{AdapterObserveCapacityPodTerminationRequest: model.AdapterObserveCapacityPodTerminationRequest{BindingName: "api-native", PodName: checkpoint.PodName, ExpectedPodUID: subject, ExpectedContainerID: checkpoint.ContainerID, ExpectedContainerStartedAt: start, Challenge: challenge}, ExpectedPodResourceVersion: rv})
		c := &model.CapacityNativeCommand{CommandID: uuid.New(), PolicyID: policy.ID, PolicyChecksum: policy.Checksum, WorkflowID: workflowID, Namespace: realm, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, IntentGeneration: 2, FencingToken: 4, LeaseOwner: lease, ExecutorID: executor, Adapter: adapter, AdapterPrincipalID: "native-adapter", Operation: capacity.DestroyNativePodProtection, Phase: "release", Sequence: i + 1, Request: requestRaw, RequestSHA256: nativeReleaseChainSHA(requestRaw), AuthorityTokenSHA256: fmt.Sprintf("%064x", i+1), AttemptID: uuid.New(), RedeemedBy: "native-adapter", CreatedAt: at, ExpiresAt: now.Add(90 * time.Second), UpdatedAt: at.Add(2 * time.Millisecond), OriginPolicy: policyRaw, OriginPolicySHA256: nativeReleaseChainSHA(policyRaw), ReleaseProtocol: capacity.NativeReleaseResultProtocol, AdapterSourceCommit: source}
		if i > 0 {
			parent := census.Commands[i-1].Hot
			c.ParentCommandID, c.ParentAttemptID, c.RecoveryDecisionID, c.RecoveryFence = parent.CommandID.String(), parent.AttemptID.String(), uuid.NewString(), uuid.NewString()
		}
		ack := at.Add(time.Millisecond)
		result := model.CapacityNativeReleaseResult{Protocol: c.ReleaseProtocol, CommandID: c.CommandID, AttemptID: c.AttemptID, IntegrationInstanceID: adapter.IntegrationInstanceID, IntegrationTypeID: adapter.IntegrationTypeID, Capability: c.Operation, RequestSHA256: c.RequestSHA256, AdapterSourceCommit: source, OriginalResponseSHA256: strings.Repeat("9", 64), OriginalStatus: 409, Outcome: "rejected_no_effect", OneSend: true, DoReturned: true, ReadReturned: true, CloseReturned: true}
		if i == count-1 {
			c.State = "confirmed"
			c.NativeReadback = json.RawMessage(`{"protocol_fixture_only":true}`)
			result.OriginalStatus, result.Outcome = 200, "applied"
		} else {
			c.State = "rejected_no_effect"
			caller := at.Add(2 * time.Millisecond)
			c.CallerReturnObservedAt = &caller
		}
		resultRaw, _ := json.Marshal(result)
		if c.State == "rejected_no_effect" {
			c.OriginalResult, c.OriginalResultSHA256 = resultRaw, nativeReleaseChainSHA(resultRaw)
		}
		typedExpiry := c.ExpiresAt
		nativeMatch := true
		r := nativeReleaseChainResult{CommandExpiryJSON: c.ExpiresAt.Format(time.RFC3339Nano), CommandExpirySQL: &typedExpiry, NativeDeadlineMatches: &nativeMatch, CommandSequence: c.Sequence, CommandID: c.CommandID, AttemptID: c.AttemptID, Protocol: c.ReleaseProtocol, Source: source, ReturnNonceSHA: fmt.Sprintf("%064x", i+20), Deadline: c.ExpiresAt, Result: resultRaw, ResultSHA: nativeReleaseChainSHA(resultRaw), AdapterACK: &ack, CallerACK: c.CallerReturnObservedAt}
		identity, _ := json.Marshal(map[string]any{"id": c.CommandID, "namespace": realm, "environment": c.Environment, "domain": c.Domain, "dimension": c.Dimension, "generation": c.IntentGeneration, "operation": c.Operation, "subject_uid": subject, "phase": c.Phase, "sequence": c.Sequence, "authority_token_sha256": c.AuthorityTokenSHA256, "request_sha256": c.RequestSHA256})
		census.Commands = append(census.Commands, nativeReleaseChainCommand{Identity: identity, Hot: c})
		census.Results = append(census.Results, r)
		if i > 0 {
			parent := census.Commands[i-1].Hot
			d := nativeReleaseChainDecision{ID: uuid.MustParse(c.RecoveryDecisionID), ParentID: parent.CommandID, ParentAttempt: parent.AttemptID, CommandID: c.CommandID, Fence: uuid.MustParse(c.RecoveryFence), CreatedAt: c.CreatedAt}
			d.Record.Command = *c
			d.Record.Command.State, d.Record.Command.AttemptID, d.Record.Command.RedeemedBy, d.Record.Command.UpdatedAt = "issued", uuid.Nil, "", c.CreatedAt
			d.Record.Command.NativeReadback, d.Record.Command.OriginalResult, d.Record.Command.OriginalResultSHA256, d.Record.Command.CallerReturnObservedAt = nil, nil, "", nil
			d.Record.ParentResultSHA = parent.OriginalResultSHA256
			observed := at.Add(-time.Millisecond)
			d.Record.HPA = model.CapacityHPAEnvelopeResponse{Operation: capacity.ObserveHPAEnvelope, Status: "observed", Observation: model.CapacityHPAEnvelopeObservation{Namespace: realm, HPAName: "api", HPAUID: hpaUID, ResourceVersion: "original-hpa", WorkloadName: "api", WorkloadUID: workloadUID, WorkloadResourceVersion: "original-workload", Owner: p.Owner, EnvelopeGeneration: 2, IdempotencyKey: "original-idempotency", MinReplicas: 2, MaxReplicas: 4, ProtectedFloor: 2, TrackedProtectedFloor: 2, MaximumReplicas: 4, MatchedOwner: true, BoundsWithinScope: true, TrackingMatchesScope: true, BoundsMatchTracking: true, DiagnosticOnly: true, ObservedAt: observed.Format(time.RFC3339Nano)}}
			code, signal := int32(0), int32(0)
			o := model.NativeTerminationObservation{BindingName: "api-native", Namespace: realm, PodName: checkpoint.PodName, PodUID: subject, PodResourceVersion: rv, WorkloadUID: workloadUID, ContainerName: "api", ContainerID: checkpoint.ContainerID, ImageDigest: challenge.ImageDigest, ImageID: "fixture@" + challenge.ImageDigest, ContainerState: "terminated", State: "terminated", ExitCode: &code, Signal: &signal, StartedAt: &start, FinishedAt: &finish, DeletionRequestedAt: &deleted, Protected: true, ObservedAt: observed, ReceiptSHA256: strings.Repeat("8", 64), Receipt: &model.NativePodTerminationReceipt{NativePodTerminationChallenge: challenge, JoinedAt: finish, Lanes: map[string]string{"listener": "done"}, RootAdmission: "previously_opened"}}
			d.Record.Witness = model.AdapterCapacityPodTerminationResponse{Operation: capacity.ObserveNativePodTermination, Status: "observed", Observation: o}
			d.Record.Inventory = model.AdapterCapacityPodInventoryResponse{Operation: capacity.ObserveNativePodInventory, Status: "observed", BindingName: "api-native", Namespace: realm, WorkloadUID: workloadUID, WorkloadResourceVersion: "original-workload", ListResourceVersion: "original-list", Complete: true, ObservedAt: observed, Pods: []model.NativeTerminationObservation{o}}
			census.Decisions = append(census.Decisions, d)
		}
	}
	return census, policy, p, checkpoint, source
}

func TestCapacityNativeReleaseRecoveryCompleteChainOracle(t *testing.T) {
	for _, mode := range []string{"two-identities", "three-identities", "four-identities", "archived-four-identities", "fifth-identity-budget", "duplicate-token", "duplicate-attempt", "duplicate-identity", "sequence-gap", "missing-parent-caller-ack", "missing-adapter-ack", "missing-result", "duplicate-result", "extra-result", "missing-decision", "extra-decision", "shared-fence", "wrong-parent-attempt", "wrong-parent-result", "renewed-deadline", "late-caller-return", "changed-owner", "changed-source", "changed-policy", "witness-inventory-race", "foreign-witness-lifetime", "foreign-inventory-lifetime", "stale-frame", "uncertain-parent", "relabelled-original409", "unjoined-original-close", "changed-permanent-identity", "changed-archive-hash", "missing-native-deadline", "false-native-deadline", "foreign-deadline-column", "foreign-json-deadline", "foreign-native-command-sequence", "missing-native-sql-deadline", "foreign-sql-expiry-projection"} {
		t.Run(mode, func(t *testing.T) {
			count := 3
			switch mode {
			case "two-identities":
				count = 2
			case "four-identities", "archived-four-identities":
				count = 4
			case "fifth-identity-budget":
				count = 5
			}
			c, policy, p, checkpoint, source := nativeReleaseChainProtocolFixture(t, count)
			valid := mode == "two-identities" || mode == "three-identities" || mode == "four-identities" || mode == "archived-four-identities"
			last := c.Commands[len(c.Commands)-1].Hot
			switch mode {
			case "missing-native-sql-deadline":
				c.Results[0].CommandExpirySQL = nil
			case "foreign-sql-expiry-projection":
				changed := c.Results[0].CommandExpirySQL.Add(time.Microsecond)
				c.Results[0].CommandExpirySQL = &changed
			case "missing-native-deadline":
				c.Results[0].NativeDeadlineMatches = nil
			case "false-native-deadline":
				no := false
				c.Results[0].NativeDeadlineMatches = &no
			case "foreign-deadline-column":
				c.Results[0].Deadline = c.Results[0].Deadline.Add(time.Microsecond)
			case "foreign-json-deadline":
				c.Results[0].CommandExpiryJSON = c.Commands[0].Hot.ExpiresAt.Add(time.Nanosecond).Format(time.RFC3339Nano)
			case "foreign-native-command-sequence":
				c.Results[0].CommandSequence++
			case "duplicate-token":
				last.AuthorityTokenSHA256 = c.Commands[0].Hot.AuthorityTokenSHA256
			case "duplicate-attempt":
				last.AttemptID = c.Commands[0].Hot.AttemptID
			case "duplicate-identity":
				last.CommandID = c.Commands[0].Hot.CommandID
			case "sequence-gap":
				last.Sequence++
			case "missing-parent-caller-ack":
				c.Results[0].CallerACK = nil
			case "missing-adapter-ack":
				c.Results[0].AdapterACK = nil
			case "missing-result":
				c.Results = c.Results[1:]
			case "duplicate-result":
				c.Results = append(c.Results, c.Results[0])
			case "extra-result":
				r := c.Results[0]
				r.CommandID = uuid.New()
				r.ReturnNonceSHA = strings.Repeat("7", 64)
				c.Results = append(c.Results, r)
			case "missing-decision":
				c.Decisions = c.Decisions[1:]
			case "extra-decision":
				d := c.Decisions[0]
				d.ID, d.CommandID, d.Fence = uuid.New(), uuid.New(), uuid.New()
				c.Decisions = append(c.Decisions, d)
			case "shared-fence":
				c.Decisions[1].Fence = c.Decisions[0].Fence
			case "wrong-parent-attempt":
				c.Decisions[0].ParentAttempt = uuid.New()
			case "wrong-parent-result":
				c.Decisions[0].Record.ParentResultSHA = strings.Repeat("6", 64)
			case "renewed-deadline":
				last.ExpiresAt = last.ExpiresAt.Add(time.Minute)
				r := &c.Results[len(c.Results)-1]
				r.Deadline = last.ExpiresAt
				r.CommandExpiryJSON = last.ExpiresAt.Format(time.RFC3339Nano)
				r.CommandExpirySQL = &r.Deadline
				matches := true
				r.NativeDeadlineMatches = &matches
				c.Decisions[len(c.Decisions)-1].Record.Command.ExpiresAt = last.ExpiresAt
				if !nativeReleaseDeadlineExact(*r, last) {
					t.Fatal("renewal fixture must preserve exact native representation before the permanent parent deadline guard")
				}
			case "late-caller-return":
				at := c.Commands[0].Hot.ExpiresAt
				c.Commands[0].Hot.CallerReturnObservedAt = &at
				c.Results[0].CallerACK = &at
			case "changed-owner":
				last.LeaseOwner = "replacement-owner"
			case "changed-source":
				last.AdapterSourceCommit = strings.Repeat("b", 40)
			case "changed-policy":
				last.PolicyChecksum = strings.Repeat("c", 64)
			case "witness-inventory-race":
				c.Decisions[0].Record.Inventory.Pods[0].PodResourceVersion = "replacement-rv"
			case "foreign-witness-lifetime":
				c.Decisions[0].Record.Witness.Observation.PodUID = uuid.NewString()
			case "foreign-inventory-lifetime":
				c.Decisions[0].Record.Inventory.Pods[0].ContainerID = "containerd://replacement"
			case "stale-frame":
				c.Decisions[0].Record.Inventory.ObservedAt = c.Decisions[0].CreatedAt.Add(-time.Hour)
			case "uncertain-parent":
				c.Commands[0].Hot.State = "uncertain"
			case "relabelled-original409", "unjoined-original-close":
				var r model.CapacityNativeReleaseResult
				_ = json.Unmarshal(c.Results[0].Result, &r)
				if mode == "relabelled-original409" {
					r.OriginalStatus, r.Outcome = 200, "applied"
				} else {
					r.CloseReturned = false
				}
				raw, _ := json.Marshal(r)
				c.Results[0].Result, c.Results[0].ResultSHA = raw, nativeReleaseChainSHA(raw)
				c.Commands[0].Hot.OriginalResult, c.Commands[0].Hot.OriginalResultSHA256 = raw, nativeReleaseChainSHA(raw)
				c.Decisions[0].Record.ParentResultSHA = nativeReleaseChainSHA(raw)
			case "changed-permanent-identity":
				c.Commands[0].Identity = json.RawMessage(`{"id":"foreign"}`)
			case "archived-four-identities", "changed-archive-hash":
				for i := range c.Commands {
					r := &c.Commands[i]
					raw, _ := json.Marshal(r.Hot)
					sha := nativeReleaseChainSHA(raw)
					r.Archive, r.Hot, r.ArchiveSHA = r.Hot, nil, &sha
				}
				if mode == "changed-archive-hash" {
					bad := strings.Repeat("1", 64)
					c.Commands[0].ArchiveSHA = &bad
				}
			}
			if err := validateNativeReleaseChain(c, checkpoint.Namespace, checkpoint.PodUID, source, policy, p, checkpoint); (err == nil) != valid {
				t.Fatal("complete chain oracle changed original authority/result denominator", mode, err)
			}
		})
	}
}

// The actual production-migrated remote PostgreSQL relation must retain BOTH
// directions of an incident decision, even when its other endpoint belongs to
// another scope. These deliberately incomplete rows are diagnostic negatives;
// they never create a token, send a native operation or qualify a release.
func TestCapacityNativeReleaseRecoveryIncidentDecisionSQLPostgres(t *testing.T) {
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_CAPACITY_NATIVE_KIND") == "true" {
			t.Fatal("actual PostgreSQL incident-edge corpus required")
		}
		t.Skip("remote PostgreSQL original incident-edge census")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal("original PostgreSQL unavailable", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	realm, subject := "original-incident-"+uuid.NewString(), uuid.NewString()
	own, incoming, outgoing := uuid.New(), uuid.New(), uuid.New()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("isolated incident fixture transaction unavailable", err)
	}
	defer tx.Rollback()
	for i, id := range []uuid.UUID{own, incoming, outgoing} {
		namespace, target := realm, subject
		if i > 0 {
			namespace, target = realm+"-foreign", uuid.NewString()
		}
		sha := fmt.Sprintf("%x", sha256.Sum256([]byte(id.String())))
		if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_command_identities(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,authority_token_sha256,request_sha256) VALUES($1,$2,'production','incident-fixture',$3,1,$4,$5,'release',1,$6,$6)`, id, namespace, capacity.ReservedPodEnvelopeUnit, capacity.DestroyNativePodProtection, target, sha); err != nil {
			t.Fatal("isolated permanent incident identity unavailable", err)
		}
	}
	if tx.Commit() != nil {
		t.Fatal("original incident identities did not commit")
	}
	t.Run("only-owned-relations-before-foreign-edges", func(t *testing.T) {
		c := nativeReleaseReadChainCensus(t, ctx, db, realm, subject)
		if len(c.Commands) != 1 || len(c.Results) != 0 || len(c.Decisions) != 0 || !nativeReleaseIncidentEdgesClosed(c) {
			t.Fatal("foreign identities entered fixed subject census")
		}
	})
	t.Run("both-directed-incident-decisions-retained", func(t *testing.T) {
		decisionIDs := map[uuid.UUID]bool{}
		for index, pair := range [][2]uuid.UUID{{incoming, own}, {own, outgoing}, {outgoing, incoming}} {
			id := uuid.New()
			if index < 2 {
				decisionIDs[id] = true
			}
			if _, err := db.ExecContext(ctx, `INSERT INTO public.capacity_native_release_recovery_decisions(id,parent_command_id,parent_attempt_id,command_id,fence,decision_record) VALUES($1,$2,$3,$4,$5,'{}'::jsonb)`, id, pair[0], uuid.New(), pair[1], uuid.New()); err != nil {
				t.Fatal("original immutable incident decision unavailable", err)
			}
		}
		c := nativeReleaseReadChainCensus(t, ctx, db, realm, subject)
		if len(c.Commands) != 1 || len(c.Results) != 0 || len(c.Decisions) != 2 || nativeReleaseIncidentEdgesClosed(c) {
			t.Fatal("incident decision omitted or duplicated by native SQL")
		}
		for _, d := range c.Decisions {
			if !decisionIDs[d.ID] {
				t.Fatal("foreign unrelated decision entered census")
			}
			delete(decisionIDs, d.ID)
		}
		if len(decisionIDs) != 0 {
			t.Fatal("either original incident direction disappeared")
		}
	})
}

// These complete declared protocol chains are stored in the actual migrated
// remote PostgreSQL relations. They qualify only the native timestamp/type and
// collector/oracle boundary; they redeem no token and send no native request.
// The original KinD cases remain the authority for actual release effects.
func TestCapacityNativeReleaseRecoveryDeadlineSQLPostgres(t *testing.T) {
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_CAPACITY_NATIVE_KIND") == "true" {
			t.Fatal("actual PostgreSQL deadline corpus required")
		}
		t.Skip("remote PostgreSQL original typed deadline census")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal("original PostgreSQL unavailable", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for _, tc := range []struct {
		name, expiry    string
		archived, valid bool
	}{
		{"exact-microseconds", "2026-10-12T20:01:30.123456Z", false, true},
		{"rounded-down-original-nanoseconds", "2026-10-12T20:01:30.123456099Z", false, true},
		{"rounded-up-original-nanoseconds", "2026-10-12T20:01:30.123456958Z", false, true},
		{"rounded-carry-to-next-second", "2026-10-12T20:01:30.999999958Z", false, true},
		{"archived-rounded-original-nanoseconds", "2026-10-12T20:01:30.123456958Z", true, true},
		{"mismatched-native-column", "2026-10-12T20:01:30.123456099Z", false, false},
		{"mismatched-original-json-deadline", "2026-10-12T20:01:30.123456099Z", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			census, policy, p, checkpoint, source := nativeReleaseChainProtocolFixture(t, 2)
			original, err := time.Parse(time.RFC3339Nano, tc.expiry)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal("isolated deadline transaction unavailable", err)
			}
			defer tx.Rollback()
			for i, row := range census.Commands {
				c := row.Hot
				c.ExpiresAt = original
				if tc.name == "mismatched-original-json-deadline" {
					c.ExpiresAt = c.ExpiresAt.Add(time.Microsecond)
				}
				// Distinct inert fixture hashes preserve global identity uniqueness.
				c.AuthorityTokenSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(c.CommandID.String())))
				commandRaw, marshalErr := json.Marshal(c)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_command_identities(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,authority_token_sha256,request_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, c.CommandID, c.Namespace, c.Environment, c.Domain, c.Dimension, c.IntentGeneration, c.Operation, checkpoint.PodUID, c.Phase, c.Sequence, c.AuthorityTokenSHA256, c.RequestSHA256); err != nil {
					t.Fatal("original inert deadline identity unavailable", err)
				}
				if tc.archived {
					_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_command_archive(id,record_sha256,command_record) VALUES($1,$2,$3)`, c.CommandID, nativeReleaseChainSHA(commandRaw), commandRaw)
				} else {
					_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_commands(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,state,authority_token_sha256,command_record) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, c.CommandID, c.Namespace, c.Environment, c.Domain, c.Dimension, c.IntentGeneration, c.Operation, checkpoint.PodUID, c.Phase, c.Sequence, c.State, c.AuthorityTokenSHA256, commandRaw)
				}
				if err != nil {
					t.Fatal("original inert deadline command unavailable", err)
				}
				r := census.Results[i]
				column := original
				if tc.name == "mismatched-native-column" {
					column = column.Add(time.Microsecond)
				}
				if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_release_results(command_id,attempt_id,protocol,adapter_source_commit,return_nonce_sha256,original_deadline,adapter_result,adapter_result_sha256,adapter_ack_at,caller_ack_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, r.CommandID, r.AttemptID, r.Protocol, r.Source, r.ReturnNonceSHA, column, r.Result, r.ResultSHA, r.AdapterACK, r.CallerACK); err != nil {
					t.Fatal("original native typed deadline result unavailable", err)
				}
				if i > 0 {
					d := census.Decisions[i-1]
					d.Record.Command.ExpiresAt = c.ExpiresAt
					d.Record.Command.AuthorityTokenSHA256 = c.AuthorityTokenSHA256
					recordRaw, marshalErr := json.Marshal(d.Record)
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_release_recovery_decisions(id,parent_command_id,parent_attempt_id,command_id,fence,decision_record,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, d.ID, d.ParentID, d.ParentAttempt, d.CommandID, d.Fence, recordRaw, d.CreatedAt); err != nil {
						t.Fatal("original immutable deadline decision unavailable", err)
					}
				}
			}
			if tx.Commit() != nil {
				t.Fatal("original deadline fixture COMMIT unresolved")
			}
			actual := nativeReleaseReadChainCensus(t, ctx, db, checkpoint.Namespace, checkpoint.PodUID)
			if len(actual.Commands) != 2 || len(actual.Results) != 2 || len(actual.Decisions) != 1 {
				t.Fatal("native deadline collector dropped original rows")
			}
			for _, r := range actual.Results {
				if r.NativeDeadlineMatches == nil || *r.NativeDeadlineMatches != tc.valid || r.CommandExpirySQL == nil || !r.Deadline.Equal(*r.CommandExpirySQL) && tc.valid {
					t.Fatal("native typed deadline equality differs")
				}
				var c *model.CapacityNativeCommand
				for _, row := range actual.Commands {
					candidate := row.Hot
					if candidate == nil {
						candidate = row.Archive
					}
					if candidate.CommandID == r.CommandID {
						c = candidate
					}
				}
				if c == nil || r.CommandExpiryJSON != c.ExpiresAt.Format(time.RFC3339Nano) || !c.ExpiresAt.Equal(original) && tc.valid {
					t.Fatal("original exact JSON nanoseconds were replaced")
				}
				if tc.valid && tc.name != "exact-microseconds" && r.Deadline.Equal(c.ExpiresAt) {
					t.Fatal("native rounding boundary was not reached")
				}
			}
			if err := validateNativeReleaseChain(actual, checkpoint.Namespace, checkpoint.PodUID, source, policy, p, checkpoint); (err == nil) != tc.valid {
				t.Fatal("whole native chain accepted a mismatched deadline or refused native typed equality", err)
			}
		})
	}
}
