package httpapi

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// This source-owned fixture only READS the server-owned deletion grace. A real
// terminated container can still precede that last graceful-delete RV change.
// Neither the spec grace nor a native object/receipt is patched or defaulted.
// Passing this prerequisite supplies no permit and cannot exclude a later
// writer: the original adapter/Core RV, redemption and HOLD guards still own it.
func nativeReleaseFixtureTerminalReady(object map[string]any, checkpoint model.CapacityNativePodCheckpoint, lanes []string, nativeFinalizer, foreignFinalizer string) bool {
	raw, err := json.Marshal(object)
	var pod corev1.Pod
	if err != nil || len(raw) > 1<<20 || json.Unmarshal(raw, &pod) != nil || string(pod.UID) != checkpoint.PodUID || pod.Name != checkpoint.PodName || pod.Namespace != checkpoint.Namespace || pod.Generation != checkpoint.PodGeneration || pod.ResourceVersion == "" || pod.DeletionTimestamp == nil || pod.DeletionTimestamp.IsZero() || pod.DeletionGracePeriodSeconds == nil || *pod.DeletionGracePeriodSeconds != 0 || pod.Spec.TerminationGracePeriodSeconds == nil || *pod.Spec.TerminationGracePeriodSeconds != 30 || len(pod.Finalizers) != 2 || nativeFinalizer == "" || foreignFinalizer == "" || nativeFinalizer == foreignFinalizer {
		return false
	}
	if !((pod.Finalizers[0] == nativeFinalizer && pod.Finalizers[1] == foreignFinalizer) || (pod.Finalizers[1] == nativeFinalizer && pod.Finalizers[0] == foreignFinalizer)) || len(pod.Status.ContainerStatuses) != 1 {
		return false
	}
	c := pod.Status.ContainerStatuses[0]
	terminated := c.State.Terminated
	if c.Name != checkpoint.ContainerName || c.ContainerID != checkpoint.ContainerID || c.RestartCount != checkpoint.RestartCount || !strings.HasSuffix(c.ImageID, checkpoint.ImageDigest) || terminated == nil || c.State.Running != nil || c.State.Waiting != nil || terminated.ExitCode != 0 || terminated.Signal != 0 || !terminated.StartedAt.Time.Equal(checkpoint.ContainerStartedAt) || terminated.FinishedAt.IsZero() {
		return false
	}
	var expected model.NativePodTerminationChallenge
	var receipt model.NativePodTerminationReceipt
	if capacity.DecodeNativeCapacity(checkpoint.Challenge, &expected) != nil || capacity.DecodeNativeCapacity(json.RawMessage(terminated.Message), &receipt) != nil || !nativeReleaseChainSameJSON(expected, receipt.NativePodTerminationChallenge) || receipt.SchemaVersion != 2 || receipt.ProcessNonce != checkpoint.ProcessNonce || receipt.RootAdmission != "previously_opened" || receipt.JoinedAt.IsZero() || receipt.JoinedAt.Before(expected.IssuedAt) || len(receipt.Lanes) != len(lanes) || receipt.LaneRosterSHA256 != capacity.NativeRosterDigest(lanes) {
		return false
	}
	seen := map[string]bool{}
	for _, lane := range lanes {
		state, known := receipt.Lanes[lane]
		if !known || seen[lane] || (state != "done" && state != "inactive") {
			return false
		}
		seen[lane] = true
	}
	return true
}

func TestCapacityNativeReleaseTerminalPrerequisite(t *testing.T) {
	for _, scenario := range []string{"original-grace-zero-terminal-receipt", "terminal-before-grace-zero", "missing-deletion-grace", "missing-deletion-timestamp", "foreign-pod-uid", "missing-resource-version", "lost-native-finalizer", "lost-foreign-finalizer", "duplicate-finalizer", "zero-spec-grace-kills-original", "container-still-running", "nonzero-original-exit", "foreign-container-lifetime", "foreign-process-nonce", "foreign-native-challenge", "incomplete-original-lane"} {
		t.Run(scenario, func(t *testing.T) {
			census, _, p, checkpoint, _ := nativeReleaseChainProtocolFixture(t, 2)
			witness := census.Decisions[0].Record.Witness.Observation
			receipt := *witness.Receipt
			grace, specGrace := int64(0), int64(30)
			deleted := metav1.NewTime(*witness.DeletionRequestedAt)
			pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: checkpoint.PodName, Namespace: checkpoint.Namespace, UID: types.UID(checkpoint.PodUID), Generation: checkpoint.PodGeneration, ResourceVersion: "original-terminal", DeletionTimestamp: &deleted, DeletionGracePeriodSeconds: &grace, Finalizers: []string{"original-native", "original-foreign"}}, Spec: corev1.PodSpec{TerminationGracePeriodSeconds: &specGrace}, Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: checkpoint.ContainerName, ContainerID: checkpoint.ContainerID, ImageID: witness.ImageID, RestartCount: checkpoint.RestartCount, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0, Signal: 0, StartedAt: metav1.NewTime(checkpoint.ContainerStartedAt), FinishedAt: metav1.NewTime(*witness.FinishedAt)}}}}}}
			switch scenario {
			case "terminal-before-grace-zero":
				grace = 30
			case "missing-deletion-grace":
				pod.DeletionGracePeriodSeconds = nil
			case "missing-deletion-timestamp":
				pod.DeletionTimestamp = nil
			case "foreign-pod-uid":
				pod.UID = types.UID(uuid.NewString())
			case "missing-resource-version":
				pod.ResourceVersion = ""
			case "lost-native-finalizer":
				pod.Finalizers = []string{"original-foreign"}
			case "lost-foreign-finalizer":
				pod.Finalizers = []string{"original-native"}
			case "duplicate-finalizer":
				pod.Finalizers = []string{"original-native", "original-native"}
			case "zero-spec-grace-kills-original":
				specGrace = 0
			case "container-still-running":
				pod.Status.ContainerStatuses[0].State.Running = &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(checkpoint.ContainerStartedAt)}
			case "nonzero-original-exit":
				pod.Status.ContainerStatuses[0].State.Terminated.ExitCode = 137
			case "foreign-container-lifetime":
				pod.Status.ContainerStatuses[0].ContainerID = "containerd://foreign"
			case "foreign-process-nonce":
				receipt.ProcessNonce = uuid.NewString()
			case "foreign-native-challenge":
				receipt.DrainNonce = uuid.NewString()
			case "incomplete-original-lane":
				delete(receipt.Lanes, p.HPAExecutionBinding.Lanes[0])
			}
			rawReceipt, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			pod.Status.ContainerStatuses[0].State.Terminated.Message = string(rawReceipt)
			raw, err := json.Marshal(pod)
			var object map[string]any
			if err != nil || json.Unmarshal(raw, &object) != nil {
				t.Fatal("native fixture prerequisite body unavailable")
			}
			if nativeReleaseFixtureTerminalReady(object, checkpoint, p.HPAExecutionBinding.Lanes, "original-native", "original-foreign") != (scenario == "original-grace-zero-terminal-receipt") {
				t.Fatal("unsettled, foreign or incomplete original Pod acquired a fixture prerequisite")
			}
		})
	}
}

type nativeReleaseOriginalVersionChange struct {
	CommandID, ParentID, PodUID, ExpectedRV, BeforeRV, AfterRV string
	At                                                         time.Time
}

// Only the separately admitted recovery child reaches this adversary. It reads
// the exact original Pod before/after ONE real fixture annotation and forwards
// the original request bytes once. No status, return certificate or authority
// is manufactured; no grace/finalizer/lifetime field is changed.
func nativeReleaseInjectOriginalChildVersion(ctx context.Context, realm string, command model.CapacityNativeCommand, request model.AdapterDestroyCapacityPodDrainProtectionRequest) (nativeReleaseOriginalVersionChange, error) {
	out := nativeReleaseOriginalVersionChange{CommandID: command.CommandID.String(), ParentID: command.ParentCommandID, PodUID: request.ExpectedPodUID, ExpectedRV: request.ExpectedPodResourceVersion}
	if command.CommandID == uuid.Nil || command.ParentCommandID == "" || command.State != "issued" || command.AttemptID != uuid.Nil || command.RedeemedBy != "" || command.RecoveryDecisionID == "" || command.RecoveryFence == "" || !command.ExpiresAt.After(time.Now().UTC()) || request.ExpectedPodUID == "" || request.ExpectedPodResourceVersion == "" || request.PodName == "" {
		return out, errors.New("current unredeemed original child required")
	}
	read := func() (*corev1.Pod, error) {
		raw, err := exec.CommandContext(ctx, "kubectl", "-n", realm, "get", "pod", request.PodName, "-o", "json").Output()
		var pod corev1.Pod
		if err != nil || len(raw) > 1<<20 || json.Unmarshal(raw, &pod) != nil || string(pod.UID) != request.ExpectedPodUID || pod.ResourceVersion == "" || pod.DeletionGracePeriodSeconds == nil || *pod.DeletionGracePeriodSeconds != 0 {
			return nil, errors.New("exact settled original child Pod unavailable")
		}
		return &pod, nil
	}
	before, err := read()
	if err != nil || before.ResourceVersion != request.ExpectedPodResourceVersion {
		return out, errors.New("original child witness already changed before fixture adversary")
	}
	out.BeforeRV = before.ResourceVersion
	const annotation = "fixture.yggdrasil.io/native-child-late-rv"
	annotations := map[string]string{}
	for key, value := range before.Annotations {
		annotations[key] = value
	}
	annotations[annotation] = "original"
	// The fixture writer has its OWN CAS. A changed/replaced object between
	// this original GET and PATCH is a refused fixture, never a retry or a
	// mutation of another lifetime selected by its reusable Pod name.
	patch, err := json.Marshal([]map[string]any{{"op": "test", "path": "/metadata/uid", "value": request.ExpectedPodUID}, {"op": "test", "path": "/metadata/resourceVersion", "value": before.ResourceVersion}, {"op": "add", "path": "/metadata/annotations", "value": annotations}})
	if err != nil {
		return out, errors.New("single original child annotation CAS unavailable")
	}
	if err := exec.CommandContext(ctx, "kubectl", "-n", realm, "patch", "pod", request.PodName, "--type=json", "-p", string(patch)).Run(); err != nil {
		return out, fmt.Errorf("single original child annotation CAS did not return: %w", err)
	}
	after, err := read()
	if err != nil || after.ResourceVersion == before.ResourceVersion || after.Annotations[annotation] != "original" || !nativeReleaseChainSameJSON(annotations, after.Annotations) || after.Namespace != before.Namespace || after.Name != before.Name || after.Generation != before.Generation || !nativeReleaseChainSameJSON(before.OwnerReferences, after.OwnerReferences) || !nativeReleaseChainSameJSON(before.DeletionTimestamp, after.DeletionTimestamp) || !nativeReleaseChainSameJSON(before.Finalizers, after.Finalizers) || !nativeReleaseChainSameJSON(before.Spec, after.Spec) || !nativeReleaseChainSameJSON(before.Status, after.Status) {
		return out, errors.New("original child annotation changed native lifetime or protection")
	}
	out.AfterRV, out.At = after.ResourceVersion, time.Now().UTC()
	return out, nil
}

func assertNativeReleaseChildVersionHold(t *testing.T, ctx context.Context, db *sql.DB, realm, subject, source string, policy model.Manifest, p model.CapacityPolicySpec, checkpoint model.CapacityNativePodCheckpoint, change nativeReleaseOriginalVersionChange, adapterLog string) {
	t.Helper()
	census := nativeReleaseReadChainCensus(t, ctx, db, realm, subject)
	if !nativeReleaseIncidentEdgesClosed(census) || len(census.Commands) != 2 || len(census.Results) != 1 || len(census.Decisions) != 1 || census.Commands[0].Hot == nil || census.Commands[1].Hot == nil || change.PodUID != subject || change.BeforeRV != change.ExpectedRV || change.AfterRV == change.BeforeRV || change.At.IsZero() {
		t.Fatal("late original child version refusal lost its exact permanent census")
	}
	parent, child := census.Commands[0].Hot, census.Commands[1].Hot
	result, decision := census.Results[0], census.Decisions[0]
	var request model.AdapterDestroyCapacityPodDrainProtectionRequest
	var original model.CapacityNativeReleaseResult
	if parent.Sequence != 1 || parent.State != "rejected_no_effect" || parent.AttemptID == uuid.Nil || parent.RedeemedBy != p.HPAExecutionBinding.AdapterPrincipalID || parent.CallerReturnObservedAt == nil || parent.AdapterSourceCommit != source || child.Sequence != 2 || child.State != "uncertain" || child.CommandID.String() != change.CommandID || child.ParentCommandID != parent.CommandID.String() || change.ParentID != parent.CommandID.String() || child.ParentAttemptID != parent.AttemptID.String() || child.AttemptID != uuid.Nil || child.RedeemedBy != "" || child.CallerReturnObservedAt != nil || len(child.OriginalResult) != 0 || len(child.NativeReadback) != 0 || child.AdapterSourceCommit != source || child.AuthorityTokenSHA256 == parent.AuthorityTokenSHA256 || child.CreatedAt.Before(*parent.CallerReturnObservedAt) || !child.ExpiresAt.Equal(parent.ExpiresAt) || child.IntentGeneration != parent.IntentGeneration || child.FencingToken != parent.FencingToken || child.PolicyID != policy.ID || child.PolicyChecksum != policy.Checksum || child.OriginPolicySHA256 != parent.OriginPolicySHA256 || child.LeaseOwner != parent.LeaseOwner || child.ExecutorID != parent.ExecutorID || child.WorkflowID != parent.WorkflowID || !nativeReleaseDeadlineExact(result, parent) || result.AdapterACK == nil || result.CallerACK == nil || result.CommandID != parent.CommandID || !result.CallerACK.Equal(*parent.CallerReturnObservedAt) || result.CallerACK.Before(*result.AdapterACK) || !result.CallerACK.Before(parent.ExpiresAt) || result.ResultSHA != parent.OriginalResultSHA256 || result.ResultSHA != nativeReleaseChainSHA(result.Result) || capacity.DecodeNativeCapacity(result.Result, &original) != nil || original.CommandID != parent.CommandID || original.AttemptID != parent.AttemptID || original.AdapterSourceCommit != source || original.OriginalStatus != 409 || original.Outcome != "rejected_no_effect" || !original.OneSend || !original.DoReturned || !original.ReadReturned || !original.CloseReturned || decision.CommandID != child.CommandID || decision.ParentID != parent.CommandID || decision.ParentAttempt != parent.AttemptID || decision.ID.String() != child.RecoveryDecisionID || decision.Fence.String() != child.RecoveryFence || decision.Record.ParentResultSHA != parent.OriginalResultSHA256 || !decision.CreatedAt.Equal(child.CreatedAt) || capacity.DecodeNativeCapacity(child.Request, &request) != nil || request.ExpectedPodUID != subject || request.ExpectedPodResourceVersion != change.BeforeRV || decision.Record.Witness.Observation.PodResourceVersion != change.BeforeRV || capacity.NativePodWitness(p, checkpoint, decision.Record.Witness.Observation, child.CreatedAt) != nil || capacity.NativePodInventory(p, decision.Record.Inventory, child.CreatedAt) != nil {
		t.Fatal("late child RV acquired a redemption/result, replay or replacement authority")
	}
	matchedInventory := false
	for _, pod := range decision.Record.Inventory.Pods {
		if pod.PodUID == subject {
			matchedInventory = capacity.NativePodMatchesCheckpoint(p, checkpoint, pod, child.CreatedAt) == nil && pod.PodResourceVersion == change.BeforeRV
		}
	}
	if !matchedInventory || validateNativeReleaseChain(census, realm, subject, source, policy, p, checkpoint) == nil {
		t.Fatal("uncertain child was treated as a qualified confirmed original release")
	}
	raw, err := os.ReadFile(adapterLog)
	if err != nil {
		t.Fatal("original adapter child refusal diagnostics unavailable", err)
	}
	refusedBeforeRedemption := false
	for _, line := range strings.Split(string(raw), "\n") {
		_, payload, found := strings.Cut(line, "NATIVE_POD_ORIGINAL_REFUSAL_V1:")
		if !found {
			continue
		}
		var facts struct {
			Phase          string `json:"phase"`
			Terminated     bool   `json:"terminated_state"`
			ReceiptPresent bool   `json:"receipt_present"`
			VersionMatched bool   `json:"resource_version_matched"`
			Authority      bool   `json:"authority"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(payload)), &facts) == nil && facts.Phase == "release-observe" && facts.Terminated && facts.ReceiptPresent && !facts.VersionMatched && !facts.Authority {
			refusedBeforeRedemption = true
		}
	}
	if !refusedBeforeRedemption {
		t.Fatal("original adapter did not prove the child RV refusal before redemption")
	}
	t.Logf("original late child native RV retained HOLD, no redemption/result/replacement; adapter_log_sha256=%x", sha256.Sum256(raw))
}
