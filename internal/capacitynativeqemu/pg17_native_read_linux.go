//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// PG17NativeRead is the read callee for ONLY the existing Source adapter's two
// advertised observation capabilities. The original RPC owner supplies the
// already decoded request; this function opens no transport/worker/queue. No
// workflow or request map can supply a successful proof, actor or native tuple.
// The logical slot name/labels are this qualification adapter's immutable Source
// projection, not claims that QEMU has a provider's labels or paid resources.
func (r *Realm) PG17NativeRead(ctx context.Context, store repository.CapacityStore, policy model.Manifest, request model.AdapterExecuteIntegrationRequest) (model.AdapterExecuteIntegrationResponse, error) {
	out := model.AdapterExecuteIntegrationResponse{}
	deadline, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil || deadline.After(r.Request.OriginalContextDeadline) || r.Request.NativeCase != "positive_original_lifecycle" || len(r.Request.Slots) != 2 || store.DB == nil || request.Operation != request.Capability || (request.Capability != capacity.VMObserveServer && request.Capability != capacity.VMObserveAction) || len(request.Auth) != 0 || len(request.Metadata) != 0 {
		return out, ErrOriginalUnknown
	}
	var spec model.CapacityPolicySpec
	if json.Unmarshal(policy.Spec, &spec) != nil || policy.Metadata.Namespace == "" || spec.Owner == "" {
		return out, ErrOriginalUnknown
	}
	profile, profileOK := request.Input["profile"].(string)
	grantID, grantOK := request.Input["grant_id"].(string)
	if !profileOK || !grantOK || grantID == "" {
		return out, ErrOriginalUnknown
	}
	var slot int
	switch v := request.Input["slot"].(type) {
	case int:
		slot = v
	case float64:
		if v != 1 && v != 2 {
			return out, ErrOriginalUnknown
		}
		slot = int(v)
	default:
		return out, ErrOriginalUnknown
	}
	if slot != 2 {
		return out, ErrOriginalUnknown
	}
	allowed := map[string]bool{"profile": true, "slot": true, "grant_id": true, "expected_resource_id": true, "expected_resource_created_at": true}
	if request.Capability == capacity.VMObserveAction {
		allowed["action_id"] = true
	}
	for key := range request.Input {
		if !allowed[key] {
			return out, ErrOriginalUnknown
		}
	}
	r.mu.Lock()
	pre, preOK := r.preregistrations[slot]
	original, originalOK := r.originals[slot]
	started := r.started[slot]
	r.mu.Unlock()
	if !preOK || !originalOK || !started || pre.OriginalCreateGrantID != grantID || pre.PolicyID != policy.ID.String() || pre.WorkflowID != store.WorkflowID.String() || pre.CoreSourceCommit != capacity.CurrentGuestCoreSource() || deadline.After(pre.OriginalDeadline) || original.Original.OriginalSourceCommit != r.Request.SourceCommit || original.Original.ResourceID != r.Request.Slots[slot-1].ResourceID {
		return out, ErrOriginalUnknown
	}
	// The RPC worker is a read owner, not the workflow executor. Bind only a
	// local readonly store copy to the SAME actual private preregistration after
	// its full immutable DB record/source/workflow match. No context/lease or
	// mutation authority is created or transferred to the worker.
	var preregistrationRaw []byte
	if err := store.DB.QueryRowContext(ctx, `SELECT preregistration_record FROM public.capacity_vm_provisioning_preregistrations WHERE id=$1 AND create_grant_id=$2`, pre.PreregistrationID, grantID).Scan(&preregistrationRaw); err != nil {
		return out, err
	}
	var durablePre model.CapacityGuestOriginalProvisioningPreregistration
	if json.Unmarshal(preregistrationRaw, &durablePre) != nil || capacity.GuestRetirementSHA(durablePre) != capacity.GuestRetirementSHA(pre) || pre.ExecutorID == "" || pre.PolicyChecksum != policy.Checksum {
		return out, ErrOriginalUnknown
	}
	store.ExecutorID = pre.ExecutorID
	store.ExecutionEnabled = false
	persisted, err := store.OriginalGuestProvisioning(ctx, grantID)
	if err != nil || capacity.GuestRetirementSHA(persisted) != capacity.GuestRetirementSHA(pre) {
		return out, ErrOriginalUnknown
	}
	binding, err := capacity.VMObservationBinding(spec, pre.BindingName)
	if err != nil || profile != binding.ProfileName || request.Integration.Instance.ID.String() != binding.IntegrationInstanceID || request.Integration.Type.ID.String() != binding.IntegrationTypeID {
		return out, ErrOriginalUnknown
	}
	// Resolve the exact current manifests, not request-supplied specs or mutable
	// aliases. The fixed native handler also independently enforces revisions.
	instanceID, err := uuid.Parse(binding.IntegrationInstanceID)
	if err != nil {
		return out, ErrOriginalUnknown
	}
	typeID, err := uuid.Parse(binding.IntegrationTypeID)
	if err != nil {
		return out, ErrOriginalUnknown
	}
	instance, err := repository.GetManifestByID(ctx, store.DB, instanceID)
	if err != nil || !instance.Metadata.Active || instance.Kind != "integration_instance" || instance.Metadata.Namespace != policy.Metadata.Namespace || instance.Checksum != binding.IntegrationChecksum {
		return out, ErrOriginalUnknown
	}
	typ, err := repository.GetManifestByID(ctx, store.DB, typeID)
	if err != nil || !typ.Metadata.Active || typ.Kind != "integration_type" || typ.Metadata.Namespace != policy.Metadata.Namespace || typ.Checksum != binding.IntegrationTypeChecksum {
		return out, ErrOriginalUnknown
	}
	receipt, err := store.MutationReceipt(ctx, binding.AdapterPrincipalID, grantID)
	if err != nil || receipt.Grant.GrantID != grantID || receipt.Grant.Slot != slot || (receipt.Grant.State != "settled" && receipt.Grant.State != "confirmed") || receipt.Outcome != "accepted" || !receipt.TransportCompleted || receipt.ResourceID != original.Original.ResourceID || receipt.ResourceCreatedAt != original.Original.OriginalCreateReturnedAt.UTC().Format(time.RFC3339Nano) || receipt.ActionID != "qemu-original-create:"+capacity.GuestRetirementSHA(original.Original) || len(receipt.NextActionIDs) != 0 {
		return out, ErrOriginalUnknown
	}
	if request.Input["expected_resource_id"] != receipt.ResourceID || request.Input["expected_resource_created_at"] != receipt.ResourceCreatedAt {
		return out, ErrOriginalUnknown
	}
	fresh, err := Observe(ctx, SlotDirectory(r.PrivateDirectory, slot), original.Original, r.QEMUBinarySHA256)
	if err != nil || r.verifyFixedCommand(ctx, slot, fresh) != nil || fresh.UUID.UUID != receipt.ResourceID || !fresh.Status.Running || fresh.Status.Status != "running" || fresh.CloseReturnedAt.Before(fresh.StartedAt) || !fresh.CloseReturnedAt.Before(deadline) {
		return out, ErrOriginalUnknown
	}
	var approved *model.CapacityMutationSpecV1
	var approvedSHA string
	for _, candidate := range binding.Slots {
		if candidate.Slot == slot {
			approved, approvedSHA = candidate.DesiredSpec, candidate.DesiredSpecSHA256
		}
	}
	if approved == nil || approvedSHA != receipt.Grant.RequestSHA256 || approvedSHA != pre.OriginalCreateRequestSHA256 || approved.NativeName != "original-native-qemu-slot-"+strconv.Itoa(slot) || approved.ProfileChecksum != capacity.GuestRetirementSHA([]string{"native-original-qemu-fixed-1536-2-kvm", r.Profile.OwnerSourceCommit}) || approved.AdmissionChecksum != capacity.GuestRetirementSHA(r.Profile) || pre.ProfileManifestSHA256 != capacity.GuestRetirementSHA(r.Profile) || binding.EnsureCapability != "ensure_server" {
		return out, ErrOriginalUnknown
	}
	// Retain complete actual native I/O independently of the public projection.
	originalReadFile := "pg17-native-read-" + uuid.NewString() + ".json"
	originalReadWire, err := Publish(ctx, filepath.Join(SlotDirectory(r.PrivateDirectory, slot), originalReadFile), fresh)
	if err != nil {
		return out, err
	}
	at := fresh.CloseReturnedAt.UTC().Format(time.RFC3339Nano)
	out = model.AdapterExecuteIntegrationResponse{Operation: request.Operation, Capability: request.Capability, Status: "observed", Metadata: map[string]any{"original_native_read_file": originalReadFile, "original_native_read_sha256": capacity.BusinessCreationSHA256(originalReadWire)}}
	if request.Capability == capacity.VMObserveAction {
		if request.Input["action_id"] != receipt.ActionID || original.Original.OriginalCreateStartedAt.IsZero() || original.Original.OriginalCreateReturnedAt.Before(original.Original.OriginalCreateStartedAt) || !original.Original.OriginalClosesReturned {
			return model.AdapterExecuteIntegrationResponse{}, ErrOriginalUnknown
		}
		out.Output = model.CapacityVMActionObservation{ID: receipt.ActionID, Status: "success", Command: "ensure_server", ResourceID: receipt.ResourceID, StartedAt: original.Original.OriginalCreateStartedAt.UTC().Format(time.RFC3339Nano), FinishedAt: receipt.ResourceCreatedAt, ObservedAt: at, ProviderFencingEvidence: false}
	} else {
		label := func(value string) string {
			raw, err := hex.DecodeString(value)
			if err != nil {
				return ""
			}
			return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
		}
		desired := *approved
		desired.Capability = capacity.VMObserveServer
		server := model.CapacityVMServerObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: receipt.ResourceID, CreatedAt: receipt.ResourceCreatedAt}, Name: approved.NativeName, Status: fresh.Status.Status, Labels: map[string]string{"yggdrasil.io/owner": spec.Owner, "yggdrasil.io/scope": label(binding.ScopeChecksum), "yggdrasil.io/spec": label(approved.ProfileChecksum), "yggdrasil.io/profile": binding.ProfileName, "yggdrasil.io/slot": strconv.Itoa(slot), "yggdrasil.io/intent": grantID}, PhysicalSpecVerified: true, ObservedAt: at}
		out.Output = model.CapacityVMFleetPlan{DesiredSpec: desired, RequestSHA256: approvedSHA, Protected: slot <= binding.ProtectedSlots, Server: &server, ObservedAt: at}
	}
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		return model.AdapterExecuteIntegrationResponse{}, ErrOriginalUnknown
	}
	return out, nil
}
