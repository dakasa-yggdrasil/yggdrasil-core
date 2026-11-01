// Package labhistorical validates a historical LAB census as a diagnostic.
// It does not establish who produced the bytes or authorize recovery.
package labhistorical

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const (
	PolicyID       = "d1d75916-4f0a-4e91-91f9-7a849da87a2f"
	PolicyChecksum = "803c521bfd421ad232c176d25624518eba2ef50a65844722d8b607ab821f858c"
	InstanceID     = "bf14f99f-5de3-4314-a462-db85fa973f3c"
	ScopeChecksum  = "15076a670596725558f1c0924daa69b88cde1dd216ea25e4cb7570c2291fc45a"
	AdapterSource  = "57fcec882c31ad958d92556de9e9789fc95b8970"
	ProfileSHA     = "1c581fa9589cd7e75104ce8529c0a98c21662f2b2756d2b336e8639453c25d71"
	AdmissionSHA   = "8ef90bfc699ea90b58a053e2ae57fbdd9b2317d5c3d3a7c13e3e362e38605473"
)

var ErrHold = errors.New("historical LAB census held")

// DiagnosticSnapshot never emits a no-send, fencing, health or recovery proof.
// Its inventory argument is untrusted data until a separate authenticated source
// and terminality/custody check has succeeded.
func DiagnosticSnapshot(policyWire, inventoryWire []byte, now time.Time) (model.CapacitySnapshot, error) {
	var empty model.CapacitySnapshot
	if len(policyWire) == 0 || len(policyWire) > 2<<20 || len(inventoryWire) == 0 || len(inventoryWire) > 2<<20 || now.IsZero() {
		return empty, ErrHold
	}
	var doc model.ManifestDocument
	if capacity.DecodeNativeCapacity(json.RawMessage(policyWire), &doc) != nil || doc.Kind != "capacity_policy" || doc.Metadata.Namespace != "dakasa-production" || doc.Metadata.Name != "notify-aws-elastic-lab-90228" {
		return empty, ErrHold
	}
	checksum, err := manifest.Checksum(doc)
	if err != nil || checksum != PolicyChecksum {
		return empty, ErrHold
	}
	p, err := manifest.ParseCapacityPolicySpec(doc.Spec)
	if err != nil || len(p.MutationBindings) != 1 || p.GuestRetirementBinding == nil {
		return empty, ErrHold
	}
	b := p.MutationBindings[0]
	if b.IntegrationInstanceID != InstanceID || b.ScopeChecksum != ScopeChecksum || b.OriginalProviderSourceCommit != AdapterSource || b.ProfileName != "notify-aws-elastic" || len(b.Slots) != 8 || b.Slots[0].DesiredSpec == nil || b.Slots[0].DesiredSpec.ProfileChecksum != ProfileSHA || b.Slots[0].DesiredSpec.AdmissionChecksum != AdmissionSHA {
		return empty, ErrHold
	}
	var inv model.CapacityVMFleetInventory
	if capacity.DecodeNativeCapacity(json.RawMessage(inventoryWire), &inv) != nil || len(inv.Members) != 0 || inv.IntegrationInstanceID != InstanceID || inv.ScopeChecksum != ScopeChecksum || inv.ProfileChecksum != ProfileSHA || inv.AdmissionChecksum != AdmissionSHA {
		return empty, ErrHold
	}
	policy := model.Manifest{ID: uuid.MustParse(PolicyID), Checksum: PolicyChecksum, Kind: doc.Kind, Spec: doc.Spec, Metadata: model.ManifestMetadata{Name: doc.Metadata.Name, Namespace: doc.Metadata.Namespace}}
	snapshot, err := capacity.GuestReconcileSnapshot(policy, p, inv, now)
	if err != nil || snapshot.Units != 0 || snapshot.ResourceUID != "original-vm-profile:"+InstanceID+":"+ScopeChecksum || snapshot.Owner != "elastic-lab-6ec84" || snapshot.TargetIdentity != "dakasa-production/notify-aws-elastic" || snapshot.WorkloadUID != "original-guest-profile:c88d0cac53ebbf35706a541a8c004373114421a0450a6b7e7a23249c575f9ebc" || snapshot.ResourceVersion != "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945" || snapshot.WorkloadResourceVersion != AdmissionSHA {
		return empty, ErrHold
	}
	return snapshot, nil
}
