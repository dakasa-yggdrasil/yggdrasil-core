package capacity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const GuestContractSuccessorSchema = "guest_contract_successor_v1"

func ValidateGuestContractSuccessorJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	opening, err := d.Token()
	if err != nil || opening != json.Delim('{') {
		return fmt.Errorf("capacity policy object required")
	}
	seen := false
	for d.More() {
		token, e := d.Token()
		name, ok := token.(string)
		var value json.RawMessage
		if e != nil || !ok || d.Decode(&value) != nil {
			return fmt.Errorf("capacity policy member required")
		}
		if !strings.EqualFold(name, "guest_contract_successor") {
			continue
		}
		var successor model.CapacityGuestContractSuccessor
		trim := bytes.TrimSpace(value)
		if seen || name != "guest_contract_successor" || len(trim) == 0 || trim[0] != '{' || DecodeGuestLifecycle(value, &successor) != nil {
			return fmt.Errorf("one closed nonnull Guest contract successor required")
		}
		seen = true
	}
	if closing, e := d.Token(); e != nil || closing != json.Delim('}') {
		return fmt.Errorf("capacity policy closing object required")
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("one capacity policy required")
	}
	return nil
}

// ValidateGuestContractSuccessor checks declarations only. Repository resolution
// independently authenticates each immutable row, complete approval and lineage.
func ValidateGuestContractSuccessor(p model.CapacityPolicySpec) error {
	s := p.GuestContractSuccessor
	if s == nil {
		return nil
	}
	refuse := func() error { return fmt.Errorf("closed original Guest contract successor required") }
	if s.Schema != GuestContractSuccessorSchema || p.GuestNotifyReconcileBinding == nil || ValidateGuestNotifyReconcileBinding(p) != nil || len(s.RetainedPolicyContracts) < 1 || len(s.RetainedPolicyContracts) > p.Ceiling {
		return refuse()
	}
	ids, contracts := map[string]bool{}, map[string]bool{}
	for _, r := range s.RetainedPolicyContracts {
		id, err := uuid.Parse(r.PolicyID)
		if err != nil || id == uuid.Nil || id.String() != r.PolicyID || !ValidDigest(r.PolicyChecksum) || !ValidDigest(r.ContractSHA256) || ids[r.PolicyID] || contracts[r.ContractSHA256] {
			return refuse()
		}
		ids[r.PolicyID], contracts[r.ContractSHA256] = true, true
	}
	return nil
}

// GuestContractView retains current scheduling, policy identity and clocks while
// selecting an already authenticated immutable physical/Guest contract. It is a
// computational view, never a Manifest with an invented checksum.
func GuestContractView(current, birth model.CapacityPolicySpec) (model.CapacityPolicySpec, error) {
	if current.GuestRetirementBinding == nil || birth.GuestRetirementBinding == nil || len(current.Profiles) != 1 || len(birth.Profiles) != 1 || len(current.MutationBindings) != 1 || len(birth.MutationBindings) != 1 || current.Owner != birth.Owner || current.Environment != birth.Environment || current.Domain != birth.Domain || current.Dimension != birth.Dimension || current.TargetIdentity != birth.TargetIdentity || !reflect.DeepEqual(current.Workflow, birth.Workflow) || current.Profiles[0].Name != birth.Profiles[0].Name || current.Profiles[0].Provider != birth.Profiles[0].Provider || current.Profiles[0].Region != birth.Profiles[0].Region || current.MutationBindings[0].Name != birth.MutationBindings[0].Name || current.MutationBindings[0].MaxSlots != birth.MutationBindings[0].MaxSlots || current.MutationBindings[0].ProtectedSlots != birth.MutationBindings[0].ProtectedSlots {
		return model.CapacityPolicySpec{}, fmt.Errorf("guest contract logical scope differs")
	}
	current.MutationBindings = append([]model.CapacityMutationBinding(nil), birth.MutationBindings...)
	current.GuestRetirementBinding = birth.GuestRetirementBinding
	current.GuestNotifyCanaryBinding = birth.GuestNotifyCanaryBinding
	if ValidateGuestNotifyReconcileBinding(current) != nil {
		return model.CapacityPolicySpec{}, fmt.Errorf("guest contract view invalid")
	}
	return current, nil
}
