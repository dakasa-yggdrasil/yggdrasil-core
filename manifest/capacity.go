package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func ParseCapacityPolicySpec(raw json.RawMessage) (model.CapacityPolicySpec, error) {
	var spec model.CapacityPolicySpec
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&spec); err != nil {
		return spec, fmt.Errorf("parse capacity policy: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return spec, fmt.Errorf("capacity policy must contain one JSON object")
	}
	return spec, nil
}

func ValidateCapacityPolicySpec(spec model.CapacityPolicySpec) error {
	if err := capacity.ValidatePolicy(spec); err != nil {
		return err
	}
	if b := spec.ControllerBinding; b != nil {
		if b.Mode != "capacity_dispatch_prestart_v1" || b.MachinePrincipalID == "" || len(b.MachinePrincipalID) > 128 || strings.TrimSpace(b.MachinePrincipalID) != b.MachinePrincipalID || strings.ContainsAny(b.MachinePrincipalID, "*?\x00\r\n") || b.DispatchLeaseSeconds < 5 || b.DispatchLeaseSeconds > 90 || spec.AssessmentBinding == nil || spec.HPAExecutionBinding == nil || spec.HPAExecutionBinding.Mode != capacity.HPALifetimeExecutionMode || spec.Dimension != "reserved_pod_envelope" || len(spec.Profiles) != 1 || len(spec.MutationBindings) != 0 {
			return fmt.Errorf("capacity controller requires fixed pre-start HPA delegation")
		}
	}
	return nil
}
