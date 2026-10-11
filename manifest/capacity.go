package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func ParseCapacityPolicySpec(raw json.RawMessage) (model.CapacityPolicySpec, error) {
	var spec model.CapacityPolicySpec
	if err := capacity.ValidateGuestBootstrapPolicyJSON(raw); err != nil {
		return spec, err
	}
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
	if err := capacity.ValidateGuestBootstrapBinding(spec); err != nil {
		return err
	}
	if b := spec.ControllerBinding; b != nil {
		if b.Mode != "capacity_dispatch_prestart_v1" || b.MachinePrincipalID == "" || len(b.MachinePrincipalID) > 128 || strings.TrimSpace(b.MachinePrincipalID) != b.MachinePrincipalID || strings.ContainsAny(b.MachinePrincipalID, "*?\x00\r\n") || b.DispatchLeaseSeconds < 5 || b.DispatchLeaseSeconds > 90 || spec.AssessmentBinding == nil || spec.HPAExecutionBinding == nil || spec.HPAExecutionBinding.Mode != capacity.HPALifetimeExecutionMode || spec.Dimension != "reserved_pod_envelope" || len(spec.Profiles) != 1 || len(spec.MutationBindings) != 0 {
			return fmt.Errorf("capacity controller requires fixed pre-start HPA delegation")
		}
		if d := b.DemandSource; d != nil {
			id, err := uuid.Parse(d.ManifestID)
			if err != nil || id == uuid.Nil || id.String() != d.ManifestID || d.Mode != "core_workflow_completion_v1" || d.Namespace == "" || d.Name == "" || strings.TrimSpace(d.Namespace) != d.Namespace || strings.TrimSpace(d.Name) != d.Name || strings.ContainsAny(d.Namespace+d.Name, "*?\x00\r\n") || len(d.Namespace) > 64 || len(d.Name) > 128 || d.Version < 1 || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(d.Checksum) || d.MaxAgeSeconds < 1 || d.MaxAgeSeconds > spec.MaxEvidenceAgeSeconds || (d.Namespace == spec.Workflow.Namespace && d.Name == spec.Workflow.Name) {
				return fmt.Errorf("capacity demand requires one exact independent source workflow")
			}
		}
	}
	return nil
}
