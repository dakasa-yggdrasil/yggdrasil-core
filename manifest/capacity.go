package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func ParseCapacityPolicySpec(raw json.RawMessage) (model.CapacityPolicySpec, error) {
	var spec model.CapacityPolicySpec
	if err := validateGuestRetirementPolicyJSON(raw); err != nil {
		return spec, err
	}
	if err := capacity.ValidateGuestBootstrapPolicyJSON(raw); err != nil {
		return spec, err
	}
	// Absence is the legacy/default-off contract. A present null value must
	// never silently disable this operator-owned prerequisite.
	if err := validateNativeNotifyWindowJSON(raw); err != nil {
		return spec, err
	}
	if err := validateNativeReleaseRecoveryJSON(raw); err != nil {
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

func validateGuestRetirementPolicyJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return fmt.Errorf("canonical capacity policy object required")
	}
	seen := false
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		var value json.RawMessage
		if err != nil || !ok || decoder.Decode(&value) != nil {
			return fmt.Errorf("capacity policy member unavailable")
		}
		if !strings.EqualFold(name, "guest_retirement_binding") {
			continue
		}
		var binding model.CapacityGuestRetirementBinding
		if name != "guest_retirement_binding" || seen || capacity.DecodeGuestLifecycle(value, &binding) != nil {
			return fmt.Errorf("closed nonnull original Guest retirement binding required")
		}
		seen = true
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || decoder.Decode(new(any)) != io.EOF {
		return fmt.Errorf("one capacity policy object required")
	}
	return nil
}

func validateNativeNotifyWindowJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	opening, err := d.Token()
	if err != nil || opening != json.Delim('{') {
		return fmt.Errorf("capacity policy object required")
	}
	seen := false
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return fmt.Errorf("capacity policy member required")
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return fmt.Errorf("capacity policy member value required")
		}
		if !strings.EqualFold(name, "native_notify_window_binding") {
			continue
		}
		if name != "native_notify_window_binding" || seen || len(value) > 32<<10 || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("canonical nonnull original Notify window binding required")
		}
		seen = true
		var binding model.CapacityNativeNotifyWindowBinding
		if capacity.DecodeNativeCapacity(value, &binding) != nil {
			return fmt.Errorf("closed original Notify window binding required")
		}
		var members map[string]json.RawMessage
		if json.Unmarshal(value, &members) != nil {
			return fmt.Errorf("original Notify window binding object required")
		}
		if _, present := members["required_resources"]; present && len(binding.RequiredResources) == 0 {
			return fmt.Errorf("present original Notify resource roster must be nonempty")
		}
	}
	closing, err := d.Token()
	if err != nil || closing != json.Delim('}') || d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("one capacity policy object required")
	}
	return nil
}

func ValidateCapacityPolicySpec(spec model.CapacityPolicySpec) error {
	if err := capacity.ValidatePolicy(spec); err != nil {
		return err
	}
	if err := capacity.ValidateGuestBootstrapBinding(spec); err != nil {
		return err
	}
	if err := validateNativeNotifyWindowBinding(spec); err != nil {
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

func validateNativeNotifyWindowBinding(p model.CapacityPolicySpec) error {
	b := p.NativeNotifyWindowBinding
	if b == nil {
		return nil
	}
	refuse := func() error { return fmt.Errorf("fixed original Notify window operator binding required") }
	sha := regexp.MustCompile(`^[0-9a-f]{64}$`)
	source := regexp.MustCompile(`^[0-9a-f]{40}$`)
	name := regexp.MustCompile(`^[a-z][a-z0-9_-]{0,127}$`)
	// This first positively declared prerequisite measures ONE original call.
	// Notify's separate 64-probe limit and registry1024-read bound are unchanged.
	if b.Mode != "core_original_bound_machine" || !name.MatchString(b.Name) || !source.MatchString(b.SourceCommit) || !sha.MatchString(b.QuerySHA256) || b.QuerySHA256 != "cb805c604ceeffb265368719082a2f9203dabb60fc0406e1378e64e6ba0180f1" || b.ProbeCount != 1 || p.Domain != "app-notify" || p.ControllerBinding == nil || p.HPAExecutionBinding == nil || p.AssessmentBinding == nil || p.HPAExecutionBinding.Mode != capacity.HPALifetimeExecutionMode || b.Adapter != p.AssessmentBinding.Snapshot.Adapter || b.NativeNamespace != p.AssessmentBinding.Snapshot.Namespace || b.NativeBindingName != p.HPAExecutionBinding.PodTerminationBinding || !name.MatchString(b.NativeBindingName) || !name.MatchString(b.PrivateBindingName) || len(b.Participants) < 2 || len(b.Participants) > 8 || b.ControlKeyRef == b.ReadKeyRef {
		return refuse()
	}
	authority, err := url.Parse(b.CoreAuthorityURL)
	if err != nil || authority.Scheme != "https" || authority.Host == "" || authority.User != nil || authority.Path != "/capacity/native/canary-authority" || authority.RawPath != "" || authority.RawQuery != "" || authority.ForceQuery || authority.Fragment != "" || len(b.CoreAuthorityURL) > 2048 {
		return refuse()
	}
	for _, secret := range []string{b.ControlKeyRef, b.ReadKeyRef} {
		if !strings.HasPrefix(secret, "secret://"+p.Workflow.Namespace+"/") || len(secret) > 2048 || !strings.HasSuffix(secret, "#value") || strings.ContainsAny(secret, "\x00\r\n") {
			return refuse()
		}
	}
	seen := map[string]bool{}
	seenOrigins := map[string]bool{}
	publishers, consumers := 0, 0
	for _, selected := range b.Participants {
		u, err := url.Parse(selected.Origin)
		if err != nil || !name.MatchString(selected.PodName) || seen[selected.PodName] || seenOrigins[selected.Origin] || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || len(selected.Origin) > 2048 {
			return refuse()
		}
		seen[selected.PodName] = true
		seenOrigins[selected.Origin] = true
		switch selected.Role {
		case "publisher_reader":
			publishers++
		case "consumer":
			consumers++
		default:
			return refuse()
		}
	}
	if publishers != 1 || consumers != len(b.Participants)-1 {
		return refuse()
	}
	return validateNativeNotifyResourceRoster(b)
}

func validateNativeReleaseRecoveryJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("capacity policy object required")
	}
	type member struct {
		name string
		raw  json.RawMessage
	}
	var hpas []member
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok {
			return fmt.Errorf("capacity policy member required")
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return fmt.Errorf("capacity policy value required")
		}
		if strings.EqualFold(name, "hpa_execution_binding") {
			hpas = append(hpas, member{name, value})
		}
	}
	for _, hpa := range hpas {
		var fields map[string]json.RawMessage
		if json.Unmarshal(hpa.raw, &fields) != nil {
			continue
		}
		for name, value := range fields {
			if !strings.EqualFold(name, "release_recovery") {
				continue
			}
			if len(hpas) != 1 || hpa.name != "hpa_execution_binding" || name != "release_recovery" || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return fmt.Errorf("canonical nonnull release recovery binding required")
			}
			var binding model.CapacityHPAExecutionBinding
			if capacity.DecodeNativeCapacity(hpa.raw, &binding) != nil || binding.ReleaseRecovery == nil {
				return fmt.Errorf("closed release recovery binding required")
			}
		}
	}
	return nil
}
