package capacity

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const HPAExecutionMode = "native_hpa_cas_v1"
const HPALifetimeExecutionMode = "native_hpa_lifetime_v2"
const EnsureBoundHPAEnvelope = "ensure_capacity_envelope_bound"
const ObserveNativePodInventory = "observe_capacity_pod_inventory"
const ObserveNativePodAdmission = "observe_capacity_pod_admission"
const ObserveNativePodAdmissionCandidates = "observe_capacity_pod_admission_candidates"
const ObserveCurrentBirthGuard = "observe_current_birth_guard"
const EnsureNativePodDrain = "ensure_capacity_pod_drain"
const ObserveNativePodTermination = "observe_capacity_pod_termination"
const DestroyNativePodProtection = "destroy_capacity_pod_drain_protection"

var nativeLanePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var lowerSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)

func ValidateHPAExecutionBinding(p model.CapacityPolicySpec) error {
	binding := p.HPAExecutionBinding
	if binding == nil {
		return nil
	}
	if p.AssessmentBinding == nil || (binding.Mode != HPAExecutionMode && binding.Mode != HPALifetimeExecutionMode) || len(p.MutationBindings) != 0 || p.Dimension != ReservedPodEnvelopeUnit || !filepath.IsAbs(binding.ProjectionDirectory) || filepath.Clean(binding.ProjectionDirectory) != binding.ProjectionDirectory || strings.Contains(binding.ProjectionDirectory, "..") {
		return fmt.Errorf("native HPA executor requires exact reserved envelope and native projection binding")
	}
	if binding.Mode == HPALifetimeExecutionMode && (binding.AdmissionMode != "process_v2" || binding.AdmissionPort < 1 || binding.AdmissionPort > 65535) {
		return fmt.Errorf("native lifetime execution requires current process admission and one fixed Pod proxy port")
	}
	if binding.Mode == HPALifetimeExecutionMode && p.ExecutionEnabled && (binding.BirthGuardBinding == "" || len(binding.BirthGuardBinding) > 128 || strings.TrimSpace(binding.BirthGuardBinding) != binding.BirthGuardBinding || strings.ContainsAny(binding.BirthGuardBinding, "/\r\n\t") || !lowerSHA.MatchString(binding.BirthGuardSHA256)) {
		return fmt.Errorf("native lifetime execution requires a fixed current installed birth guard binding")
	}
	if binding.Mode == HPALifetimeExecutionMode && (binding.AdmissionWorkflow.Namespace == "" || binding.AdmissionWorkflow.Name == "" || binding.AdmissionWorkflow.ManifestID != "" || binding.AdmissionWorkflow.Version != nil || (binding.AdmissionWorkflow.Namespace == p.Workflow.Namespace && binding.AdmissionWorkflow.Name == p.Workflow.Name)) {
		return fmt.Errorf("native admission requires a separate fixed protected logical workflow")
	}
	for _, name := range []string{binding.AdapterPrincipalID, binding.PodTerminationBinding, binding.ContainerName} {
		if name == "" || len(name) > 128 || strings.TrimSpace(name) != name || strings.ContainsAny(name, "/\r\n\t") {
			return fmt.Errorf("native HPA executor requires exact bounded Pod/container bindings")
		}
	}
	if len(binding.ImageDigest) != 71 || !strings.HasPrefix(binding.ImageDigest, "sha256:") || strings.ToLower(binding.ImageDigest) != binding.ImageDigest {
		return fmt.Errorf("native HPA executor requires immutable image digest")
	}
	if _, err := hex.DecodeString(binding.ImageDigest[7:]); err != nil {
		return fmt.Errorf("native HPA executor requires immutable image digest")
	}
	if len(binding.Lanes) == 0 || len(binding.Lanes) > 64 {
		return fmt.Errorf("native HPA executor requires complete bounded local lane roster")
	}
	seen := map[string]bool{}
	for _, name := range binding.Lanes {
		if !nativeLanePattern.MatchString(name) || seen[name] {
			return fmt.Errorf("native HPA executor requires unique canonical lane names")
		}
		seen[name] = true
	}
	return nil
}
