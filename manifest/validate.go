package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// NormalizeDocument trims and defaults a manifest document before validation/persistence.
func NormalizeDocument(doc model.ManifestDocument) model.ManifestDocument {
	doc.APIVersion = strings.TrimSpace(doc.APIVersion)
	doc.Kind = strings.ToLower(strings.TrimSpace(doc.Kind))
	doc.Metadata.Name = strings.ToLower(strings.TrimSpace(doc.Metadata.Name))

	namespace := strings.ToLower(strings.TrimSpace(doc.Metadata.Namespace))
	if namespace == "" {
		namespace = "global"
	}
	doc.Metadata.Namespace = namespace

	if doc.Metadata.Labels == nil {
		doc.Metadata.Labels = map[string]string{}
	}

	if doc.Metadata.Active == nil {
		active := true
		doc.Metadata.Active = &active
	}

	return doc
}

// DocumentActive resolves the input active flag with the default value.
func DocumentActive(doc model.ManifestDocument) bool {
	if doc.Metadata.Active == nil {
		return true
	}
	return *doc.Metadata.Active
}

// ValidateDocument validates a manifest envelope and delegates kind-specific checks.
func ValidateDocument(doc model.ManifestDocument) error {
	doc = NormalizeDocument(doc)

	if doc.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if doc.Kind == "" {
		return fmt.Errorf("kind is required")
	}
	if doc.Metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}
	if len(doc.Spec) == 0 {
		return fmt.Errorf("spec is required")
	}

	switch doc.Kind {
	case "rbac":
		spec, err := ParseRBACSpec(doc.Spec)
		if err != nil {
			return err
		}
		return ValidateRBACSpec(spec)
	case "policy":
		spec, err := ParsePolicySpec(doc.Spec)
		if err != nil {
			return err
		}
		return ValidatePolicySpec(spec)
	case "integration_family":
		spec, err := ParseIntegrationFamilySpec(doc.Spec)
		if err != nil {
			return err
		}
		return ValidateIntegrationFamilySpec(spec)
	case "integration_quickstart":
		spec, err := ParseIntegrationQuickstartSpec(doc.Spec)
		if err != nil {
			return err
		}
		return ValidateIntegrationQuickstartSpec(spec)
	case "integration_type":
		spec, err := ParseIntegrationTypeSpec(doc.Spec)
		if err != nil {
			return err
		}
		return ValidateIntegrationTypeSpec(spec)
	case "integration_instance":
		spec, err := ParseIntegrationInstanceSpec(doc.Spec)
		if err != nil {
			return err
		}
		return ValidateIntegrationInstanceSpec(spec)
	case "resource":
		spec, err := ParseResourceSpec(doc.Spec)
		if err != nil {
			return err
		}
		return ValidateResourceSpec(spec)
	case "surface":
		spec, err := ParseSurfaceSpec(doc.Spec)
		if err != nil {
			return err
		}
		return ValidateSurfaceSpec(spec)
	case "repository_binding":
		spec, err := ParseRepositoryBindingSpec(doc.Spec)
		if err != nil {
			return err
		}
		return ValidateRepositoryBindingSpec(spec)
	case "guardian_policy":
		spec, err := ParseGuardianPolicySpec(doc.Spec)
		if err != nil {
			return err
		}
		return ValidateGuardianPolicySpec(spec)
	case "guardian_approval":
		spec, err := ParseGuardianApprovalSpec(doc.Spec)
		if err != nil {
			return err
		}
		return ValidateGuardianApprovalSpec(spec)
	case "guardian_memory":
		spec, err := ParseGuardianMemorySpec(doc.Spec)
		if err != nil {
			return err
		}
		return ValidateGuardianMemorySpec(spec)
	case "remediation_bundle":
		spec, err := ParseRemediationBundleSpec(doc.Spec)
		if err != nil {
			return err
		}
		return ValidateRemediationBundleSpec(spec)
	case "remediation_contract":
		spec, err := ParseRemediationContractSpec(doc.Spec)
		if err != nil {
			return err
		}
		return ValidateRemediationContractSpec(spec)
	case "product":
		spec, err := ParseProductSpec(doc.Spec)
		if err != nil {
			return err
		}
		return ValidateProductSpec(spec)
	case "workflow":
		spec, err := ParseWorkflowSpec(doc.Spec)
		if err != nil {
			return err
		}
		return ValidateWorkflowSpec(spec)
	default:
		return fmt.Errorf("unsupported manifest kind: %s", doc.Kind)
	}
}

// Checksum produces a deterministic hash for the normalized manifest.
func Checksum(doc model.ManifestDocument) (string, error) {
	doc = NormalizeDocument(doc)

	payload := struct {
		APIVersion string                 `json:"apiVersion"`
		Kind       string                 `json:"kind"`
		Metadata   model.ManifestMetadata `json:"metadata"`
		Spec       json.RawMessage        `json:"spec"`
	}{
		APIVersion: doc.APIVersion,
		Kind:       doc.Kind,
		Metadata: model.ManifestMetadata{
			Name:        doc.Metadata.Name,
			Namespace:   doc.Metadata.Namespace,
			Description: strings.TrimSpace(doc.Metadata.Description),
			Labels:      doc.Metadata.Labels,
			Active:      DocumentActive(doc),
		},
		Spec: doc.Spec,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
