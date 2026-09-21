package httpapi

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"time"
)

// Directory machine principals (ADR-0019) are hashed service credentials that
// may read exactly three collaborator routes with a minimal projection. They
// reuse the digest, lifecycle, and rotation validation of the workflow and
// event principals (ADR-0017) but form an independent inventory: a directory
// credential never dispatches workflows, publishes events, or reaches any
// console, catalog, secret, or mutation route.
const (
	directoryMachinePrincipalsEnv = "YGGDRASIL_DIRECTORY_MACHINE_PRINCIPALS_JSON"
	directoryMachineTokenHeader   = "X-Yggdrasil-Directory-Token"

	directoryCapabilityLookupEmail      = "directory.lookup_email"
	directoryCapabilityRead             = "directory.read"
	directoryCapabilityEffectiveActions = "directory.effective_actions"
)

// tartaroInstanceRef names one Tartaro integration instance by its exact
// manifest namespace and name, the same pair team grants are keyed on.
type tartaroInstanceRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type directoryMachinePrincipalConfig struct {
	PrincipalID             string               `json:"principal_id"`
	Status                  string               `json:"status"`
	ExpiresAt               time.Time            `json:"expires_at"`
	RotationID              string               `json:"rotation_id"`
	RotatedAt               time.Time            `json:"rotated_at"`
	TokenSHA256             string               `json:"token_sha256"`
	Capabilities            []string             `json:"capabilities"`
	AllowedTartaroInstances []tartaroInstanceRef `json:"allowed_tartaro_instances"`
}

type directoryMachinePrincipal struct {
	PrincipalID             string
	Status                  string
	ExpiresAt               time.Time
	RotationID              string
	RotatedAt               time.Time
	TokenSHA256             [sha256.Size]byte
	Capabilities            map[string]struct{}
	AllowedTartaroInstances map[tartaroInstanceRef]struct{}
}

func knownDirectoryCapability(name string) bool {
	switch name {
	case directoryCapabilityLookupEmail, directoryCapabilityRead, directoryCapabilityEffectiveActions:
		return true
	default:
		return false
	}
}

// directoryMachinePrincipalsFromEnv loads the directory inventory. Like the
// workflow loader it accepts only digests plus authorization metadata, and any
// malformed entry rejects the whole inventory so a typo cannot silently widen
// or drop a scope.
func directoryMachinePrincipalsFromEnv() ([]directoryMachinePrincipal, error) {
	rawConfigured := strings.TrimSpace(os.Getenv(directoryMachinePrincipalsEnv)) != ""
	var configs []directoryMachinePrincipalConfig
	if err := decodeMachinePrincipalConfig(directoryMachinePrincipalsEnv, &configs); err != nil {
		return nil, err
	}
	if configs == nil {
		if rawConfigured {
			return nil, fmt.Errorf("%s must be a non-empty JSON array", directoryMachinePrincipalsEnv)
		}
		return nil, nil
	}
	if len(configs) == 0 {
		return nil, fmt.Errorf("%s must contain at least one principal when configured", directoryMachinePrincipalsEnv)
	}

	principals := make([]directoryMachinePrincipal, 0, len(configs))
	seenIDs := make(map[string]struct{}, len(configs))
	seenHashes := make(map[[sha256.Size]byte]struct{}, len(configs))
	for index, config := range configs {
		base, err := validateMachinePrincipalBase(
			directoryMachinePrincipalsEnv,
			index,
			config.PrincipalID,
			config.Status,
			config.ExpiresAt,
			config.RotationID,
			config.RotatedAt,
			config.TokenSHA256,
		)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seenIDs[base.principalID]; duplicate {
			return nil, fmt.Errorf("%s entry %d duplicates principal_id", directoryMachinePrincipalsEnv, index)
		}
		if _, duplicate := seenHashes[base.tokenSHA256]; duplicate {
			return nil, fmt.Errorf("%s entry %d duplicates a credential digest", directoryMachinePrincipalsEnv, index)
		}

		if len(config.Capabilities) == 0 {
			return nil, fmt.Errorf("%s entry %d requires at least one capability", directoryMachinePrincipalsEnv, index)
		}
		capabilities := make(map[string]struct{}, len(config.Capabilities))
		for capabilityIndex, capability := range config.Capabilities {
			capability = strings.TrimSpace(capability)
			if !knownDirectoryCapability(capability) {
				return nil, fmt.Errorf("%s entry %d capabilities item %d must be one of %s, %s, %s",
					directoryMachinePrincipalsEnv, index, capabilityIndex,
					directoryCapabilityLookupEmail, directoryCapabilityRead, directoryCapabilityEffectiveActions)
			}
			if _, duplicate := capabilities[capability]; duplicate {
				return nil, fmt.Errorf("%s entry %d duplicates a capabilities item", directoryMachinePrincipalsEnv, index)
			}
			capabilities[capability] = struct{}{}
		}

		_, wantsEffectiveActions := capabilities[directoryCapabilityEffectiveActions]
		if wantsEffectiveActions && len(config.AllowedTartaroInstances) == 0 {
			return nil, fmt.Errorf("%s entry %d requires at least one exact allowed_tartaro_instances item for %s",
				directoryMachinePrincipalsEnv, index, directoryCapabilityEffectiveActions)
		}
		if !wantsEffectiveActions && len(config.AllowedTartaroInstances) > 0 {
			return nil, fmt.Errorf("%s entry %d allowed_tartaro_instances requires the %s capability",
				directoryMachinePrincipalsEnv, index, directoryCapabilityEffectiveActions)
		}
		instances := make(map[tartaroInstanceRef]struct{}, len(config.AllowedTartaroInstances))
		for instanceIndex, instance := range config.AllowedTartaroInstances {
			instance.Namespace = strings.TrimSpace(instance.Namespace)
			instance.Name = strings.TrimSpace(instance.Name)
			if instance.Namespace == "" || instance.Name == "" {
				return nil, fmt.Errorf("%s entry %d allowed_tartaro_instances item %d requires namespace and name",
					directoryMachinePrincipalsEnv, index, instanceIndex)
			}
			if containsWildcard(instance.Namespace) || containsWildcard(instance.Name) {
				return nil, fmt.Errorf("%s entry %d allowed_tartaro_instances item %d must be exact and cannot contain wildcards",
					directoryMachinePrincipalsEnv, index, instanceIndex)
			}
			if _, duplicate := instances[instance]; duplicate {
				return nil, fmt.Errorf("%s entry %d duplicates an allowed_tartaro_instances item", directoryMachinePrincipalsEnv, index)
			}
			instances[instance] = struct{}{}
		}

		principals = append(principals, directoryMachinePrincipal{
			PrincipalID:             base.principalID,
			Status:                  base.status,
			ExpiresAt:               base.expiresAt,
			RotationID:              base.rotationID,
			RotatedAt:               base.rotatedAt,
			TokenSHA256:             base.tokenSHA256,
			Capabilities:            capabilities,
			AllowedTartaroInstances: instances,
		})
		seenIDs[base.principalID] = struct{}{}
		seenHashes[base.tokenSHA256] = struct{}{}
	}
	return principals, nil
}

// directoryMachinePrincipalByCredential returns the principal whose digest
// matches the candidate regardless of lifecycle state. Matching in any state
// lets the gate recognize an expired or revoked directory credential and
// refuse it outright instead of letting it continue to human authentication.
func directoryMachinePrincipalByCredential(candidate string, principals []directoryMachinePrincipal) *directoryMachinePrincipal {
	var matched *directoryMachinePrincipal
	for index := range principals {
		principal := &principals[index]
		if machineCredentialMatches(candidate, principal.TokenSHA256) {
			matched = principal
		}
	}
	return matched
}

// directoryMachinePrincipalUsable reports whether the principal may act now
// and, when it may not, the audit reason.
func directoryMachinePrincipalUsable(principal *directoryMachinePrincipal, now time.Time) (bool, string) {
	if principal == nil {
		return false, "credential_unknown"
	}
	if principal.Status != "active" {
		return false, "status_" + principal.Status
	}
	if !now.Before(principal.ExpiresAt) {
		return false, "expired"
	}
	return true, ""
}

func directoryMachinePrincipalHasCapability(principal *directoryMachinePrincipal, capability string) bool {
	if principal == nil {
		return false
	}
	_, ok := principal.Capabilities[capability]
	return ok
}

func directoryMachinePrincipalAllowsTartaroInstance(principal *directoryMachinePrincipal, namespace, name string) bool {
	if principal == nil {
		return false
	}
	_, ok := principal.AllowedTartaroInstances[tartaroInstanceRef{
		Namespace: strings.TrimSpace(namespace),
		Name:      strings.TrimSpace(name),
	}]
	return ok
}
