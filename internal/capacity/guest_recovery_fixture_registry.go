//go:build recoveryfixture && !nativequalification

package capacity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// RegisterRecoveryFixtureApproval exists only in the explicitly tagged test
// binary. It alters fixture approval data and proves no production authority.
// The default and native qualification builds do not compile this function.
func RegisterRecoveryFixtureApproval(p model.CapacityPolicySpec, binding model.CapacityGuestRetirementBinding, provider string) error {
	if !strings.HasSuffix(filepath.Base(os.Args[0]), ".test") || os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" {
		return fmt.Errorf("recovery fixture is test-only")
	}
	contract := GuestProductionProfileContractSHA256(p, binding, provider)
	catalog := binding.ProfileManifest.ProductionCatalogSHA256
	if !ValidDigest(contract) || !ValidDigest(catalog) {
		return fmt.Errorf("fixture binding invalid")
	}
	guestProductionProfileApprovals = append(guestProductionProfileApprovals, guestProductionProfileApproval{Provider: provider, Profile: binding.ProfileManifest.Profile, ProductionCatalogSHA256: catalog, ContractSHA256: contract})
	return nil
}

// RecoveryFixtureApprovalScope restores exactly the pre-test registry. Tests
// using this process-scoped registry must be sequential and tagged explicitly.
func RecoveryFixtureApprovalScope(t *testing.T) {
	t.Helper()
	if !strings.HasSuffix(filepath.Base(os.Args[0]), ".test") || os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" {
		t.Fatal("recovery fixture is test-only")
	}
	before := append([]guestProductionProfileApproval(nil), guestProductionProfileApprovals...)
	t.Cleanup(func() { guestProductionProfileApprovals = before })
}
