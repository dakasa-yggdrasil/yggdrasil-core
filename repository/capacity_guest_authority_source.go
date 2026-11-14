//go:build !recoveryfixture || nativequalification

package repository

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// The production and native qualification issuer always is the actual build.
func guestAuthorityIssueSource(_ CapacityStore, _ model.Manifest, _ string) string {
	return capacity.CurrentGuestCoreSource()
}
