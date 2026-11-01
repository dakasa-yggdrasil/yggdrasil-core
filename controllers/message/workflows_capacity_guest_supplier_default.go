//go:build !labqualification && !nativequalification

package message

import "github.com/dakasa-yggdrasil/yggdrasil-core/model"

func labOriginalGuestSupplierApproved(string, string, model.Manifest, model.Manifest, model.IntegrationTypeManifestSpec) bool {
	return false
}
