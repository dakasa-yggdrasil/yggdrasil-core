//go:build nativequalification

package capacity

import "github.com/dakasa-yggdrasil/yggdrasil-core/model"

// ApprovedHostFactorySource requires a reviewed actual CODE/PUB/build/approval tuple.
// The compiled registry is EMPTY. Nativequalification is not an approval source.
func ApprovedHostFactorySource() (model.HostFactorySourceApproval, error) {
	return model.HostFactorySourceApproval{}, ErrHostFactorySourceUnavailable
}
