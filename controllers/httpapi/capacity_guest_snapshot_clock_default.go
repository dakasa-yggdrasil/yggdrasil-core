//go:build !linux || !nativequalification

package httpapi

import (
	"context"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func guestQualificationBeforeSnapshotGET(context.Context, repository.GuestOriginalAuthorityRead) error {
	return nil
}
