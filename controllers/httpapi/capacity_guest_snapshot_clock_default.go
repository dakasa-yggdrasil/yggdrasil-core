//go:build !linux || !nativequalification

package httpapi

import (
	"context"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"net/http"
)

func guestQualificationBeforeSnapshotGET(context.Context, repository.GuestOriginalAuthorityRead) error {
	return nil
}

func guestQualificationSnapshotFailure(http.ResponseWriter, repository.GuestOriginalAuthorityRead, string) {
}
