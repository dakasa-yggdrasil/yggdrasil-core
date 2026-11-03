//go:build !linux || !nativequalification

package httpapi

import (
	"context"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"net/http"
)

func guestQualificationRegistrationClock(context.Context, repository.CapacityStore, string, string, string, *http.Request) (any, error) {
	return nil, repository.ErrCapacityMutationAuthorization
}
