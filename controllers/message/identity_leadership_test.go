package message

import (
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"testing"
)

func TestIdentityLeadershipErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{
		{repository.ErrLeadershipAssertionRequired, "leadership_assertion_required"},
		{repository.ErrLeadershipVersionConflict, "leadership_version_conflict"},
		{repository.ErrTeamNotFound, "not_found"},
	} {
		if got := identityErrorCode(fmt.Errorf("writer: %w", tc.err)); got != tc.code {
			t.Fatalf("code=%s want=%s", got, tc.code)
		}
	}
}
