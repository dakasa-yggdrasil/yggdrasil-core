//go:build !linux && capacitytest && nativequalification

package main

import (
	"context"
	"database/sql"
)

// The source-owned HTTP qualification imports Linux-only Core runtime code.
// A non-Linux fixture must explicitly report that it did not run this case.
func syntheticHTTPCallbacks(context.Context, *sql.DB, string) (bool, error) {
	return false, nil
}
