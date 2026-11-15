//go:build linux && nativequalification

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"path/filepath"
	"regexp"

	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
)

const originalRetirementFailureDispositionSchema = "core_original_retirement_failure_export_disposition_v1"

// Closed diagnostic metadata only: no raw SQL, error, identifiers or bodies.
type originalRetirementFailureDisposition struct {
	Schema                  string `json:"schema"`
	Status                  string `json:"status"`
	Matches                 int    `json:"matches"`
	CallerProjectionPresent bool   `json:"caller_projection_present"`
	ErrorClass              string `json:"error_class"`
	SQLState                string `json:"sqlstate"`
	Stage                   string `json:"stage"`
}

func (d *originalRetirementFailureDisposition) setError(err error) {
	d.ErrorClass, d.SQLState = "other", ""
	switch {
	case err == nil:
		d.ErrorClass = "none"
	case errors.Is(err, context.Canceled):
		d.ErrorClass = "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		d.ErrorClass = "deadline"
	case errors.Is(err, sql.ErrNoRows):
		d.ErrorClass = "sql_no_rows"
	default:
		var state interface{ SQLState() string }
		if errors.As(err, &state) {
			if value := state.SQLState(); regexp.MustCompile(`^[0-9A-Z]{5}$`).MatchString(value) {
				d.ErrorClass, d.SQLState = "sqlstate", value
			}
		}
	}
}

func (f *fixture) publishOriginalRetirementFailureDisposition(ctx context.Context, d originalRetirementFailureDisposition) {
	if f != nil && f.private != "" && ctx != nil {
		if _, err := q.Publish(ctx, filepath.Join(f.private, "core-original-retirement-failure-export-disposition.json"), d); err != nil {
			d.Status, d.Stage = "not_exported", "publish"
			d.setError(err)
		}
	}
	// A failed diagnostic publication remains visible without extending the
	// same five-second context or replacing the original run error.
	wire, err := json.Marshal(d)
	if err == nil {
		log.Printf("%s %s", originalRetirementFailureDispositionSchema, wire)
	}
}
