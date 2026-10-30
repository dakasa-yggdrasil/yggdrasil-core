//go:build linux && nativequalification

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func TestHeldAckOriginalTransportDiagnostic(t *testing.T) {
	for _, mode := range []string{"retained", "missing", "foreign_digest", "duplicate", "other_case", "successful_retirement", "unknown_scope"} {
		t.Run(mode, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			original := repository.GuestOriginalCallerReturn{
				Status: 0, DoFailed: true, OriginalContextFailed: true,
				ResponseBodyScope: capacity.GuestOriginalBodyNoRead, Body: []byte("private-never-export"),
			}
			if mode == "unknown_scope" {
				original.ResponseBodyScope = "private-never-export"
			}
			raw, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			digest := capacity.BusinessCreationSHA256(raw)
			if mode == "foreign_digest" {
				digest = strings.Repeat("0", 64)
			}
			if mode != "other_case" && mode != "successful_retirement" {
				rows := sqlmock.NewRows([]string{"original_wire", "return_sha256"})
				if mode != "missing" {
					rows.AddRow(raw, digest)
				}
				if mode == "duplicate" {
					rows.AddRow(raw, digest)
				}
				mock.ExpectQuery("SELECT c.original_wire,c.return_sha256").WithArgs("prereg-original").WillReturnRows(rows)
			}
			f := &fixture{db: db, private: t.TempDir()}
			f.request.NativeCase = "held_ack_after_owned_original_deadline"
			if mode == "other_case" {
				f.request.NativeCase = "positive_original_lifecycle"
			}
			status := "failed"
			if mode == "successful_retirement" {
				status = "succeeded"
			}
			f.retainHeldAckTransportDiagnostic(context.Background(), "prereg-original", status)
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
			rawOutput, readErr := os.ReadFile(filepath.Join(f.private, "core-held-ack-transport-diagnostic.json"))
			if mode != "retained" {
				if !os.IsNotExist(readErr) {
					t.Fatalf("diagnostic was retained without one bound original: %v", readErr)
				}
				return
			}
			if readErr != nil {
				t.Fatal(readErr)
			}
			var got heldAckTransportDiagnostic
			if err := json.Unmarshal(rawOutput, &got); err != nil || got.OriginalReturnSHA256 != digest || !got.DoFailed || !got.OriginalContextFailed || got.Status != 0 {
				t.Fatalf("original flags not projected: %v", err)
			}
			if strings.Contains(string(rawOutput), "private-never-export") || strings.Contains(string(rawOutput), "cHJpdmF0ZS1uZXZlci1leHBvcnQ") {
				t.Fatal("private body was projected")
			}
		})
	}
}
