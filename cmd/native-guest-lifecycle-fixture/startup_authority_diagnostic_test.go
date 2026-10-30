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
)

func TestStartupAuthorityDiagnostic(t *testing.T) {
	for _, mode := range []string{"recorded", "missing_read", "missing_transport", "wrong_digest", "multiple_reads", "other_case", "success"} {
		t.Run(mode, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			v := map[string]any{"read_id": "read-1", "native_stage": "snapshot", "status": 200, "response_body_scope": "complete_original_body_read", "preflight_failed": false, "do_failed": false, "read_failed": false, "close_failed": false, "original_context_failed": false, "private_body": "NEVER_PROJECT_PRIVATE"}
			raw, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			digest := capacity.BusinessCreationSHA256(raw)
			if mode == "wrong_digest" {
				digest = strings.Repeat("0", 64)
			}
			if mode != "other_case" && mode != "success" {
				rows := sqlmock.NewRows([]string{"id", "challenge", "snapshot", "authority"})
				if mode != "missing_read" {
					rows.AddRow("read-1", true, false, false)
				}
				if mode == "multiple_reads" {
					rows.AddRow("read-2", true, true, true)
				}
				mock.ExpectQuery("SELECT r.id::text").WithArgs("prereg-original").WillReturnRows(rows)
				if mode != "missing_read" && mode != "multiple_reads" {
					for _, stage := range []string{"snapshot", "journal"} {
						transport := sqlmock.NewRows([]string{"original_wire", "return_sha256"})
						if stage == "snapshot" && mode != "missing_transport" {
							transport.AddRow(raw, digest)
						}
						mock.ExpectQuery("SELECT original_wire,return_sha256").WithArgs("read-1", stage).WillReturnRows(transport)
					}
				}
			}
			f := &fixture{db: db, private: t.TempDir()}
			f.request.NativeCase = "actor_startup_delay_positive"
			if mode == "recorded" || mode == "wrong_digest" {
				f.request.NativeCase = "positive_original_lifecycle"
			}
			status := "failed"
			if mode == "other_case" {
				f.request.NativeCase = "held_hello_original_deadline"
			}
			if mode == "success" {
				status = "succeeded"
			}
			f.retainStartupAuthorityDiagnostic(context.Background(), "prereg-original", status)
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
			output, err := os.ReadFile(filepath.Join(f.private, "core-startup-authority-diagnostic.json"))
			if mode == "other_case" || mode == "success" || mode == "multiple_reads" {
				if !os.IsNotExist(err) {
					t.Fatalf("unexpected retained diagnostic %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(output), "NEVER_PROJECT_PRIVATE") || strings.Contains(string(output), "read-1") {
				t.Fatal("private data projected")
			}
			var fact struct {
				Scope     string               `json:"scope"`
				ReadState string               `json:"read_state"`
				Snapshot  startupTransportFact `json:"snapshot"`
				Journal   startupTransportFact `json:"journal"`
			}
			if json.Unmarshal(output, &fact) != nil {
				t.Fatal("invalid closed JSON")
			}
			if fact.Scope != "historical_nonatomic_source_observation_only_not_authority" {
				t.Fatal("observation atomicity scope missing")
			}
			if mode == "missing_read" {
				if fact.ReadState != "NOT_OBSERVED_UNKNOWN" {
					t.Fatal("missing read was not unknown")
				}
				return
			}
			if fact.ReadState != "OBSERVED" || fact.Journal.State != "NOT_OBSERVED_UNKNOWN" {
				t.Fatal("scope not retained")
			}
			if mode == "recorded" && (fact.Snapshot.State != "RECORDED_ORIGINAL_RETURN" || fact.Snapshot.Status == nil || *fact.Snapshot.Status != 200) {
				t.Fatal("recorded facts missing")
			}
			if mode == "wrong_digest" && fact.Snapshot.State != "UNKNOWN" {
				t.Fatal("foreign digest accepted")
			}
			if mode == "missing_transport" && fact.Snapshot.State != "NOT_OBSERVED_UNKNOWN" {
				t.Fatal("absent transport not unknown")
			}
		})
	}
}
