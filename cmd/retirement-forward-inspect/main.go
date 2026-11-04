// Command retirement-forward-inspect is a rollback-only diagnostic companion.
// It does not start Core, addons, migrations, provider clients or Guest clients.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/psql"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func privateJSON(path, digest string, target any) bool {
	if !capacity.ValidDigest(digest) {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 2 || info.Size() > 4096 {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	finished, statErr := f.Stat()
	if err != nil || statErr != nil || len(raw) != int(info.Size()) || opened.Size() != finished.Size() || !opened.ModTime().Equal(finished.ModTime()) || capacity.BusinessCreationSHA256(raw) != digest {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(target) == nil && d.Decode(new(any)) == io.EOF
}

func run(args []string) int {
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Second)
	defer stop()
	flags := flag.NewFlagSet("retirement-forward-inspect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	requestPath := flags.String("request", "", "private original seven-field request")
	requestSHA := flags.String("request-sha256", "", "SHA256 of original request bytes")
	barrierPath := flags.String("barrier", "", "private original inspected Core barrier")
	barrierSHA := flags.String("barrier-sha256", "", "SHA256 of original barrier bytes")
	operator := flags.String("operator", "", "actual human collaborator UUID")
	runtimeSource := flags.String("runtime-source", "", "actual inspected Core source; not diagnostic identity")
	build := flags.String("expected-build-source", "", "qualified diagnostic build source")
	report := repository.GuestRetirementForwardInspection{Schema: "guest_retirement_forward_readonly_inspection_v1", DiagnosticSource: capacity.CurrentGuestCoreSource(), Stage: "cli_inputs", FailureClass: "invalid_inputs"}
	defer func() { _ = json.NewEncoder(os.Stdout).Encode(report) }()
	if flags.Parse(args) != nil || flags.NArg() != 0 || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(*build) || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(*runtimeSource) || !capacity.ValidDigest(*requestSHA) || !capacity.ValidDigest(*barrierSHA) || report.DiagnosticSource != *build {
		return 30
	}
	report.RequestSHA256, report.BarrierSHA256 = *requestSHA, *barrierSHA
	report.InspectedCoreSource = *runtimeSource
	var request model.CapacityGuestRetirementForwardRequest
	var barrier repository.CapacityDispatchExecutorBarrier
	if !privateJSON(*requestPath, *requestSHA, &request) || !privateJSON(*barrierPath, *barrierSHA, &barrier) {
		return 30
	}
	// Reuse Core's existing RAM-only DB configuration. No DSN or DB error text
	// is logged, and no service/addon initializer is imported or started.
	if psql.LoadConfig().Name != "yggdrasil" {
		report.Stage = "database_config"
		return 30
	}
	db, err := psql.Open()
	if err != nil {
		report.Stage, report.FailureClass = "database_open", "database_unavailable"
		return 30
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	report = (repository.CapacityStore{DB: db}).InspectGuestRetirementForwardHistorical(ctx, request, *operator, barrier, *runtimeSource, "yggdrasil")
	report.RequestSHA256, report.BarrierSHA256 = *requestSHA, *barrierSHA
	if !report.ReadChecksPassed || !report.RolledBack {
		return 30
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:])) }
