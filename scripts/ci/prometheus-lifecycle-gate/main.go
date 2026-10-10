//go:build linux

// This CI-only command owns one fixed collector test process. Its report is
// observation data; only its actual successful exit qualifies the gate.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	collectorCommit  = "f8f7da808af78e252c0c389cb48ce73a973b49e1"
	collectorModule  = "github.com/dakasa-yggdrasil/integration-prometheus"
	collectorPackage = collectorModule + "/internal/adapter"
	collectorRoot    = "TestRangeEvidenceActualTLSReadCloseAndPostReturnFence"
	maxRawBytes      = 4 << 20
	commandBudget    = 3 * time.Minute
)

var collectorCases = [...]string{
	"on-time", "first-close-error", "second-close-error",
	"first-deadline-after-read", "second-deadline-after-read",
	"earlier-parent-deadline", "first-parent-canceled-after-read",
	"second-parent-canceled-after-read", "read-close-parent-causes",
	"read-close-deadline-causes",
}

func contextFailure(ctx context.Context) error {
	if ctx == nil {
		return errors.New("gate context missing")
	}
	err := ctx.Err()
	if deadline, known := ctx.Deadline(); known && !time.Now().Before(deadline) {
		err = errors.Join(err, context.DeadlineExceeded)
	}
	return err
}

// Named buffers avoid promoting ReadFrom and bypassing the combined cap when
// os/exec copies the original pipes. Overflow still drains, but never qualifies.
type rawCapture struct {
	mu       sync.Mutex
	out      bytes.Buffer
	err      bytes.Buffer
	seen     uint64
	used     int
	overflow bool
}

type captureWriter struct {
	capture *rawCapture
	stderr  bool
}

func (w captureWriter) Write(p []byte) (int, error) {
	c := w.capture
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen += uint64(len(p))
	keep := len(p)
	if keep > maxRawBytes-c.used {
		keep, c.overflow = maxRawBytes-c.used, true
	}
	buffer := &c.out
	if w.stderr {
		buffer = &c.err
	}
	_, _ = buffer.Write(p[:keep])
	c.used += keep
	return len(p), nil
}

func (c *rawCapture) snapshot() ([]byte, []byte, uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.out.Bytes()...), append([]byte(nil), c.err.Bytes()...), c.seen, c.overflow
}

type processObservation struct {
	Started              bool   `json:"started"`
	PID                  int    `json:"pid"`
	ArgvSHA256           string `json:"argv_sha256"`
	WaitReturned         bool   `json:"wait_returned"`
	Exited               bool   `json:"exited"`
	ExitCode             int    `json:"exit_code"`
	GroupCancelAttempted bool   `json:"group_cancel_attempted"`
	GroupCancelSucceeded bool   `json:"group_cancel_succeeded"`
	RawBytes             uint64 `json:"raw_bytes_observed"`
	Overflow             bool   `json:"overflow"`
}

// Callers are source-owned only: fixed git observations and the fixed go test.
// Tests use this private seam for real subprocess/pipe failures, never evidence.
func observeCommand(ctx context.Context, dir string, argv, env []string, stdout, stderr io.Writer) (record processObservation, resultErr error) {
	record.ExitCode = -1
	encoded, _ := json.Marshal(argv)
	record.ArgvSHA256 = fmt.Sprintf("%x", sha256.Sum256(encoded))
	if contextFailure(ctx) != nil || len(argv) == 0 || stdout == nil || stderr == nil {
		return record, errors.Join(errors.New("command refused before start"), contextFailure(ctx))
	}
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	command.Dir, command.Env = dir, env
	command.Stdout, command.Stderr = stdout, stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var mu sync.Mutex
	var cancelErr error
	command.Cancel = func() error {
		mu.Lock()
		defer mu.Unlock()
		if command.Process == nil || command.Process.Pid <= 0 {
			cancelErr = errors.New("owned process identity missing")
			return cancelErr
		}
		record.GroupCancelAttempted = true
		cancelErr = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		record.GroupCancelSucceeded = cancelErr == nil
		if errors.Is(cancelErr, syscall.ESRCH) {
			// A racing original exit still needs actual Wait and the deadline fence.
			cancelErr = nil
			return os.ErrProcessDone
		}
		return cancelErr
	}
	if err := command.Start(); err != nil {
		return record, errors.Join(err, contextFailure(ctx))
	}
	record.Started, record.PID = true, command.Process.Pid
	// Wait also joins os/exec's stdout/stderr copying, including failed outcomes.
	waitErr := command.Wait()
	mu.Lock()
	record.WaitReturned = true
	if command.ProcessState != nil {
		record.Exited, record.ExitCode = command.ProcessState.Exited(), command.ProcessState.ExitCode()
	}
	resultErr = errors.Join(waitErr, cancelErr, contextFailure(ctx))
	mu.Unlock()
	if !record.Exited || record.ExitCode != 0 {
		resultErr = errors.Join(resultErr, errors.New("original command did not exit successfully"))
	}
	return record, resultErr
}

func processFailure(record processObservation, originalErr error, overflow bool) error {
	if !record.Started || record.PID <= 0 || !record.WaitReturned || !record.Exited || record.ExitCode != 0 || overflow {
		return errors.Join(originalErr, errors.New("original process or bounded capture unresolved"))
	}
	return originalErr
}

type testEvent struct {
	Time        string
	Action      string
	Package     string
	Test        string
	Elapsed     float64
	Output      string
	ImportPath  string
	FailedBuild string
}

func decodeEvent(line []byte) (testEvent, error) {
	var event testEvent
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		return event, errors.New("invalid test event")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return event, errors.New("test event has trailing data")
	}
	// The original producer has unique keys. Do not let a duplicate key replace
	// a foreign package/action/name when validating retained original bytes.
	keys := json.NewDecoder(bytes.NewReader(line))
	if token, err := keys.Token(); err != nil || token != json.Delim('{') {
		return event, errors.New("test event is not an object")
	}
	seen := map[string]bool{}
	allowed := map[string]bool{"Time": true, "Action": true, "Package": true, "Test": true, "Elapsed": true, "Output": true, "ImportPath": true, "FailedBuild": true}
	for keys.More() {
		key, err := keys.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] || seen[name] {
			return event, errors.New("duplicate test event key")
		}
		seen[name] = true
		if err := keys.Decode(new(json.RawMessage)); err != nil {
			return event, errors.New("invalid test event value")
		}
	}
	return event, nil
}

type caseCounts struct {
	Run  int `json:"run"`
	Pass int `json:"pass"`
}

type eventObservation struct {
	Cases        map[string]caseCounts `json:"cases"`
	PackageStart int                   `json:"package_start"`
	PackagePass  int                   `json:"package_pass"`
}

func inspectEvents(raw []byte) (out eventObservation, resultErr error) {
	out.Cases = map[string]caseCounts{collectorRoot: {}}
	for _, name := range collectorCases {
		out.Cases[collectorRoot+"/"+name] = caseCounts{}
	}
	if len(raw) == 0 || len(raw) > maxRawBytes || raw[len(raw)-1] != '\n' {
		return out, errors.New("missing or incomplete original GoJSON")
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), maxRawBytes+1)
	for scanner.Scan() {
		e, err := decodeEvent(scanner.Bytes())
		if err != nil {
			return out, err
		}
		if e.Action == "build-output" {
			if e.ImportPath == "" || e.Test != "" || e.Package != "" || e.FailedBuild != "" || e.Output == "" || out.PackageStart != 0 {
				return out, errors.New("foreign or unordered compiler diagnostic")
			}
			continue // Known pre-start compiler diagnostic, never an approval.
		}
		at, err := time.Parse(time.RFC3339Nano, e.Time)
		if err != nil || at.IsZero() || e.Package != collectorPackage || e.FailedBuild != "" || e.ImportPath != "" || out.PackagePass != 0 {
			return out, errors.New("foreign or unordered test event")
		}
		if e.Action == "start" && e.Test == "" && out.PackageStart == 0 {
			out.PackageStart++
			continue
		}
		if out.PackageStart != 1 {
			return out, errors.New("package did not start exactly once")
		}
		counts, known := out.Cases[e.Test]
		if e.Test != "" && !known {
			return out, errors.New("foreign test name")
		}
		switch e.Action {
		case "output":
			// Text can neither create nor pass a case.
		case "run":
			if !known || counts.Run != 0 || counts.Pass != 0 || (e.Test != collectorRoot && (out.Cases[collectorRoot].Run != 1 || out.Cases[collectorRoot].Pass != 0)) {
				return out, errors.New("duplicate or unordered test run")
			}
			counts.Run++
			out.Cases[e.Test] = counts
		case "pass":
			if e.Test == "" {
				for _, c := range out.Cases {
					if c.Run != 1 || c.Pass != 1 {
						return out, errors.New("incomplete test roster")
					}
				}
				out.PackagePass++
			} else {
				if counts.Run != 1 || counts.Pass != 0 {
					return out, errors.New("duplicate or unordered test pass")
				}
				if e.Test == collectorRoot {
					for name, c := range out.Cases {
						if name != collectorRoot && (c.Run != 1 || c.Pass != 1) {
							return out, errors.New("parent passed before its cases")
						}
					}
				}
				counts.Pass++
				out.Cases[e.Test] = counts
			}
		default:
			return out, errors.New("failed skipped or unknown event action")
		}
	}
	if scanner.Err() != nil || out.PackageStart != 1 || out.PackagePass != 1 {
		return out, errors.New("original test package did not return once")
	}
	return out, nil
}

func inspectOriginalEvents(ctx context.Context, raw []byte) (eventObservation, error) {
	observed, err := inspectEvents(raw)
	return observed, errors.Join(err, contextFailure(ctx))
}

type ownedWriter interface {
	io.Writer
	io.Closer
}

func exclusiveFile(path string) (ownedWriter, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
}

// Actual write and Close return before the context/absolute-deadline fence.
func writeOwned(ctx context.Context, path string, raw []byte, open func(string) (ownedWriter, error)) error {
	file, err := open(path)
	if err != nil {
		return errors.Join(err, contextFailure(ctx))
	}
	n, writeErr := file.Write(raw)
	if n != len(raw) {
		writeErr = errors.Join(writeErr, io.ErrShortWrite)
	}
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr, contextFailure(ctx))
}

func selectedDirectory(mode, workspace string) (string, error) {
	var name string
	switch mode {
	case "--mode=postgres":
		name = ".ci-bound-prometheus"
	case "--mode=kind":
		name = ".ci-native-prometheus"
	default:
		return "", errors.New("unknown source gate mode")
	}
	if !filepath.IsAbs(workspace) {
		return "", errors.New("workspace missing")
	}
	dir := filepath.Join(workspace, name)
	real, err := filepath.EvalSymlinks(dir)
	if err != nil || real != dir {
		return "", errors.New("source checkout path changed")
	}
	return dir, nil
}

func childEnvironment() []string {
	overrides := map[string]string{"GO111MODULE": "on", "GOWORK": "off", "GOFLAGS": "-mod=readonly", "GOTOOLCHAIN": "local"}
	out := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := overrides[key]; !replaced {
			out = append(out, entry)
		}
	}
	for _, key := range []string{"GO111MODULE", "GOWORK", "GOFLAGS", "GOTOOLCHAIN"} {
		out = append(out, key+"="+overrides[key])
	}
	return out
}

func checkSource(ctx context.Context, dir string) error {
	for _, args := range [][]string{{"git", "rev-parse", "HEAD"}, {"git", "status", "--porcelain", "--untracked-files=all"}} {
		capture := new(rawCapture)
		record, err := observeCommand(ctx, dir, args, os.Environ(), captureWriter{capture, false}, captureWriter{capture, true})
		out, _, _, overflow := capture.snapshot()
		if err != nil || !record.WaitReturned || overflow || (args[1] == "rev-parse" && strings.TrimSpace(string(out)) != collectorCommit) || (args[1] == "status" && len(out) != 0) {
			return errors.Join(errors.New("fixed source identity refused"), err, contextFailure(ctx))
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil || !bytes.HasPrefix(raw, []byte("module "+collectorModule+"\n")) || !bytes.Contains(raw, []byte("\ngo 1.25.0\n")) {
		return errors.Join(errors.New("owning collector module changed"), err, contextFailure(ctx))
	}
	return contextFailure(ctx)
}

type gateObservation struct {
	Schema       string             `json:"schema"`
	Scope        string             `json:"scope"`
	Source       string             `json:"expected_collector_source"`
	SourceBefore bool               `json:"source_verified_before"`
	SourceAfter  bool               `json:"source_verified_after"`
	GoVersion    string             `json:"helper_go_version"`
	Process      processObservation `json:"process"`
	Events       eventObservation   `json:"events"`
	StdoutSHA256 string             `json:"stdout_sha256"`
	StderrSHA256 string             `json:"stderr_sha256"`
	StdoutBytes  int                `json:"stdout_bytes_retained"`
	StderrBytes  int                `json:"stderr_bytes_retained"`
}

func gate(ctx context.Context, mode, workspace, temporary string) (resultErr error) {
	if ctx == nil {
		return errors.New("gate context missing")
	}
	dir, err := selectedDirectory(mode, workspace)
	if err != nil || !filepath.IsAbs(temporary) {
		return errors.Join(errors.New("fixed gate inputs refused"), err)
	}
	output := filepath.Join(temporary, "prometheus-lifecycle-"+strings.TrimPrefix(mode, "--mode="))
	if err := os.Mkdir(output, 0700); err != nil {
		return errors.Join(errors.New("fresh gate retention refused"), err)
	}
	ctx, cancel := context.WithTimeout(ctx, commandBudget)
	defer cancel()
	capture := new(rawCapture)
	report := gateObservation{Schema: "collector_lifecycle_observations_v1", Scope: "observations only; actual gate exit required", Source: collectorCommit, GoVersion: runtime.Version()}
	resultErr = checkSource(ctx, dir)
	report.SourceBefore = resultErr == nil
	if resultErr == nil {
		report.Process, resultErr = observeCommand(ctx, dir, []string{"go", "test", "-race", "-count=1", "-timeout=3m", "-json", "-run", "^" + collectorRoot + "$", "./internal/adapter"}, childEnvironment(), captureWriter{capture, false}, captureWriter{capture, true})
	}
	stdout, stderr, observed, overflow := capture.snapshot()
	report.Process.RawBytes, report.Process.Overflow = observed, overflow
	resultErr = processFailure(report.Process, resultErr, overflow)
	// Retain bounded original bytes even when their process or verdict failed.
	resultErr = errors.Join(resultErr, writeOwned(ctx, filepath.Join(output, "original.jsonl"), stdout, exclusiveFile), writeOwned(ctx, filepath.Join(output, "original.stderr"), stderr, exclusiveFile))
	var verdictErr error
	report.Events, verdictErr = inspectOriginalEvents(ctx, stdout)
	sourceErr := checkSource(ctx, dir)
	report.SourceAfter = sourceErr == nil
	resultErr = errors.Join(resultErr, verdictErr, contextFailure(ctx), sourceErr)
	report.StdoutBytes, report.StderrBytes = len(stdout), len(stderr)
	report.StdoutSHA256, report.StderrSHA256 = fmt.Sprintf("%x", sha256.Sum256(stdout)), fmt.Sprintf("%x", sha256.Sum256(stderr))
	raw, marshalErr := json.Marshal(report)
	resultErr = errors.Join(resultErr, marshalErr)
	if marshalErr == nil {
		resultErr = errors.Join(resultErr, writeOwned(ctx, filepath.Join(output, "observations.json"), append(raw, '\n'), exclusiveFile))
	}
	return errors.Join(resultErr, contextFailure(ctx))
}

func main() {
	var err error
	if len(os.Args) != 2 {
		err = errors.New("gate inputs refused")
	} else {
		err = gate(context.Background(), os.Args[1], os.Getenv("GITHUB_WORKSPACE"), os.Getenv("RUNNER_TEMP"))
	}
	if err != nil {
		// The existing report is pre-publication observation data. Never rewrite
		// it to manufacture final success after a late write/Close/context error.
		fmt.Fprintln(os.Stderr, publicFailure(err))
		os.Exit(1)
	}
	fmt.Println("collector lifecycle gate complete")
}

func publicFailure(err error) string {
	category := "unresolved"
	if errors.Is(err, context.DeadlineExceeded) {
		category = "deadline"
	} else if errors.Is(err, context.Canceled) {
		category = "canceled"
	}
	return "collector lifecycle gate refused: " + category
}
