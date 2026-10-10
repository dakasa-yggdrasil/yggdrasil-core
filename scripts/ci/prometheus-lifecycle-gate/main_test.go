//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func validEvents(t *testing.T) []testEvent {
	t.Helper()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	event := func(action, name string) testEvent {
		return testEvent{Time: stamp, Action: action, Package: collectorPackage, Test: name}
	}
	rows := []testEvent{event("start", ""), event("run", collectorRoot)}
	for _, name := range collectorCases {
		rows = append(rows, event("run", collectorRoot+"/"+name), event("pass", collectorRoot+"/"+name))
	}
	return append(rows, event("pass", collectorRoot), event("pass", ""))
}

func eventBytes(t *testing.T, rows []testEvent) []byte {
	t.Helper()
	var raw bytes.Buffer
	for _, row := range rows {
		if err := json.NewEncoder(&raw).Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	return raw.Bytes()
}

func TestGateExactRosterAndEveryMissingOrDuplicateEvent(t *testing.T) {
	rows := validEvents(t)
	if observed, err := inspectEvents(eventBytes(t, rows)); err != nil || len(observed.Cases) != 11 || observed.PackagePass != 1 {
		t.Fatal("exact complete native roster refused", err)
	}
	for index := range rows {
		t.Run(rows[index].Action+"/"+rows[index].Test, func(t *testing.T) {
			missing := append(append([]testEvent(nil), rows[:index]...), rows[index+1:]...)
			if _, err := inspectEvents(eventBytes(t, missing)); err == nil {
				t.Fatal("missing original lifecycle event qualified")
			}
			duplicate := append(append(append([]testEvent(nil), rows[:index]...), rows[index]), rows[index:]...)
			if _, err := inspectEvents(eventBytes(t, duplicate)); err == nil {
				t.Fatal("duplicate lifecycle event qualified")
			}
		})
	}
}

func TestGateForeignMalformedSkippedAndOutputOnlyRefuse(t *testing.T) {
	for _, change := range []struct {
		name   string
		mutate func([]testEvent) []testEvent
	}{
		{"zero-selection", func(e []testEvent) []testEvent { return []testEvent{e[0], e[len(e)-1]} }},
		{"foreign-package", func(e []testEvent) []testEvent { e[3].Package += "/foreign"; return e }},
		{"foreign-root", func(e []testEvent) []testEvent { e[1].Test = "TestForeign"; return e }},
		{"foreign-subcase", func(e []testEvent) []testEvent { e[2].Test += "/foreign"; return e }},
		{"skip", func(e []testEvent) []testEvent { e[3].Action = "skip"; return e }},
		{"fail", func(e []testEvent) []testEvent { e[3].Action = "fail"; return e }},
		{"build-fail", func(e []testEvent) []testEvent { e[0].Action = "build-fail"; return e }},
		{"pass-before-run", func(e []testEvent) []testEvent { e[2], e[3] = e[3], e[2]; return e }},
		{"parent-pass-before-cases", func(e []testEvent) []testEvent { e[2], e[len(e)-2] = e[len(e)-2], e[2]; return e }},
		{"Output-does-not-pass", func(e []testEvent) []testEvent { e[3].Action, e[3].Output = "output", "--- PASS: "+e[3].Test; return e }},
		{"bad-time", func(e []testEvent) []testEvent { e[3].Time = ""; return e }},
	} {
		t.Run(change.name, func(t *testing.T) {
			if _, err := inspectEvents(eventBytes(t, change.mutate(validEvents(t)))); err == nil {
				t.Fatal("invalid event stream qualified")
			}
		})
	}
	complete := eventBytes(t, validEvents(t))
	for _, raw := range [][]byte{nil, []byte("not JSON\n"), complete[:len(complete)-1], append(append([]byte(nil), complete...), []byte("{}{}\n")...), bytes.Replace(complete, []byte(`"Action":"run"`), []byte(`"Action":"fail","Action":"run"`), 1), bytes.Replace(complete, []byte(`"Action":"run"`), []byte(`"action":"run"`), 1)} {
		if _, err := inspectEvents(raw); err == nil {
			t.Fatal("missing malformed duplicate-key or truncated raw qualified")
		}
	}
}

func TestGateActualExpiredContextCannotQualifyCompleteParsedJSON(t *testing.T) {
	raw := eventBytes(t, validEvents(t))
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	<-ctx.Done()
	observed, err := inspectOriginalEvents(ctx, raw)
	if observed.PackagePass != 1 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("complete original event roster refreshed an expired parse deadline")
	}
	parent, stop := context.WithTimeout(t.Context(), 20*time.Millisecond)
	stop()
	deadline, _ := parent.Deadline()
	<-time.After(time.Until(deadline))
	err = contextFailure(parent)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("absolute expiry discarded an original cancellation cause")
	}
}

func TestGateCompilerDiagnosticsCannotEscapeOriginalLifecycle(t *testing.T) {
	diagnostic := testEvent{Action: "build-output", ImportPath: collectorPackage, Output: "original compiler diagnostic\n"}
	rows := validEvents(t)
	if _, err := inspectEvents(eventBytes(t, append([]testEvent{diagnostic}, rows...))); err != nil {
		t.Fatal("known pre-start compiler diagnostic refused", err)
	}
	for _, invalid := range []testEvent{
		{Action: "build-output", Output: diagnostic.Output},
		{Action: "build-output", ImportPath: collectorPackage},
		{Action: "build-output", ImportPath: collectorPackage, Output: diagnostic.Output, FailedBuild: collectorPackage},
		{Action: "build-output", ImportPath: collectorPackage, Output: diagnostic.Output, Test: collectorRoot},
	} {
		if _, err := inspectEvents(eventBytes(t, append([]testEvent{invalid}, rows...))); err == nil {
			t.Fatal("foreign compiler diagnostic qualified")
		}
	}
	if _, err := inspectEvents(eventBytes(t, append(rows, diagnostic))); err == nil {
		t.Fatal("post-return compiler diagnostic escaped the package terminal fence")
	}
}

// No WriterTo: io.Copy must use the capture's own capped Write, never ReadFrom.
type onlyReader struct{ reader io.Reader }

func (r onlyReader) Read(p []byte) (int, error) { return r.reader.Read(p) }

func TestGateCombinedCapOwnsActualIOCopy(t *testing.T) {
	capture := new(rawCapture)
	if n, err := io.Copy(captureWriter{capture, false}, onlyReader{strings.NewReader(strings.Repeat("o", maxRawBytes))}); err != nil || n != maxRawBytes {
		t.Fatal("original io.Copy failed", n, err)
	}
	if n, err := io.Copy(captureWriter{capture, true}, onlyReader{strings.NewReader("e")}); err != nil || n != 1 {
		t.Fatal("overflow did not finish draining")
	}
	out, stderr, observed, overflow := capture.snapshot()
	if !overflow || len(out)+len(stderr) != maxRawBytes || observed != maxRawBytes+1 {
		t.Fatal("combined cap bypassed or bytes mistaken for complete output")
	}
}

func TestGateCompleteJSONCannotReplaceOverflowRefusal(t *testing.T) {
	capture := new(rawCapture)
	complete := eventBytes(t, validEvents(t))
	_, _ = captureWriter{capture, false}.Write(complete)
	_, err := io.Copy(captureWriter{capture, true}, onlyReader{strings.NewReader(strings.Repeat("e", maxRawBytes))})
	if err != nil {
		t.Fatal(err)
	}
	stdout, _, _, overflow := capture.snapshot()
	if _, err := inspectEvents(stdout); err != nil {
		t.Fatal("original complete stdout was not preserved", err)
	}
	if !overflow || processFailure(processObservation{Started: true, PID: 1, WaitReturned: true, Exited: true, ExitCode: 0}, nil, overflow) == nil {
		t.Fatal("complete original JSON hid overflow on the original stderr channel")
	}
}

// This is a protocol/process fixture, never native collector evidence. Normal
// unit execution has no effect; only the privately selected child invocation
// emits protocol bytes, exits nonzero, overflows or waits for its owned signal.
func TestGateFixtureProcess(t *testing.T) {
	switch os.Getenv("CORE_GATE_CHILD_FIXTURE") {
	case "nonzero":
		_, _ = os.Stdout.Write(eventBytes(t, validEvents(t)))
		os.Exit(7)
	case "overflow":
		_, _ = io.Copy(os.Stdout, onlyReader{strings.NewReader(strings.Repeat("x", maxRawBytes+1))})
		_, _ = os.Stderr.Write([]byte("original stderr"))
		os.Exit(0)
	case "held":
		_, _ = os.Stdout.Write([]byte("held original process\n"))
		time.Sleep(time.Minute)
		os.Exit(0)
	case "complete":
		_, _ = os.Stdout.Write(eventBytes(t, validEvents(t)))
		os.Exit(0)
	}
}

func childArgs(t *testing.T, mode string) ([]string, []string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return []string{executable, "-test.run=^TestGateFixtureProcess$"}, append(os.Environ(), "CORE_GATE_CHILD_FIXTURE="+mode)
}

func TestGateNominalTranscriptCannotReplaceActualWaitExit(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	args, env := childArgs(t, "nonzero")
	capture := new(rawCapture)
	record, err := observeCommand(ctx, "", args, env, captureWriter{capture, false}, captureWriter{capture, true})
	raw, _, _, _ := capture.snapshot()
	if _, eventErr := inspectEvents(raw); eventErr != nil {
		t.Fatal("fixture did not emit its complete protocol transcript", eventErr)
	}
	if processFailure(record, err, false) == nil || !record.Started || record.PID <= 0 || !record.WaitReturned || !record.Exited || record.ExitCode != 7 {
		t.Fatal("nominal PASS defeated actual original nonzero exit")
	}
}

func TestGateActualSubprocessOverflowIsDrainedAndRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	args, env := childArgs(t, "overflow")
	capture := new(rawCapture)
	record, err := observeCommand(ctx, "", args, env, captureWriter{capture, false}, captureWriter{capture, true})
	out, stderr, observed, overflow := capture.snapshot()
	if err != nil || !record.WaitReturned || record.ExitCode != 0 || !overflow || len(out)+len(stderr) != maxRawBytes || observed <= maxRawBytes {
		t.Fatal("original overflow subprocess did not actually drain and return")
	}
	if processFailure(record, err, overflow) == nil {
		t.Fatal("actual subprocess overflow was treated as successful capture")
	}
	if _, verdictErr := inspectEvents(out); verdictErr == nil {
		t.Fatal("overflow prefix qualified")
	}
}

func TestGateCancelledOriginalGroupStillWaitsAndRefuses(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	args, env := childArgs(t, "held")
	capture := new(rawCapture)
	writer := &observedWriter{writer: captureWriter{capture, false}, entered: make(chan struct{})}
	type outcome struct {
		record processObservation
		err    error
	}
	done := make(chan outcome, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		record, err := observeCommand(ctx, "", args, env, writer, captureWriter{capture, true})
		done <- outcome{record, err}
	}()
	t.Cleanup(func() { cancel(); <-joined })
	select {
	case <-writer.entered:
	case <-ctx.Done():
		t.Fatal("original held process did not publish its real stdout before deadline")
	}
	final := <-done
	<-joined
	record, err := final.record, final.err
	if !errors.Is(err, context.DeadlineExceeded) || !record.Started || record.PID <= 0 || !record.GroupCancelAttempted || !record.GroupCancelSucceeded || !record.WaitReturned || record.ExitCode == 0 {
		t.Fatal("timeout notification replaced actual owned process Wait")
	}
}

type observedWriter struct {
	writer  io.Writer
	entered chan struct{}
	once    sync.Once
}

func (w *observedWriter) Write(raw []byte) (int, error) {
	n, err := w.writer.Write(raw)
	w.once.Do(func() { close(w.entered) })
	return n, err
}

type heldWriter struct {
	writer  io.Writer
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (w *heldWriter) Write(raw []byte) (int, error) {
	w.once.Do(func() { close(w.entered); <-w.release })
	return w.writer.Write(raw)
}

func TestGateWaitCannotPrecedeOriginalPipeDrain(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	args, env := childArgs(t, "complete")
	capture := new(rawCapture)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	writer := &heldWriter{captureWriter{capture, false}, make(chan struct{}), release, sync.Once{}}
	done := make(chan error, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		_, err := observeCommand(ctx, "", args, env, writer, captureWriter{capture, true})
		done <- err
	}()
	t.Cleanup(func() { cancel(); unblock(); <-joined })
	select {
	case <-writer.entered:
	case <-ctx.Done():
		t.Fatal("original pipe writer did not enter")
	}
	select {
	case <-done:
		t.Fatal("Wait returned before actual original pipe drain")
	default:
	}
	unblock()
	if err := <-done; err != nil {
		t.Fatal("released original pipe did not return", err)
	}
	<-joined
}

type heldClose struct {
	*os.File
	entered  chan struct{}
	release  <-chan struct{}
	returned chan struct{}
	writeErr error
	closeErr error
}

func (w *heldClose) Write(raw []byte) (int, error) {
	n, err := w.File.Write(raw)
	return n, errors.Join(err, w.writeErr)
}

func (w *heldClose) Close() error {
	err := w.File.Close()
	close(w.entered)
	<-w.release
	close(w.returned)
	return errors.Join(err, w.closeErr)
}

func TestGateActualRetentionCloseAndDeadlinePreserveAllCauses(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	writeCause, closeCause := errors.New("private original write"), errors.New("private original Close")
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	file, err := os.OpenFile(filepath.Join(t.TempDir(), "observations.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	owned := &heldClose{file, make(chan struct{}), release, make(chan struct{}), writeCause, closeCause}
	done := make(chan error, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		done <- writeOwned(ctx, "fixed", []byte("actual retained bytes"), func(string) (ownedWriter, error) { return owned, nil })
	}()
	t.Cleanup(func() { cancel(); unblock(); <-joined })
	<-owned.entered
	<-ctx.Done()
	if deadline, known := ctx.Deadline(); !known || time.Now().Before(deadline) {
		t.Fatal("original absolute retention deadline still live")
	}
	select {
	case <-done:
		t.Fatal("context notification replaced actual Close return")
	default:
	}
	unblock()
	err = <-done
	<-owned.returned
	for _, cause := range []error{writeCause, closeCause, context.DeadlineExceeded} {
		if !errors.Is(err, cause) {
			t.Fatal("actual original retention cause lost")
		}
	}
	<-joined
	if publicFailure(err) != "collector lifecycle gate refused: deadline" || strings.Contains(publicFailure(err), "private") {
		t.Fatal("final late report failure exposed a private cause or lost its category")
	}
}

func TestGateClosedInputsAndFreshRetention(t *testing.T) {
	workspace := t.TempDir()
	for _, mode := range []string{"--mode=other", "--mode=postgres --command=foreign", ""} {
		if _, err := selectedDirectory(mode, workspace); err == nil {
			t.Fatal("foreign input selected a collector")
		}
	}
	if err := os.Mkdir(filepath.Join(workspace, ".ci-bound-prometheus"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := selectedDirectory("--mode=postgres", workspace); err != nil {
		t.Fatal("fixed existing checkout refused", err)
	}
	if err := os.Symlink(filepath.Join(workspace, ".ci-bound-prometheus"), filepath.Join(workspace, ".ci-native-prometheus")); err != nil {
		t.Fatal(err)
	}
	if _, err := selectedDirectory("--mode=kind", workspace); err == nil {
		t.Fatal("foreign symlink source adopted")
	}
	raw := filepath.Join(t.TempDir(), "retained")
	if err := os.WriteFile(raw, []byte("old original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeOwned(t.Context(), raw, []byte("replacement"), exclusiveFile); err == nil {
		t.Fatal("stale original raw overwritten")
	}
	before, err := os.ReadFile(raw)
	if err != nil || string(before) != "old original" {
		t.Fatal("original raw was changed")
	}
}

func TestGateUnknownSourceNeverStartsCollectorAndRetainsRefusal(t *testing.T) {
	workspace, temporary := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(workspace, ".ci-bound-prometheus"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := gate(ctx, "--mode=postgres", workspace, temporary); err == nil {
		t.Fatal("unknown actual Git source qualified")
	}
	raw, err := os.ReadFile(filepath.Join(temporary, "prometheus-lifecycle-postgres", "observations.json"))
	var report gateObservation
	if err != nil || json.Unmarshal(raw, &report) != nil || report.Process.Started || report.SourceBefore || report.SourceAfter || report.Events.PackagePass != 0 {
		t.Fatal("refused source manufactured a native collector invocation")
	}
	if err := gate(ctx, "--mode=postgres", workspace, temporary); err == nil {
		t.Fatal("preexisting retained observation was adopted")
	}
}
