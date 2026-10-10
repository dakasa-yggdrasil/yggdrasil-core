//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	nominal := processObservation{Started: true, PID: 1, WaitReturned: true, ContextOwnerJoined: true, Exited: true, ExitCode: 0}
	if processFailure(nominal, nil, false) != nil {
		t.Fatal("complete process observation refused before overflow")
	}
	if !overflow || processFailure(nominal, nil, overflow) == nil {
		t.Fatal("complete original JSON hid overflow on the original stderr channel")
	}
	nominal.ContextOwnerJoined = false
	if processFailure(nominal, nil, false) == nil {
		t.Fatal("unjoined deadline owner qualified")
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
	case "leader-with-held-descendant":
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		child := exec.Command(executable, "-test.run=^TestGateFixtureProcess$")
		child.Env = append(os.Environ(), "CORE_GATE_CHILD_FIXTURE=held-descendant")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		// Fixture-only: the test owner becomes the kernel parent so that it can
		// observe the original descendant's actual Wait, not PID disappearance.
		child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_PARENT}
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		birth := descendantBirth{Leader: os.Getpid(), Child: child.Process.Pid}
		raw, err := json.Marshal(birth)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeOwned(t.Context(), os.Getenv("CORE_GATE_DESCENDANT_BIRTH"), raw, exclusiveFile); err != nil {
			t.Fatal(err)
		}
		_, _ = os.Stdout.Write(eventBytes(t, validEvents(t)))
		os.Exit(0)
	case "held-descendant":
		identity, err := readProcessIdentity(os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(identity)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeOwned(t.Context(), os.Getenv("CORE_GATE_DESCENDANT_READY"), raw, exclusiveFile); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Minute)
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
	if !errors.Is(err, context.DeadlineExceeded) || !record.Started || record.PID <= 0 || !record.GroupCancelAttempted || !record.GroupCancelSucceeded || !record.WaitReturned || !record.ContextOwnerJoined || record.ExitCode == 0 {
		t.Fatal("timeout notification replaced actual owned process Wait")
	}
}

type descendantBirth struct {
	Leader, Child int
}

type processIdentity struct {
	PID, Parent, Group int
	StartTicks         uint64
	State              string
}

// These GET-only kernel identities are fixture witnesses. No disappearance is
// substituted for the original descendant's native Process.Wait below.
func readProcessIdentity(pid int) (processIdentity, error) {
	var out processIdentity
	if pid <= 0 {
		return out, errors.New("native fixture PID missing")
	}
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return out, err
	}
	open, close := bytes.IndexByte(raw, '('), bytes.LastIndexByte(raw, ')')
	if open <= 0 || close <= open {
		return out, errors.New("native fixture stat incomplete")
	}
	fields := strings.Fields(string(raw[close+1:]))
	if len(fields) < 20 {
		return out, errors.New("native fixture stat fields incomplete")
	}
	out.PID, err = strconv.Atoi(strings.TrimSpace(string(raw[:open])))
	if err != nil || out.PID != pid {
		return out, errors.Join(errors.New("native fixture stat PID changed"), err)
	}
	out.State = fields[0]
	out.Parent, err = strconv.Atoi(fields[1])
	if err != nil {
		return out, err
	}
	out.Group, err = strconv.Atoi(fields[2])
	if err != nil {
		return out, err
	}
	out.StartTicks, err = strconv.ParseUint(fields[19], 10, 64)
	if err != nil || out.StartTicks == 0 {
		return out, errors.Join(errors.New("native fixture birth identity missing"), err)
	}
	return out, nil
}

func readFixtureJSON(path string, target any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > 4096 {
		return errors.New("native fixture identity size refused")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("native fixture identity has trailing data")
	}
	return nil
}

// Failed assertions can precede the birth-file observation. Find only children
// actually parented to this test and still bound to the original fresh group,
// then perform their real Wait after the group's owned cancellation/leader join.
func waitRemainingFixtureChildren(group int) error {
	if group <= 0 {
		return nil
	}
	tasks, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(os.Getpid()), "task"))
	if err != nil {
		return err
	}
	seen := map[int]bool{}
	var resultErr error
	for _, task := range tasks {
		raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(os.Getpid()), "task", task.Name(), "children"))
		if errors.Is(err, os.ErrNotExist) {
			continue // A retired owning thread has no remaining child census.
		}
		if err != nil {
			resultErr = errors.Join(resultErr, err)
			continue
		}
		for _, value := range strings.Fields(string(raw)) {
			pid, err := strconv.Atoi(value)
			if err != nil || seen[pid] {
				resultErr = errors.Join(resultErr, err)
				continue
			}
			seen[pid] = true
			identity, err := readProcessIdentity(pid)
			if err != nil {
				resultErr = errors.Join(resultErr, err)
				continue
			}
			if identity.Parent != os.Getpid() || identity.Group != group {
				continue
			}
			child, err := os.FindProcess(pid)
			if err != nil {
				resultErr = errors.Join(resultErr, err)
				continue
			}
			_, err = child.Wait()
			resultErr = errors.Join(resultErr, err)
		}
	}
	return resultErr
}

func TestGateLeaderExitDoesNotEndOwnershipBeforeDescendantPipeEOF(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	args, env := childArgs(t, "leader-with-held-descendant")
	retention := t.TempDir()
	birthPath, readyPath := filepath.Join(retention, "original-birth.json"), filepath.Join(retention, "original-ready.json")
	env = append(env, "CORE_GATE_DESCENDANT_BIRTH="+birthPath, "CORE_GATE_DESCENDANT_READY="+readyPath)
	capture := new(rawCapture)
	type outcome struct {
		record processObservation
		err    error
	}
	var final outcome
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		final.record, final.err = observeCommand(ctx, "", args, env, captureWriter{capture, false}, captureWriter{capture, true})
	}()
	var childJoined <-chan struct{}
	t.Cleanup(func() {
		cancel()
		<-joined
		if childJoined != nil {
			<-childJoined
		}
		if err := waitRemainingFixtureChildren(final.record.PID); err != nil {
			t.Error("original fixture children were not actually joined", err)
		}
	})
	var birth descendantBirth
	var ready, identity processIdentity
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		birthErr := readFixtureJSON(birthPath, &birth)
		readyErr := readFixtureJSON(readyPath, &ready)
		if birthErr == nil && readyErr == nil {
			if birth.Leader <= 0 || birth.Child <= 0 || birth.Leader == birth.Child || ready.PID != birth.Child || ready.Parent != os.Getpid() || ready.Group != birth.Leader {
				t.Fatal("original Start identity/parent/group refused")
			}
			var err error
			identity, err = readProcessIdentity(birth.Child)
			if err != nil || identity.PID != ready.PID || identity.Parent != ready.Parent || identity.Group != ready.Group || identity.StartTicks != ready.StartTicks || (identity.State != "R" && identity.State != "S") {
				t.Fatal("original inherited-pipe child is not independently alive", err)
			}
			_, leaderErr := readProcessIdentity(birth.Leader)
			if errors.Is(leaderErr, os.ErrNotExist) {
				if err := contextFailure(ctx); err != nil {
					t.Fatal("original leader was not reaped before its deadline", err)
				}
				break
			}
			if leaderErr != nil {
				t.Fatal("native leader identity unreadable", leaderErr)
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("native leader/descendant causal phase not reached before original deadline")
		case <-joined:
			t.Fatal("original Wait returned while its child still owns pipe EOF")
		case <-ticker.C:
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	actualExecutable, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(identity.PID), "exe"))
	if err != nil || actualExecutable != executable {
		t.Fatal("original child executable identity changed", err)
	}
	if err := contextFailure(ctx); err != nil {
		t.Fatal("original inherited-pipe witness crossed its absolute deadline", err)
	}
	child, err := os.FindProcess(identity.PID)
	if err != nil {
		t.Fatal(err)
	}
	var childState *os.ProcessState
	var childErr error
	childDone := make(chan struct{})
	childJoined = childDone
	go func() { defer close(childDone); childState, childErr = child.Wait() }()
	select {
	case <-joined:
		t.Fatal("leader exit0 replaced actual descendant pipe EOF")
	default:
	}
	<-ctx.Done()
	<-joined
	<-childDone
	status, known := syscall.WaitStatus(0), false
	if childState != nil {
		status, known = childState.Sys().(syscall.WaitStatus)
	}
	if childErr != nil || childState == nil || !known || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("signal/PID disappearance replaced original child Wait", childErr)
	}
	record, originalErr := final.record, final.err
	stdout, _, _, overflow := capture.snapshot()
	if _, err := inspectEvents(stdout); err != nil {
		t.Fatal("leader's original complete GoJSON missing", err)
	}
	if record.PID != birth.Leader || !record.WaitReturned || !record.ContextOwnerJoined || !record.Exited || record.ExitCode != 0 || !record.GroupCancelAttempted || !record.GroupCancelSucceeded || !errors.Is(originalErr, context.DeadlineExceeded) || processFailure(record, originalErr, overflow) == nil {
		t.Fatal("complete leader0 evidence hid descendant-held EOF or expired ownership")
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
