//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testRoot(t *testing.T) (*retainedRoot, string) {
	t.Helper()
	path := t.TempDir()
	root, err := openRetainedRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if root.Close() != nil {
			t.Error("original root close failed")
		}
	})
	return root, path
}

func preparedRoot(t *testing.T) (*retainedRoot, string) {
	t.Helper()
	root, path := testRoot(t)
	if prepare(root) != nil {
		t.Fatal("preparation refused")
	}
	return root, path
}

func corpusFile(path, corpus, file string) string {
	return filepath.Join(path, corpusRoot, corpus, file)
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func writeFile(t *testing.T, path string, raw []byte) {
	t.Helper()
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("fixture write refused")
	}
}

type originalOutput struct {
	raw      []byte
	eof      bool
	readErr  error
	closeErr error
}

type originalProcess struct {
	started        bool
	waitReturned   bool
	waitErr        error
	stdout         originalOutput
	stderr         originalOutput
	writerCloseErr error
}

// Only GitHub CI calls this test-owned fixed command constructor. These are
// actual Start/Wait and two distinct pipe Read/EOF/Close returns, not dispatch
// through the test executable or a borrowed workflow binary.
func originalCommand(t *testing.T, ctx context.Context, cancel context.CancelFunc, executable, directory string, args, env []string) originalProcess {
	t.Helper()
	var returned originalProcess
	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		t.Fatal("original stdout pipe refused")
	}
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		_ = stdoutRead.Close()
		_ = stdoutWrite.Close()
		t.Fatal("original stderr pipe refused")
	}
	deadline, exists := ctx.Deadline()
	if !exists || stdoutRead.SetReadDeadline(deadline) != nil || stderrRead.SetReadDeadline(deadline) != nil {
		_ = stdoutRead.Close()
		_ = stdoutWrite.Close()
		_ = stderrRead.Close()
		_ = stderrWrite.Close()
		t.Fatal("original pipe deadline refused")
	}
	read := func(file *os.File) <-chan originalOutput {
		done := make(chan originalOutput, 1)
		go func() {
			var output originalOutput
			buffer := make([]byte, 4096)
			for {
				n, readErr := file.Read(buffer)
				output.raw = append(output.raw, buffer[:n]...)
				if len(output.raw) > lineLimit {
					output.readErr = errRetention
					cancel()
					break
				}
				if readErr == io.EOF {
					output.eof = true
					break
				}
				if readErr != nil {
					output.readErr = readErr
					cancel()
					break
				}
			}
			output.closeErr = file.Close()
			done <- output
		}()
		return done
	}
	stdout, stderr := read(stdoutRead), read(stderrRead)
	command := exec.CommandContext(ctx, executable, args...)
	command.Dir, command.Env = directory, env
	command.Stdout, command.Stderr = stdoutWrite, stderrWrite
	startErr := command.Start()
	stdoutClose, stderrClose := stdoutWrite.Close(), stderrWrite.Close()
	if stdoutClose != nil || stderrClose != nil {
		returned.writerCloseErr = errRetention
		cancel()
	}
	if startErr == nil {
		returned.started = true
		returned.waitErr = command.Wait()
		returned.waitReturned = true
	} else {
		returned.waitErr = startErr
	}
	returned.stdout, returned.stderr = <-stdout, <-stderr
	return returned
}

func joinedProcess(returned originalProcess) bool {
	return returned.started && returned.waitReturned && returned.writerCloseErr == nil && returned.stdout.eof && returned.stderr.eof && returned.stdout.readErr == nil && returned.stderr.readErr == nil && returned.stdout.closeErr == nil && returned.stderr.closeErr == nil
}

func originalTestContext(t *testing.T, budget time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	deadline := time.Now().Add(budget)
	if original, exists := t.Deadline(); exists && original.Before(deadline) {
		deadline = original
	}
	return context.WithDeadline(t.Context(), deadline)
}

func compiledOwner(t *testing.T) string {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Fatal("actual compiled owner qualification requires GitHub Actions")
	}
	_, source, _, found := runtime.Caller(0)
	if !found || !filepath.IsAbs(source) {
		t.Fatal("actual current Source package unavailable")
	}
	binary := filepath.Join(t.TempDir(), "original-status-owner")
	ctx, cancel := originalTestContext(t, 30*time.Second)
	defer cancel()
	returned := originalCommand(t, ctx, cancel, "go", filepath.Dir(source), []string{"build", "-mod=readonly", "-o", binary, "."}, os.Environ())
	if !joinedProcess(returned) || returned.waitErr != nil || ctx.Err() != nil {
		t.Fatal("actual current Source owner build or original joins failed")
	}
	return binary
}

func ownerEnvironment(path string) []string {
	env := []string{}
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "RUNNER_TEMP=") {
			env = append(env, value)
		}
	}
	if path != "" {
		env = append(env, "RUNNER_TEMP="+path)
	}
	return env
}

func invokeOwner(t *testing.T, binary, path string, args ...string) originalProcess {
	t.Helper()
	ctx, cancel := originalTestContext(t, 5*time.Second)
	defer cancel()
	returned := originalCommand(t, ctx, cancel, binary, t.TempDir(), args, ownerEnvironment(path))
	if !joinedProcess(returned) || ctx.Err() != nil {
		t.Fatal("actual main original Start/Wait/Read/EOF/Close incomplete")
	}
	return returned
}

func ownerResult(t *testing.T, returned originalProcess, success bool) {
	t.Helper()
	if len(returned.stdout.raw) != 0 {
		t.Fatal("actual main emitted unexpected stdout")
	}
	if success {
		if returned.waitErr != nil || len(returned.stderr.raw) != 0 {
			t.Fatal("actual main original success refused")
		}
		return
	}
	exit, ok := returned.waitErr.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || string(returned.stderr.raw) != errRetention.Error()+"\n" {
		t.Fatal("actual main refusal not opaque or original exit not retained")
	}
}

func TestRetentionOwnerPreparation(t *testing.T) {
	t.Run("complete_private_original", func(t *testing.T) {
		root, path := preparedRoot(t)
		for _, corpus := range corpusNames {
			if withCorpus(root, corpus, func(dir *retainedRoot) error { return pristine(dir, corpus) }) != nil {
				t.Fatal("original not pristine")
			}
			for _, name := range rawNames {
				info, err := os.Lstat(corpusFile(path, corpus, name))
				if err != nil || !privateInfo(info, false) || info.Size() != 0 {
					t.Fatal("raw file not private and empty")
				}
			}
		}
	})
	t.Run("preexisting_root_preserved", func(t *testing.T) {
		root, path := testRoot(t)
		if os.Mkdir(filepath.Join(path, corpusRoot), 0700) != nil {
			t.Fatal("fixture mkdir failed")
		}
		file := filepath.Join(path, corpusRoot, "prior-original")
		original := []byte("prior interrupted original\n")
		writeFile(t, file, original)
		if prepare(root) == nil || !bytes.Equal(readFile(t, file), original) {
			t.Fatal("preexisting original adopted or changed")
		}
	})
	t.Run("partial_preparation_never_starts", func(t *testing.T) {
		root, path := preparedRoot(t)
		if os.Remove(filepath.Join(path, corpusRoot, "preparation.json")) != nil {
			t.Fatal("fixture remove failed")
		}
		before := readFile(t, corpusFile(path, "capacity", "status.json"))
		if start(root, "capacity") == nil || prepare(root) == nil || !bytes.Equal(before, readFile(t, corpusFile(path, "capacity", "status.json"))) {
			t.Fatal("partial prep adopted")
		}
	})
}

func TestRetentionOwnerPristineStart(t *testing.T) {
	t.Run("original_once", func(t *testing.T) {
		root, path := preparedRoot(t)
		if start(root, "capacity") != nil {
			t.Fatal("start refused")
		}
		before := readFile(t, corpusFile(path, "capacity", "status.json"))
		if start(root, "capacity") == nil || !bytes.Equal(before, readFile(t, corpusFile(path, "capacity", "status.json"))) {
			t.Fatal("second original adopted")
		}
	})
	for _, name := range []string{"stale_status", "missing_raw", "nonempty_raw", "wrong_mode", "symlink_raw", "hardlink_raw"} {
		t.Run(name, func(t *testing.T) {
			root, path := preparedRoot(t)
			status := corpusFile(path, "capacity", "status.json")
			raw := corpusFile(path, "capacity", rawNames[0])
			before := readFile(t, status)
			switch name {
			case "stale_status":
				writeFile(t, status, []byte("{}\n"))
				before = readFile(t, status)
			case "missing_raw":
				if os.Remove(raw) != nil {
					t.Fatal("fixture remove failed")
				}
			case "nonempty_raw":
				writeFile(t, raw, []byte("actual prior bytes\n"))
			case "wrong_mode":
				if os.Chmod(raw, 0644) != nil {
					t.Fatal("fixture chmod failed")
				}
			case "symlink_raw":
				other := filepath.Join(path, "original-target")
				writeFile(t, other, []byte("unchanged\n"))
				if os.Remove(raw) != nil || os.Symlink(other, raw) != nil {
					t.Fatal("fixture symlink failed")
				}
			case "hardlink_raw":
				if os.Link(raw, filepath.Join(path, "second-link")) != nil {
					t.Fatal("fixture link failed")
				}
			}
			if start(root, "capacity") == nil || !bytes.Equal(before, readFile(t, status)) {
				t.Fatal("nonpristine original admitted or status changed")
			}
		})
	}
}

func TestRetentionOwnerFinishReturns(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		t.Run(fmt.Sprintf("actual_returns_%03b", mask), func(t *testing.T) {
			root, path := preparedRoot(t)
			if start(root, "capacity") != nil {
				t.Fatal("start refused")
			}
			exits := [3]int{}
			for i := range exits {
				if mask&(1<<i) != 0 {
					exits[i] = 255
				}
			}
			if finish(root, "capacity", exits[0], exits[1], exits[2]) != nil {
				t.Fatal("original return retention refused")
			}
			var state corpusState
			if json.Unmarshal(readFile(t, corpusFile(path, "capacity", "status.json")), &state) != nil {
				t.Fatal("invalid status")
			}
			want := "FAILED_OR_INCOMPLETE"
			if mask == 0 {
				want = "SOURCE_TESTS_AND_CENSUS_PASSED"
			}
			if state.State != want || state.GoExit == nil || *state.GoExit != exits[0] || state.TeeExit == nil || *state.TeeExit != exits[1] || state.CensusExit == nil || *state.CensusExit != exits[2] || state.NativeQualification != "HOLD" || state.LocalSourceClaim != "NONE" {
				t.Fatal("actual return relabeled")
			}
			before := readFile(t, corpusFile(path, "capacity", "status.json"))
			if finish(root, "capacity", 0, 0, 0) == nil || !bytes.Equal(before, readFile(t, corpusFile(path, "capacity", "status.json"))) {
				t.Fatal("return replay changed original status")
			}
		})
	}
	t.Run("no_original_start", func(t *testing.T) {
		root, _ := preparedRoot(t)
		if finish(root, "capacity", 0, 0, 0) == nil {
			t.Fatal("unstarted return admitted")
		}
	})
	t.Run("interrupted_return_marker", func(t *testing.T) {
		root, path := preparedRoot(t)
		if start(root, "capacity") != nil {
			t.Fatal("start refused")
		}
		writeFile(t, corpusFile(path, "capacity", "returned.json"), []byte("partial original"))
		before := readFile(t, corpusFile(path, "capacity", "status.json"))
		if finish(root, "capacity", 0, 0, 0) == nil || !bytes.Equal(before, readFile(t, corpusFile(path, "capacity", "status.json"))) {
			t.Fatal("partial return repaired")
		}
	})
}

func TestRetentionOwnerRawPreservation(t *testing.T) {
	root, path := preparedRoot(t)
	if start(root, "guest-wire") != nil {
		t.Fatal("start refused")
	}
	for i, name := range rawNames {
		writeFile(t, corpusFile(path, "guest-wire", name), []byte(fmt.Sprintf("actual raw stream %d\n", i)))
	}
	if finish(root, "guest-wire", 1, 0, 1) != nil {
		t.Fatal("failed return not retained")
	}
	if prepare(root) == nil || start(root, "guest-wire") == nil || finish(root, "guest-wire", 0, 0, 0) == nil {
		t.Fatal("prior original reused")
	}
	for i, name := range rawNames {
		if !bytes.Equal(readFile(t, corpusFile(path, "guest-wire", name)), []byte(fmt.Sprintf("actual raw stream %d\n", i))) {
			t.Fatal("original raw bytes changed")
		}
	}
}

func TestRetentionOwnerClosedCLI(t *testing.T) {
	for _, args := range [][]string{nil, {"prepare", "extra"}, {"repair"}, {"start", "../capacity"}, {"start", "/capacity"}, {"start", "Capacity"}, {"finish", "capacity", "00", "0", "0"}, {"finish", "capacity", "+0", "0", "0"}, {"finish", "capacity", "256", "0", "0"}, {"finish", "capacity", "-1", "0", "0"}, {"finish", "capacity", "0", "0"}, {"verify-owner-tests", "path"}} {
		root, _ := testRoot(t)
		if run(root, args) == nil {
			t.Fatalf("invalid argv admitted: %q", args)
		}
	}
	for _, value := range []string{"0", "1", "255"} {
		if _, err := parseExit(value); err != nil {
			t.Fatal("canonical actual return refused")
		}
	}
	binary := compiledOwner(t)
	t.Run("compiled_original_prepare_start_finish", func(t *testing.T) {
		path := t.TempDir()
		ownerResult(t, invokeOwner(t, binary, path, "prepare"), true)
		ownerResult(t, invokeOwner(t, binary, path, "start", "capacity"), true)
		for _, name := range rawNames {
			writeFile(t, corpusFile(path, "capacity", name), []byte("same original raw bytes\n"))
		}
		ownerResult(t, invokeOwner(t, binary, path, "finish", "capacity", "1", "0", "0"), true)
		before := readFile(t, corpusFile(path, "capacity", "status.json"))
		var state corpusState
		if json.Unmarshal(before, &state) != nil || state.State != "FAILED_OR_INCOMPLETE" || state.GoExit == nil || *state.GoExit != 1 || state.NativeQualification != "HOLD" || state.LocalSourceClaim != "NONE" {
			t.Fatal("actual main return state relabeled")
		}
		ownerResult(t, invokeOwner(t, binary, path, "finish", "capacity", "0", "0", "0"), false)
		if !bytes.Equal(before, readFile(t, corpusFile(path, "capacity", "status.json"))) {
			t.Fatal("actual main replay changed original status")
		}
		for _, name := range rawNames {
			if string(readFile(t, corpusFile(path, "capacity", name))) != "same original raw bytes\n" {
				t.Fatal("actual main changed raw original bytes")
			}
		}
	})
	for _, name := range []string{"compiled_missing_runner_temp", "compiled_relative_runner_temp", "compiled_nondirectory_runner_temp", "compiled_symlinked_runner_temp", "compiled_wrong_argv", "compiled_fifo_private_input", "compiled_owner_census", "compiled_cancelled_original_context"} {
		t.Run(name, func(t *testing.T) {
			path := t.TempDir()
			switch name {
			case "compiled_missing_runner_temp":
				ownerResult(t, invokeOwner(t, binary, "", "prepare"), false)
			case "compiled_relative_runner_temp":
				ownerResult(t, invokeOwner(t, binary, "relative-original", "prepare"), false)
			case "compiled_nondirectory_runner_temp":
				file := filepath.Join(path, "regular-original")
				writeFile(t, file, nil)
				ownerResult(t, invokeOwner(t, binary, file, "prepare"), false)
			case "compiled_symlinked_runner_temp":
				alias := filepath.Join(t.TempDir(), "original-alias")
				if os.Symlink(path, alias) != nil {
					t.Fatal("original root alias fixture refused")
				}
				ownerResult(t, invokeOwner(t, binary, alias, "prepare"), false)
			case "compiled_wrong_argv":
				ownerResult(t, invokeOwner(t, binary, path, "repair"), false)
			case "compiled_fifo_private_input":
				ownerResult(t, invokeOwner(t, binary, path, "prepare"), true)
				raw := corpusFile(path, "capacity", rawNames[0])
				if os.Remove(raw) != nil || syscall.Mkfifo(raw, 0600) != nil {
					t.Fatal("original FIFO fixture refused")
				}
				before := readFile(t, corpusFile(path, "capacity", "status.json"))
				ownerResult(t, invokeOwner(t, binary, path, "start", "capacity"), false)
				if !bytes.Equal(before, readFile(t, corpusFile(path, "capacity", "status.json"))) {
					t.Fatal("original FIFO refusal changed status")
				}
			case "compiled_owner_census":
				if os.Mkdir(filepath.Join(path, ownerRoot), 0700) != nil {
					t.Fatal("original owner directory refused")
				}
				writeFile(t, filepath.Join(path, ownerRoot, "owner-tests.jsonl"), goodCensus())
				writeFile(t, filepath.Join(path, ownerRoot, "owner-tests.stderr"), nil)
				writeFile(t, filepath.Join(path, ownerRoot, "owner-tests-tee.stderr"), nil)
				ownerResult(t, invokeOwner(t, binary, path, "verify-owner-tests"), true)
			case "compiled_cancelled_original_context":
				ctx, cancel := originalTestContext(t, 5*time.Second)
				cancel()
				returned := originalCommand(t, ctx, cancel, binary, path, []string{"prepare"}, ownerEnvironment(path))
				if returned.started || returned.waitReturned || returned.waitErr == nil || !returned.stdout.eof || !returned.stderr.eof || returned.stdout.closeErr != nil || returned.stderr.closeErr != nil || len(returned.stdout.raw) != 0 || len(returned.stderr.raw) != 0 {
					t.Fatal("cancelled original command return not retained")
				}
				if _, err := os.Lstat(filepath.Join(path, corpusRoot)); !os.IsNotExist(err) {
					t.Fatal("cancelled command adopted original preparation")
				}
			}
		})
	}
}

func TestRetentionOwnerBoundedState(t *testing.T) {
	for _, name := range []string{"over_cap", "duplicate", "case_alias", "unknown", "omitted", "null", "trailing", "non_utf8"} {
		t.Run(name, func(t *testing.T) {
			root, path := preparedRoot(t)
			file := corpusFile(path, "capacity", "status.json")
			raw := readFile(t, file)
			switch name {
			case "over_cap":
				raw = bytes.Repeat([]byte(" "), stateLimit+1)
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"corpus":"capacity"`), []byte(`"corpus":"capacity","corpus":"capacity"`), 1)
			case "case_alias":
				raw = bytes.Replace(raw, []byte(`"schema"`), []byte(`"Schema"`), 1)
			case "unknown":
				raw = bytes.Replace(raw, []byte(`{"schema"`), []byte(`{"extra":true,"schema"`), 1)
			case "omitted":
				raw = bytes.Replace(raw, []byte(`,"go_exit":null`), nil, 1)
			case "null":
				raw = []byte("null\n")
			case "trailing":
				raw = append(raw, []byte("{}\n")...)
			case "non_utf8":
				raw = []byte{0xff}
			}
			writeFile(t, file, raw)
			if start(root, "capacity") == nil || !bytes.Equal(raw, readFile(t, file)) {
				t.Fatal("invalid state accepted or repaired")
			}
		})
	}
}

func goodCensus() []byte {
	var buffer bytes.Buffer
	write := func(action, test string) {
		raw, _ := json.Marshal(testEvent{Action: action, Package: packageName, Test: test})
		buffer.Write(raw)
		buffer.WriteByte('\n')
	}
	write("start", "")
	for _, name := range ownerTests {
		write("run", name)
		for _, child := range ownerChildren[name] {
			write("run", name+"/"+child)
			write("pass", name+"/"+child)
		}
		write("pass", name)
	}
	write("pass", "")
	return buffer.Bytes()
}

func TestRetentionOwnerOriginalCaseCensus(t *testing.T) {
	good := goodCensus()
	if verifyCensus(bytes.NewReader(good)) != nil {
		t.Fatal("complete original Source census refused")
	}
	for _, name := range []string{"missing_root", "duplicate_run", "duplicate_key", "case_alias", "unknown_root", "fail", "skip", "incomplete_package", "trailing_event", "line_cap", "total_cap", "missing_child", "extra_child", "roots_only", "parent_pass_before_child", "time_object", "time_bad_date", "time_noncanonical", "elapsed_string", "elapsed_negative", "elapsed_nonfinite", "output_array", "failedbuild_number", "output_wrong_action", "elapsed_wrong_action", "failedbuild_wrong_action", "missing_output_field"} {
		t.Run(name, func(t *testing.T) {
			raw := append([]byte(nil), good...)
			switch name {
			case "missing_root":
				lines := bytes.Split(raw, []byte("\n"))
				raw = nil
				for _, line := range lines {
					if len(line) > 0 && !bytes.Contains(line, []byte(ownerTests[0])) {
						raw = append(raw, line...)
						raw = append(raw, '\n')
					}
				}
			case "duplicate_run":
				raw = bytes.Replace(raw, []byte(`"Action":"pass","Package":"`+packageName+`","Test":"`+ownerTests[0]+`"`), []byte(`"Action":"run","Package":"`+packageName+`","Test":"`+ownerTests[0]+`"`), 1)
			case "duplicate_key":
				raw = bytes.Replace(raw, []byte(`"Action":"start"`), []byte(`"Action":"start","Action":"start"`), 1)
			case "case_alias":
				raw = bytes.Replace(raw, []byte(`"Action"`), []byte(`"action"`), 1)
			case "unknown_root":
				raw = bytes.ReplaceAll(raw, []byte(ownerTests[0]), []byte("TestOtherRoot"))
			case "fail":
				raw = bytes.Replace(raw, []byte(`"Action":"pass"`), []byte(`"Action":"fail"`), 1)
			case "skip":
				raw = bytes.Replace(raw, []byte(`"Action":"pass"`), []byte(`"Action":"skip"`), 1)
			case "incomplete_package":
				lines := bytes.Split(raw, []byte("\n"))
				raw = bytes.Join(lines[:len(lines)-2], []byte("\n"))
				raw = append(raw, '\n')
			case "trailing_event":
				raw = append(raw, good...)
			case "line_cap":
				raw = bytes.Repeat([]byte(" "), lineLimit+1)
			case "total_cap":
				lines := bytes.SplitN(good, []byte("\n"), 2)
				var buffer bytes.Buffer
				buffer.Write(lines[0])
				buffer.WriteByte('\n')
				output, _ := json.Marshal(map[string]string{"Action": "output", "Package": packageName, "Output": strings.Repeat("x", 64<<10)})
				for buffer.Len() <= censusLimit {
					buffer.Write(output)
					buffer.WriteByte('\n')
				}
				buffer.Write(lines[1])
				raw = buffer.Bytes()
			case "missing_child", "roots_only":
				child := ownerTests[0] + "/" + ownerChildren[ownerTests[0]][0]
				var buffer bytes.Buffer
				for _, line := range bytes.Split(raw, []byte("\n")) {
					if len(line) == 0 {
						continue
					}
					var event testEvent
					if json.Unmarshal(line, &event) != nil {
						t.Fatal("census fixture invalid")
					}
					if (name == "missing_child" && event.Test == child) || (name == "roots_only" && strings.Contains(event.Test, "/")) {
						continue
					}
					buffer.Write(line)
					buffer.WriteByte('\n')
				}
				raw = buffer.Bytes()
			case "extra_child", "parent_pass_before_child":
				parent := ownerTests[0]
				pass, _ := json.Marshal(testEvent{Action: "pass", Package: packageName, Test: parent})
				if name == "extra_child" {
					unknownRun, _ := json.Marshal(testEvent{Action: "run", Package: packageName, Test: parent + "/unreviewed_child"})
					unknownPass, _ := json.Marshal(testEvent{Action: "pass", Package: packageName, Test: parent + "/unreviewed_child"})
					replacement := append(append(append(unknownRun, '\n'), unknownPass...), '\n')
					replacement = append(replacement, pass...)
					raw = bytes.Replace(raw, pass, replacement, 1)
				} else {
					parentRun, _ := json.Marshal(testEvent{Action: "run", Package: packageName, Test: parent})
					raw = bytes.Replace(raw, append(pass, '\n'), nil, 1)
					raw = bytes.Replace(raw, parentRun, append(append(append([]byte(nil), parentRun...), '\n'), pass...), 1)
				}
			case "time_object", "time_bad_date", "time_noncanonical", "elapsed_string", "elapsed_negative", "elapsed_nonfinite", "output_array", "failedbuild_number", "output_wrong_action", "elapsed_wrong_action", "failedbuild_wrong_action", "missing_output_field":
				value := `"Time":{}`
				anchor := `"Action":"start"`
				switch name {
				case "time_bad_date":
					value = `"Time":"2026-02-30T12:00:00Z"`
				case "time_noncanonical":
					value = `"Time":"2026-10-13T1:00:00Z"`
				case "elapsed_string":
					value, anchor = `"Elapsed":"bad"`, `"Action":"pass"`
				case "elapsed_negative":
					value, anchor = `"Elapsed":-1`, `"Action":"pass"`
				case "elapsed_nonfinite":
					value, anchor = `"Elapsed":1e1000`, `"Action":"pass"`
				case "output_array":
					value, anchor = `"Output":[]`, `"Action":"start"`
				case "failedbuild_number":
					value = `"FailedBuild":123`
				case "output_wrong_action":
					value = `"Output":"original text"`
				case "elapsed_wrong_action":
					value = `"Elapsed":0`
				case "failedbuild_wrong_action":
					value = `"FailedBuild":"original/package"`
				case "missing_output_field":
					value = `"Time":"2026-10-13T12:00:00Z"`
					anchor = `"Action":"output"`
					raw = bytes.Replace(raw, []byte(`"Action":"start"`), []byte(anchor), 1)
				}
				raw = bytes.Replace(raw, []byte(anchor), []byte(anchor+","+value), 1)
			}
			if verifyCensus(bytes.NewReader(raw)) == nil {
				t.Fatal("incomplete original census admitted")
			}
		})
	}
	t.Run("real_shaped_package_fields", func(t *testing.T) {
		var buffer bytes.Buffer
		for _, line := range bytes.Split(good, []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			var fields map[string]any
			if json.Unmarshal(line, &fields) != nil {
				t.Fatal("original frame fixture invalid")
			}
			fields["Time"] = "2026-10-13T12:00:00.123456789Z"
			if fields["Action"] == "pass" {
				fields["Elapsed"] = 0.001
			}
			if fields["Action"] == "pass" && fields["Test"] == nil {
				output, _ := json.Marshal(map[string]any{"Time": "2026-10-13T12:00:00Z", "Action": "output", "Package": packageName, "Output": "ok original source package\n"})
				buffer.Write(output)
				buffer.WriteByte('\n')
			}
			raw, _ := json.Marshal(fields)
			buffer.Write(raw)
			buffer.WriteByte('\n')
		}
		if verifyCensus(bytes.NewReader(buffer.Bytes())) != nil {
			t.Fatal("legitimate typed package fields and absent Test refused")
		}
	})
	t.Run("fixed_private_owner_input", func(t *testing.T) {
		root, path := testRoot(t)
		if os.Mkdir(filepath.Join(path, ownerRoot), 0700) != nil {
			t.Fatal("fixture mkdir failed")
		}
		writeFile(t, filepath.Join(path, ownerRoot, "owner-tests.jsonl"), good)
		writeFile(t, filepath.Join(path, ownerRoot, "owner-tests.stderr"), nil)
		writeFile(t, filepath.Join(path, ownerRoot, "owner-tests-tee.stderr"), nil)
		if verifyOwnerTests(root) != nil {
			t.Fatal("original fixed owner census refused")
		}
	})
}

func TestRetentionOwnerCorporaIsolation(t *testing.T) {
	root, path := preparedRoot(t)
	if start(root, "capacity") != nil || finish(root, "capacity", 1, 0, 1) != nil {
		t.Fatal("first failed original not retained")
	}
	failed := readFile(t, corpusFile(path, "capacity", "status.json"))
	for _, name := range []string{"guest-wire", "notify-owner"} {
		if start(root, name) != nil || finish(root, name, 0, 0, 0) != nil {
			t.Fatal("independent original refused")
		}
	}
	if !bytes.Equal(failed, readFile(t, corpusFile(path, "capacity", "status.json"))) {
		t.Fatal("later corpus changed prior red status")
	}
}

func TestRetentionOwnerPrivatePaths(t *testing.T) {
	t.Run("symlinked_corpus", func(t *testing.T) {
		root, path := preparedRoot(t)
		original := filepath.Join(path, corpusRoot, "capacity")
		moved := filepath.Join(path, corpusRoot, "original-capacity")
		if os.Rename(original, moved) != nil || os.Symlink("original-capacity", original) != nil {
			t.Fatal("fixture symlink failed")
		}
		before := readFile(t, filepath.Join(moved, "status.json"))
		if start(root, "capacity") == nil || !bytes.Equal(before, readFile(t, filepath.Join(moved, "status.json"))) {
			t.Fatal("symlinked corpus adopted")
		}
	})
	t.Run("public_corpus_directory", func(t *testing.T) {
		root, path := preparedRoot(t)
		if os.Chmod(filepath.Join(path, corpusRoot, "capacity"), 0755) != nil {
			t.Fatal("fixture chmod failed")
		}
		if start(root, "capacity") == nil {
			t.Fatal("nonprivate corpus admitted")
		}
	})
	for _, name := range []string{"regular_to_fifo_after_lstat", "same_inode_symlink_after_lstat", "same_inode_directory_symlink_after_lstat", "pinned_directory_survives_name_replacement", "fixed_basename_only", "closed_pin_never_reused"} {
		t.Run(name, func(t *testing.T) {
			root, path := preparedRoot(t)
			dir, err := openDirectory(root, corpusRoot)
			if err != nil {
				t.Fatal("original directory pin refused")
			}
			t.Cleanup(func() {
				if dir.bridge != nil && dir.Close() != nil {
					t.Error("original directory close failed")
				}
			})
			if name == "same_inode_directory_symlink_after_lstat" || name == "pinned_directory_survives_name_replacement" {
				before, err := dir.Lstat("capacity")
				if err != nil {
					_ = dir.Close()
					t.Fatal("original directory metadata refused")
				}
				var child *retainedRoot
				if name == "pinned_directory_survives_name_replacement" {
					child, err = openDirectory(dir, "capacity")
					if err != nil {
						_ = dir.Close()
						t.Fatal("original child pin refused")
					}
					t.Cleanup(func() {
						if child.bridge != nil && child.Close() != nil {
							t.Error("original child close failed")
						}
					})
				}
				original := filepath.Join(path, corpusRoot, "capacity")
				moved := filepath.Join(path, corpusRoot, "original-capacity")
				if os.Rename(original, moved) != nil || os.Symlink("original-capacity", original) != nil {
					t.Fatal("actual directory swap fixture refused")
				}
				if child == nil {
					adopted, err := openDirectoryObserved(dir, "capacity", before)
					if adopted != nil {
						_ = adopted.Close()
					}
					if err == nil {
						t.Fatal("same-inode directory alias adopted")
					}
				} else {
					if pristine(child, "capacity") != nil || child.Close() != nil {
						t.Fatal("actual pinned original lost after name replacement")
					}
				}
				if dir.Close() != nil {
					t.Fatal("original parent close refused")
				}
				return
			}
			child, err := openDirectory(dir, "capacity")
			if err != nil {
				_ = dir.Close()
				t.Fatal("original child pin refused")
			}
			t.Cleanup(func() {
				if child.bridge != nil && child.Close() != nil {
					t.Error("original child close failed")
				}
			})
			file := corpusFile(path, "capacity", rawNames[0])
			before, err := child.Lstat(rawNames[0])
			if err != nil {
				t.Fatal("original file metadata refused")
			}
			switch name {
			case "regular_to_fifo_after_lstat":
				if os.Remove(file) != nil || syscall.Mkfifo(file, 0600) != nil {
					t.Fatal("actual FIFO swap refused")
				}
			case "same_inode_symlink_after_lstat":
				moved := filepath.Join(filepath.Dir(file), "original-raw")
				if os.Rename(file, moved) != nil || os.Symlink("original-raw", file) != nil {
					t.Fatal("actual same-inode symlink swap refused")
				}
			case "fixed_basename_only":
				for _, alias := range []string{"./original.jsonl", "../capacity/original.jsonl", "/original.jsonl", "original.jsonl/", "other.jsonl"} {
					opened, err := openFixed(child, alias, os.O_RDONLY, 0)
					if opened != nil {
						_ = opened.Close()
					}
					if err == nil {
						t.Fatal("caller alias passed native open")
					}
				}
			case "closed_pin_never_reused":
				// Dispose the actual pin while its bridge still exists. The owner
				// must refuse before using that FD number; Close propagates error.
				if child.directory.Close() != nil {
					t.Fatal("actual pin close refused")
				}
			}
			if name != "fixed_basename_only" {
				opened, err := openPrivateObserved(child, rawNames[0], before)
				if opened != nil {
					_ = opened.Close()
				}
				if err == nil {
					t.Fatal("unsafe final-name or disposed pin adopted")
				}
			}
			closeErr := child.Close()
			if (name == "closed_pin_never_reused") != (closeErr != nil) || child.Close() == nil || dir.Close() != nil {
				t.Fatal("original pin/bridge Close ownership lost")
			}
		})
	}
}

func TestRetentionOwnerInterruptedInvocation(t *testing.T) {
	for _, name := range []string{"exclusive_start_marker", "start_publication_pending", "exclusive_finish_marker", "finish_publication_pending"} {
		t.Run(name, func(t *testing.T) {
			root, path := preparedRoot(t)
			if strings.HasPrefix(name, "finish") || name == "exclusive_finish_marker" {
				if start(root, "capacity") != nil {
					t.Fatal("start refused")
				}
			}
			file := "started.json"
			switch name {
			case "start_publication_pending":
				file = "status-started.pending"
			case "exclusive_finish_marker":
				file = "returned.json"
			case "finish_publication_pending":
				file = "status-returned.pending"
			}
			writeFile(t, corpusFile(path, "capacity", file), []byte("partial original\n"))
			before := readFile(t, corpusFile(path, "capacity", "status.json"))
			var err error
			if strings.HasPrefix(name, "finish") || name == "exclusive_finish_marker" {
				err = finish(root, "capacity", 0, 0, 0)
			} else {
				err = start(root, "capacity")
			}
			if err == nil || !bytes.Equal(before, readFile(t, corpusFile(path, "capacity", "status.json"))) || !bytes.Equal(readFile(t, corpusFile(path, "capacity", file)), []byte("partial original\n")) {
				t.Fatal("interrupted original repaired")
			}
		})
	}
}
