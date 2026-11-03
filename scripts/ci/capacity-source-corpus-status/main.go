//go:build linux

// This owner retains Source corpus status. It never invokes a workload and its
// records do not grant native qualification, noStart or production authority.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	corpusRoot  = "capacity-postgres-original"
	ownerRoot   = "capacity-source-corpus-go-owner"
	stateSchema = "capacity_original_source_corpus_status_v1"
	packageName = "github.com/dakasa-yggdrasil/yggdrasil-core/scripts/ci/capacity-source-corpus-status"
	stateLimit  = 4096
	censusLimit = 32 << 20
	lineLimit   = 1 << 20
)

var errRetention = errors.New("original Source corpus retention refused or incomplete")
var corpusNames = []string{"capacity", "guest-wire", "notify-owner"}
var rawNames = []string{"original.jsonl", "go-test.stderr", "tee.stderr", "census.stdout", "census.stderr"}
var ownerTests = []string{
	"TestRetentionOwnerPreparation", "TestRetentionOwnerPristineStart",
	"TestRetentionOwnerFinishReturns", "TestRetentionOwnerRawPreservation",
	"TestRetentionOwnerClosedCLI", "TestRetentionOwnerBoundedState",
	"TestRetentionOwnerOriginalCaseCensus", "TestRetentionOwnerCorporaIsolation",
	"TestRetentionOwnerPrivatePaths", "TestRetentionOwnerInterruptedInvocation",
}

// This is an expected Source manifest, not a roster inferred from observed
// events. Every listed root and child must run and pass exactly once.
var ownerChildren = map[string][]string{
	"TestRetentionOwnerPreparation":           {"complete_private_original", "preexisting_root_preserved", "partial_preparation_never_starts"},
	"TestRetentionOwnerPristineStart":         {"original_once", "stale_status", "missing_raw", "nonempty_raw", "wrong_mode", "symlink_raw", "hardlink_raw"},
	"TestRetentionOwnerFinishReturns":         {"no_original_start", "interrupted_return_marker", "actual_returns_000", "actual_returns_001", "actual_returns_010", "actual_returns_011", "actual_returns_100", "actual_returns_101", "actual_returns_110", "actual_returns_111"},
	"TestRetentionOwnerRawPreservation":       {},
	"TestRetentionOwnerClosedCLI":             {"compiled_original_prepare_start_finish", "compiled_missing_runner_temp", "compiled_relative_runner_temp", "compiled_nondirectory_runner_temp", "compiled_symlinked_runner_temp", "compiled_wrong_argv", "compiled_fifo_private_input", "compiled_owner_census", "compiled_cancelled_original_context"},
	"TestRetentionOwnerBoundedState":          {"over_cap", "duplicate", "case_alias", "unknown", "omitted", "null", "trailing", "non_utf8"},
	"TestRetentionOwnerOriginalCaseCensus":    {"real_shaped_package_fields", "fixed_private_owner_input", "missing_root", "duplicate_run", "duplicate_key", "case_alias", "unknown_root", "fail", "skip", "incomplete_package", "trailing_event", "line_cap", "total_cap", "missing_child", "extra_child", "roots_only", "parent_pass_before_child", "time_object", "time_bad_date", "time_noncanonical", "elapsed_string", "elapsed_negative", "elapsed_nonfinite", "output_array", "failedbuild_number", "output_wrong_action", "elapsed_wrong_action", "failedbuild_wrong_action", "missing_output_field"},
	"TestRetentionOwnerCorporaIsolation":      {},
	"TestRetentionOwnerPrivatePaths":          {"symlinked_corpus", "public_corpus_directory", "regular_to_fifo_after_lstat", "same_inode_symlink_after_lstat", "same_inode_directory_symlink_after_lstat", "pinned_directory_survives_name_replacement", "fixed_basename_only", "closed_pin_never_reused"},
	"TestRetentionOwnerInterruptedInvocation": {"exclusive_start_marker", "start_publication_pending", "exclusive_finish_marker", "finish_publication_pending"},
}

// The kernel directory descriptor stays owned until every operation on its
// /proc bridge has returned. Closing the bridge first prevents a closed/reused
// descriptor number from becoming another root. No descriptor map is borrowed.
type retainedRoot struct {
	bridge    *os.Root
	directory *os.File
}

func fixedName(name string) bool {
	for _, allowed := range []string{corpusRoot, ownerRoot, "capacity", "guest-wire", "notify-owner", "preparation.json", "prepared.json", "status.json", "started.json", "returned.json", "status-started.pending", "status-returned.pending", "owner-tests.jsonl", "owner-tests.stderr", "owner-tests-tee.stderr"} {
		if name == allowed {
			return true
		}
	}
	for _, allowed := range rawNames {
		if name == allowed {
			return true
		}
	}
	return false
}

func retainedDirectory(file *os.File, before os.FileInfo, private bool) (*retainedRoot, error) {
	after, err := file.Stat()
	if err != nil || !after.IsDir() || (private && !privateInfo(after, true)) || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, errRetention
	}
	// This proc path is constructed only from this still-held kernel FD. It is
	// not a caller alias and is never reopened after the FD has been closed.
	bridge, err := os.OpenRoot("/proc/self/fd/" + strconv.Itoa(int(file.Fd())))
	if err != nil {
		_ = file.Close()
		return nil, errRetention
	}
	anchored, statErr := bridge.Stat(".")
	if statErr != nil || !os.SameFile(after, anchored) {
		_ = bridge.Close()
		_ = file.Close()
		return nil, errRetention
	}
	return &retainedRoot{bridge: bridge, directory: file}, nil
}

func openRetainedRoot(path string) (*retainedRoot, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.HasPrefix(path, "/proc/") {
		return nil, errRetention
	}
	original, err := os.OpenRoot(path)
	if err != nil {
		return nil, errRetention
	}
	before, statErr := original.Stat(".")
	file, openErr := os.OpenFile(original.Name(), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	closeErr := original.Close()
	if statErr != nil || openErr != nil || closeErr != nil {
		if file != nil {
			_ = file.Close()
		}
		return nil, errRetention
	}
	return retainedDirectory(file, before, false)
}

func (root *retainedRoot) descriptor() (int, error) {
	if root == nil || root.bridge == nil || root.directory == nil {
		return -1, errRetention
	}
	actual, fileErr := root.directory.Stat()
	anchored, rootErr := root.bridge.Stat(".")
	if fileErr != nil || rootErr != nil || !actual.IsDir() || !os.SameFile(actual, anchored) {
		return -1, errRetention
	}
	return int(root.directory.Fd()), nil
}

func (root *retainedRoot) Close() error {
	if root == nil || root.bridge == nil || root.directory == nil {
		return errRetention
	}
	bridgeErr := root.bridge.Close()
	fileErr := root.directory.Close()
	root.bridge, root.directory = nil, nil
	if bridgeErr != nil || fileErr != nil {
		return errRetention
	}
	return nil
}

func (root *retainedRoot) Lstat(name string) (os.FileInfo, error) {
	if !fixedName(name) {
		return nil, errRetention
	}
	if _, err := root.descriptor(); err != nil {
		return nil, errRetention
	}
	return root.bridge.Lstat(name)
}

func (root *retainedRoot) Mkdir(name string, mode os.FileMode) error {
	if !fixedName(name) || mode != 0700 {
		return errRetention
	}
	if _, err := root.descriptor(); err != nil {
		return errRetention
	}
	return root.bridge.Mkdir(name, mode)
}

func (root *retainedRoot) Rename(old, next string) error {
	if !fixedName(old) || !fixedName(next) {
		return errRetention
	}
	if _, err := root.descriptor(); err != nil {
		return errRetention
	}
	return root.bridge.Rename(old, next)
}

func openFixed(root *retainedRoot, name string, flags int, mode uint32) (*os.File, error) {
	if !fixedName(name) {
		return nil, errRetention
	}
	directory, err := root.descriptor()
	if err != nil {
		return nil, errRetention
	}
	fd, err := syscall.Openat(directory, name, flags|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, mode)
	runtime.KeepAlive(root)
	if err != nil {
		return nil, errRetention
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errRetention
	}
	return file, nil
}

type corpusState struct {
	Schema              string `json:"schema"`
	Corpus              string `json:"corpus"`
	State               string `json:"state"`
	NativeQualification string `json:"native_qualification"`
	LocalSourceClaim    string `json:"local_source_claim"`
	GoExit              *int   `json:"go_exit"`
	TeeExit             *int   `json:"tee_exit"`
	CensusExit          *int   `json:"census_exit"`
}

func initialState(corpus string) corpusState {
	return corpusState{Schema: stateSchema, Corpus: corpus, State: "NOT_STARTED", NativeQualification: "HOLD", LocalSourceClaim: "NONE"}
}

func canonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, errRetention
	}
	return append(raw, '\n'), nil
}

// Canonical byte equality closes duplicate/case/unknown keys, null/omission,
// trailing bytes and encodings without a second permissive JSON decoder.
func readState(root *retainedRoot, name string) (corpusState, []byte, error) {
	var state corpusState
	raw, err := readPrivate(root, name, stateLimit)
	if err != nil || !utf8.Valid(raw) || json.Unmarshal(raw, &state) != nil {
		return state, nil, errRetention
	}
	want, err := canonical(state)
	if err != nil || !bytes.Equal(raw, want) {
		return state, nil, errRetention
	}
	return state, raw, nil
}

func privateInfo(info os.FileInfo, directory bool) bool {
	if info == nil || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if directory {
		return info.IsDir() && info.Mode().Perm() == 0700
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return info.Mode().IsRegular() && info.Mode().Perm() == 0600 && ok && uint64(stat.Nlink) == 1
}

func openPrivate(root *retainedRoot, name string) (*os.File, error) {
	before, err := root.Lstat(name)
	if err != nil || !privateInfo(before, false) {
		return nil, errRetention
	}
	return openPrivateObserved(root, name, before)
}

// The actual kernel open is independently testable after the real prior Lstat;
// it cannot unwrap ELOOP or wait for a FIFO writer before rejecting its type.
func openPrivateObserved(root *retainedRoot, name string, before os.FileInfo) (*os.File, error) {
	if !privateInfo(before, false) {
		return nil, errRetention
	}
	file, err := openFixed(root, name, os.O_RDONLY, 0)
	if err != nil {
		return nil, errRetention
	}
	after, err := file.Stat()
	if err != nil || !privateInfo(after, false) || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, errRetention
	}
	return file, nil
}

func readPrivate(root *retainedRoot, name string, limit int64) ([]byte, error) {
	file, err := openPrivate(root, name)
	if err != nil {
		return nil, errRetention
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(raw)) > limit {
		return nil, errRetention
	}
	return raw, nil
}

func createPrivate(root *retainedRoot, name string, raw []byte) error {
	file, err := openFixed(root, name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errRetention
	}
	opened, statErr := file.Stat()
	if statErr != nil || !privateInfo(opened, false) {
		_ = file.Close()
		return errRetention
	}
	n, writeErr := file.Write(raw)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || n != len(raw) || syncErr != nil || closeErr != nil {
		return errRetention
	}
	info, err := root.Lstat(name)
	if err != nil || !privateInfo(info, false) || !os.SameFile(opened, info) {
		return errRetention
	}
	return nil
}

func openDirectory(root *retainedRoot, name string) (*retainedRoot, error) {
	before, err := root.Lstat(name)
	if err != nil || !privateInfo(before, true) {
		return nil, errRetention
	}
	return openDirectoryObserved(root, name, before)
}

func openDirectoryObserved(root *retainedRoot, name string, before os.FileInfo) (*retainedRoot, error) {
	if !privateInfo(before, true) {
		return nil, errRetention
	}
	file, err := openFixed(root, name, os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, errRetention
	}
	return retainedDirectory(file, before, true)
}

func prepare(root *retainedRoot) error {
	// Never adopt, repair, delete or truncate a prior/partial original directory.
	if root.Mkdir(corpusRoot, 0700) != nil {
		return errRetention
	}
	base, err := openDirectory(root, corpusRoot)
	if err != nil {
		return errRetention
	}
	for _, corpus := range corpusNames {
		if base.Mkdir(corpus, 0700) != nil {
			_ = base.Close()
			return errRetention
		}
		dir, err := openDirectory(base, corpus)
		if err != nil {
			_ = base.Close()
			return errRetention
		}
		for _, name := range rawNames {
			if createPrivate(dir, name, nil) != nil {
				_ = dir.Close()
				_ = base.Close()
				return errRetention
			}
		}
		raw, err := canonical(initialState(corpus))
		if err != nil || createPrivate(dir, "status.json", raw) != nil || createPrivate(dir, "prepared.json", raw) != nil {
			_ = dir.Close()
			_ = base.Close()
			return errRetention
		}
		if dir.Close() != nil {
			_ = base.Close()
			return errRetention
		}
	}
	complete, err := canonical(initialState("all"))
	if err != nil || createPrivate(base, "preparation.json", complete) != nil {
		_ = base.Close()
		return errRetention
	}
	if base.Close() != nil {
		return errRetention
	}
	return nil
}

func withCorpus(root *retainedRoot, corpus string, action func(*retainedRoot) error) error {
	valid := false
	for _, name := range corpusNames {
		valid = valid || name == corpus
	}
	if !valid {
		return errRetention
	}
	base, err := openDirectory(root, corpusRoot)
	if err != nil {
		return errRetention
	}
	complete, err := readPrivate(base, "preparation.json", stateLimit)
	want, marshalErr := canonical(initialState("all"))
	if err != nil || marshalErr != nil || !bytes.Equal(complete, want) {
		_ = base.Close()
		return errRetention
	}
	dir, err := openDirectory(base, corpus)
	if err != nil {
		_ = base.Close()
		return errRetention
	}
	actionErr := action(dir)
	dirErr, baseErr := dir.Close(), base.Close()
	if actionErr != nil || dirErr != nil || baseErr != nil {
		return errRetention
	}
	return nil
}

func pristine(root *retainedRoot, corpus string) error {
	want, err := canonical(initialState(corpus))
	if err != nil {
		return errRetention
	}
	for _, name := range []string{"prepared.json", "status.json"} {
		_, raw, err := readState(root, name)
		if err != nil || !bytes.Equal(raw, want) {
			return errRetention
		}
	}
	for _, name := range rawNames {
		raw, err := readPrivate(root, name, 0)
		if err != nil || len(raw) != 0 {
			return errRetention
		}
	}
	return nil
}

func publishStatus(root *retainedRoot, stage string, raw []byte) error {
	// The stage marker was exclusively created first. Interrupted publication
	// leaves the original marker/pending bytes and permanently refuses a retry.
	pending := "status-" + stage + ".pending"
	if createPrivate(root, pending, raw) != nil || root.Rename(pending, "status.json") != nil {
		return errRetention
	}
	return nil
}

func start(root *retainedRoot, corpus string) error {
	return withCorpus(root, corpus, func(dir *retainedRoot) error {
		if pristine(dir, corpus) != nil {
			return errRetention
		}
		state := initialState(corpus)
		state.State = "INVOCATION_ABOUT_TO_START"
		raw, err := canonical(state)
		if err != nil || createPrivate(dir, "started.json", raw) != nil {
			return errRetention
		}
		return publishStatus(dir, "started", raw)
	})
}

func finish(root *retainedRoot, corpus string, goExit, teeExit, censusExit int) error {
	if goExit < 0 || goExit > 255 || teeExit < 0 || teeExit > 255 || censusExit < 0 || censusExit > 255 {
		return errRetention
	}
	return withCorpus(root, corpus, func(dir *retainedRoot) error {
		state := initialState(corpus)
		state.State = "INVOCATION_ABOUT_TO_START"
		want, err := canonical(state)
		if err != nil {
			return errRetention
		}
		for _, name := range []string{"started.json", "status.json"} {
			_, raw, err := readState(dir, name)
			if err != nil || !bytes.Equal(raw, want) {
				return errRetention
			}
		}
		state.State = "FAILED_OR_INCOMPLETE"
		if goExit == 0 && teeExit == 0 && censusExit == 0 {
			state.State = "SOURCE_TESTS_AND_CENSUS_PASSED"
		}
		state.GoExit, state.TeeExit, state.CensusExit = &goExit, &teeExit, &censusExit
		raw, err := canonical(state)
		if err != nil || createPrivate(dir, "returned.json", raw) != nil {
			return errRetention
		}
		return publishStatus(dir, "returned", raw)
	})
}

type testEvent struct {
	Time        *time.Time `json:"Time,omitempty"`
	Action      string     `json:"Action"`
	Package     string     `json:"Package"`
	Test        string     `json:"Test,omitempty"`
	Elapsed     *float64   `json:"Elapsed,omitempty"`
	Output      *string    `json:"Output,omitempty"`
	FailedBuild *string    `json:"FailedBuild,omitempty"`
}

func decodeEvent(raw []byte) (testEvent, error) {
	var event testEvent
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return event, errRetention
	}
	keys := map[string]bool{}
	allowed := map[string]bool{"Time": true, "Action": true, "Package": true, "Test": true, "Elapsed": true, "Output": true, "FailedBuild": true}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] || keys[key] {
			return event, errRetention
		}
		keys[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(value, []byte("null")) {
			return event, errRetention
		}
		var target *string
		switch key {
		case "Action":
			target = &event.Action
		case "Package":
			target = &event.Package
		case "Test":
			target = &event.Test
		case "Time":
			var text string
			if json.Unmarshal(value, &text) != nil {
				return event, errRetention
			}
			parsed, parseErr := time.Parse(time.RFC3339Nano, text)
			if parseErr != nil || parsed.IsZero() || parsed.Format(time.RFC3339Nano) != text {
				return event, errRetention
			}
			event.Time = &parsed
		case "Elapsed":
			var elapsed float64
			if json.Unmarshal(value, &elapsed) != nil || math.IsNaN(elapsed) || math.IsInf(elapsed, 0) || elapsed < 0 {
				return event, errRetention
			}
			event.Elapsed = &elapsed
		case "Output", "FailedBuild":
			var text string
			if json.Unmarshal(value, &text) != nil {
				return event, errRetention
			}
			if key == "Output" {
				event.Output = &text
			} else {
				if text == "" {
					return event, errRetention
				}
				event.FailedBuild = &text
			}
		}
		if target != nil && json.Unmarshal(value, target) != nil {
			return event, errRetention
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return event, errRetention
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || !keys["Action"] || !keys["Package"] {
		return event, errRetention
	}
	// Go 1.25 test2json emits these typed optional fields. A package record
	// legitimately omits Test; arbitrary shapes or action aliases do not.
	switch event.Action {
	case "start", "run", "pause", "cont":
		if event.Elapsed != nil || event.Output != nil || event.FailedBuild != nil {
			return event, errRetention
		}
	case "output":
		if event.Output == nil || event.Elapsed != nil || event.FailedBuild != nil {
			return event, errRetention
		}
	case "pass", "skip":
		if event.Output != nil || event.FailedBuild != nil {
			return event, errRetention
		}
	case "fail":
		if event.Output != nil || (event.FailedBuild != nil && event.Test != "") {
			return event, errRetention
		}
	default:
		return event, errRetention
	}
	return event, nil
}

func verifyCensus(reader io.Reader) error {
	limited := &io.LimitedReader{R: reader, N: censusLimit + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), lineLimit+1)
	runs, passes := map[string]int{}, map[string]int{}
	pkgStarts, pkgPasses := 0, 0
	roots := map[string]bool{}
	expected := map[string]bool{}
	for _, name := range ownerTests {
		roots[name] = true
		expected[name] = true
		for _, child := range ownerChildren[name] {
			expected[name+"/"+child] = true
		}
	}
	for scanner.Scan() {
		line := scanner.Bytes()
		event, decodeErr := decodeEvent(line)
		if len(line) == 0 || len(line) > lineLimit || !utf8.Valid(line) || decodeErr != nil || event.Package != packageName || pkgPasses != 0 {
			return errRetention
		}
		// Go emits Time/Elapsed/Output too; retain original JSON unchanged. Count
		// only actual typed actions, with no repair or synthetic package events.
		if event.Test == "" {
			switch event.Action {
			case "start":
				pkgStarts++
				if pkgStarts != 1 {
					return errRetention
				}
			case "pass":
				if pkgStarts != 1 {
					return errRetention
				}
				pkgPasses++
			case "output":
				if pkgStarts != 1 {
					return errRetention
				}
			default:
				return errRetention
			}
			continue
		}
		parts := strings.Split(event.Test, "/")
		if pkgStarts != 1 || !expected[event.Test] || !roots[parts[0]] || len(event.Test) > 512 || (len(parts) > 1 && (runs[parts[0]] != 1 || passes[parts[0]] != 0)) {
			return errRetention
		}
		for _, part := range parts {
			if part == "" {
				return errRetention
			}
		}
		switch event.Action {
		case "run":
			runs[event.Test]++
			if runs[event.Test] != 1 || len(runs) > 4096 {
				return errRetention
			}
		case "pass":
			if len(parts) == 1 {
				for _, child := range ownerChildren[event.Test] {
					if runs[event.Test+"/"+child] != 1 || passes[event.Test+"/"+child] != 1 {
						return errRetention
					}
				}
			}
			passes[event.Test]++
			if runs[event.Test] != 1 || passes[event.Test] != 1 {
				return errRetention
			}
		case "output", "pause", "cont":
			if runs[event.Test] != 1 || passes[event.Test] != 0 {
				return errRetention
			}
		default:
			return errRetention
		}
	}
	if scanner.Err() != nil || limited.N == 0 || pkgStarts != 1 || pkgPasses != 1 {
		return errRetention
	}
	if len(runs) != len(expected) || len(passes) != len(expected) {
		return errRetention
	}
	for name := range expected {
		if runs[name] != 1 || passes[name] != 1 {
			return errRetention
		}
	}
	for name, count := range runs {
		if count != 1 || passes[name] != 1 {
			return errRetention
		}
	}
	return nil
}

func verifyOwnerTests(root *retainedRoot) error {
	dir, err := openDirectory(root, ownerRoot)
	if err != nil {
		return errRetention
	}
	for _, name := range []string{"owner-tests.stderr", "owner-tests-tee.stderr"} {
		if _, err := readPrivate(dir, name, 1<<20); err != nil {
			_ = dir.Close()
			return errRetention
		}
	}
	file, err := openPrivate(dir, "owner-tests.jsonl")
	if err != nil {
		_ = dir.Close()
		return errRetention
	}
	verifyErr := verifyCensus(file)
	fileErr, dirErr := file.Close(), dir.Close()
	if verifyErr != nil || fileErr != nil || dirErr != nil {
		return errRetention
	}
	return nil
}

func parseExit(raw string) (int, error) {
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 || value > 255 || strconv.Itoa(value) != raw {
		return 0, errRetention
	}
	return value, nil
}

func run(root *retainedRoot, args []string) error {
	if len(args) == 1 && args[0] == "prepare" {
		return prepare(root)
	}
	if len(args) == 1 && args[0] == "verify-owner-tests" {
		return verifyOwnerTests(root)
	}
	if len(args) == 2 && args[0] == "start" {
		return start(root, args[1])
	}
	if len(args) == 5 && args[0] == "finish" {
		goExit, goErr := parseExit(args[2])
		teeExit, teeErr := parseExit(args[3])
		censusExit, censusErr := parseExit(args[4])
		if goErr != nil || teeErr != nil || censusErr != nil {
			return errRetention
		}
		return finish(root, args[1], goExit, teeExit, censusExit)
	}
	return errRetention
}

func main() {
	path := os.Getenv("RUNNER_TEMP")
	if !filepath.IsAbs(path) {
		fmt.Fprintln(os.Stderr, errRetention)
		os.Exit(1)
	}
	root, err := openRetainedRoot(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, errRetention)
		os.Exit(1)
	}
	runErr := run(root, os.Args[1:])
	closeErr := root.Close()
	if runErr != nil || closeErr != nil {
		fmt.Fprintln(os.Stderr, errRetention)
		os.Exit(1)
	}
}
