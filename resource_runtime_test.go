package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

type capacityShortWriter struct{}

func (capacityShortWriter) Write(raw []byte) (int, error) { return len(raw) / 2, nil }

func capacityStat(start uint64, state, comm string) []byte {
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[19] = state, strconv.FormatUint(start, 10)
	return []byte("1 (" + comm + ") " + strings.Join(fields, " ") + "\n")
}

func capacityFiles() map[string][]byte {
	return map[string][]byte{
		pid1StatPath:   capacityStat(73119, "S", "private argv ) space"),
		selfCgroupPath: []byte("0::/\n"), pid1CgroupPath: []byte("0::/\n"),
		cpuMaxPath: []byte("200000 100000\n"), memoryMaxPath: []byte("536870912\n"),
	}
}

func capacityFixture(t *testing.T, before, after map[string][]byte) (func(string, int) ([]byte, error), *[]string) {
	t.Helper()
	calls := []string{}
	reader := func(path string, bound int) ([]byte, error) {
		t.Helper()
		files := before
		if len(calls) >= 5 {
			files = after
		}
		calls = append(calls, path)
		value, ok := files[path]
		if !ok {
			t.Fatalf("reader used an unapproved path: %q", path)
		}
		if bound <= 0 || len(value) > bound {
			return nil, errCPUCapacityRuntime
		}
		return append([]byte(nil), value...), nil
	}
	return reader, &calls
}

func TestCPUCapacityFiniteAndUnlimitedClosedABI(t *testing.T) {
	for _, unlimited := range []bool{false, true} {
		t.Run(strconv.FormatBool(unlimited), func(t *testing.T) {
			files := capacityFiles()
			if unlimited {
				files[cpuMaxPath], files[memoryMaxPath] = []byte("max 100000\n"), []byte("max\n")
			}
			read, calls := capacityFixture(t, files, files)
			value, err := readCPUCapacityRuntime(read)
			if err != nil || value.SchemaVersion != 1 || value.PID1StartTicks != 73119 || !value.SameCgroup || value.CPUPeriodMicros != 100000 || value.CPUUnlimited != unlimited || value.MemoryUnlimited != unlimited {
				t.Fatalf("wrong capacity result: %#v %v", value, err)
			}
			if unlimited {
				if value.CPUQuotaMicros != nil || value.MemoryMaxBytes != nil {
					t.Fatal("unlimited must have explicit null bounds")
				}
			} else if value.CPUQuotaMicros == nil || *value.CPUQuotaMicros != 200000 || value.MemoryMaxBytes == nil || *value.MemoryMaxBytes != 536870912 {
				t.Fatal("finite kernel limits changed")
			}
			wantCalls := []string{pid1StatPath, selfCgroupPath, pid1CgroupPath, cpuMaxPath, memoryMaxPath, pid1StatPath, selfCgroupPath, pid1CgroupPath, cpuMaxPath, memoryMaxPath}
			if !reflect.DeepEqual(*calls, wantCalls) {
				t.Fatal("fixed before/after read set changed")
			}
			var output, diagnostic bytes.Buffer
			code := printCPUCapacityRuntime(&output, &diagnostic, func() (cpuCapacityRuntime, error) { return value, nil })
			var fields map[string]json.RawMessage
			if code != 0 || diagnostic.Len() != 0 || json.Unmarshal(output.Bytes(), &fields) != nil || len(fields) != 8 || !bytes.HasSuffix(output.Bytes(), []byte("\n")) {
				t.Fatal("not one closed capacity JSON line")
			}
			for _, name := range []string{"schemaVersion", "pid1StartTicks", "sameCgroup", "cpuQuotaMicros", "cpuPeriodMicros", "cpuUnlimited", "memoryMaxBytes", "memoryUnlimited"} {
				if _, ok := fields[name]; !ok {
					t.Fatal("capacity ABI field missing")
				}
			}
			for _, private := range []string{"private argv", "/proc/", "/sys/", "cgroupPath", "publicKey", "keyID", "credential"} {
				if strings.Contains(output.String(), private) {
					t.Fatal("capacity output reflected private process/runtime fields")
				}
			}
		})
	}
}

func TestCPUCapacityRejectsUnsupportedIdentityStateAndMalformedLimits(t *testing.T) {
	cases := map[string]struct{ path, value string }{
		"v1": {selfCgroupPath, "2:cpu:/\n"}, "hybrid": {pid1CgroupPath, "0::/\n2:cpu:/\n"},
		"both_nonroot": {selfCgroupPath, "0::/other\n"}, "mismatch": {pid1CgroupPath, "0::/other\n"},
		"empty_cgroup": {selfCgroupPath, ""}, "unknown_cgroup": {pid1CgroupPath, "0::"},
		"zero_start":     {pid1StatPath, string(capacityStat(0, "S", "private"))},
		"wrong_pid":      {pid1StatPath, "2 (private) S " + strings.Repeat("0 ", 19)},
		"truncated_stat": {pid1StatPath, "1 (private) S 0"}, "missing_comm": {pid1StatPath, "1 private S " + strings.Repeat("0 ", 19)},
		"cpu_empty": {cpuMaxPath, ""}, "cpu_extra": {cpuMaxPath, "200000 100000 extra"},
		"cpu_negative": {cpuMaxPath, "-1 100000"}, "cpu_plus": {cpuMaxPath, "+1 100000"},
		"cpu_fraction": {cpuMaxPath, "0.5 100000"}, "cpu_zero": {cpuMaxPath, "0 100000"},
		"period_zero": {cpuMaxPath, "max 0"}, "period_max": {cpuMaxPath, "max max"},
		"overflow":     {cpuMaxPath, "18446744073709551616 100000"},
		"memory_empty": {memoryMaxPath, ""}, "memory_extra": {memoryMaxPath, "123 456"},
		"memory_negative": {memoryMaxPath, "-1"}, "memory_overflow": {memoryMaxPath, "18446744073709551616"},
		"memory_nul": {memoryMaxPath, "123\x00"},
	}
	for _, state := range []string{"Z", "X", "x", "T", "t", "?", "SS"} {
		cases["state_"+state] = struct{ path, value string }{pid1StatPath, string(capacityStat(73119, state, "private"))}
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			files := capacityFiles()
			files[change.path] = []byte(change.value)
			if name == "both_nonroot" {
				files[pid1CgroupPath] = []byte(change.value)
			}
			read, _ := capacityFixture(t, files, files)
			if value, err := readCPUCapacityRuntime(read); err != errCPUCapacityRuntime || value != (cpuCapacityRuntime{}) {
				t.Fatal("unsupported or malformed kernel observation accepted")
			}
		})
	}
}

func TestCPUCapacityRefusesChangesAcrossTheSameObservation(t *testing.T) {
	for name, change := range map[string]struct{ path, value string }{
		"new_pid1":  {pid1StatPath, string(capacityStat(73120, "S", "private"))},
		"cpu_quota": {cpuMaxPath, "300000 100000"}, "cpu_period": {cpuMaxPath, "200000 200000"},
		"cpu_unlimited": {cpuMaxPath, "max 100000"}, "memory_limit": {memoryMaxPath, "1073741824"},
		"memory_unlimited": {memoryMaxPath, "max"}, "changed_self_cgroup": {selfCgroupPath, "0::/moved"},
	} {
		t.Run(name, func(t *testing.T) {
			before, after := capacityFiles(), capacityFiles()
			after[change.path] = []byte(change.value)
			read, _ := capacityFixture(t, before, after)
			if _, err := readCPUCapacityRuntime(read); err != errCPUCapacityRuntime {
				t.Fatal("changed lifetime/limits accepted")
			}
		})
	}
	// Normal scheduling changes process state without changing its lifetime.
	before, after := capacityFiles(), capacityFiles()
	after[pid1StatPath] = capacityStat(73119, "R", "private")
	read, _ := capacityFixture(t, before, after)
	if _, err := readCPUCapacityRuntime(read); err != nil {
		t.Fatal("normal running/sleeping transition changed identity")
	}
}

func TestCPUCapacityOutputFailureAndInvalidDTOCannotSucceed(t *testing.T) {
	files := capacityFiles()
	read, _ := capacityFixture(t, files, files)
	valid, err := readCPUCapacityRuntime(read)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*cpuCapacityRuntime){
		"schema":               func(v *cpuCapacityRuntime) { v.SchemaVersion = 2 },
		"zero_start":           func(v *cpuCapacityRuntime) { v.PID1StartTicks = 0 },
		"identity":             func(v *cpuCapacityRuntime) { v.SameCgroup = false },
		"period":               func(v *cpuCapacityRuntime) { v.CPUPeriodMicros = 0 },
		"cpu_null":             func(v *cpuCapacityRuntime) { v.CPUQuotaMicros = nil },
		"cpu_contradiction":    func(v *cpuCapacityRuntime) { v.CPUUnlimited = true },
		"memory_null":          func(v *cpuCapacityRuntime) { v.MemoryMaxBytes = nil },
		"memory_contradiction": func(v *cpuCapacityRuntime) { v.MemoryUnlimited = true },
	} {
		t.Run(name, func(t *testing.T) {
			value := valid
			change(&value)
			var output, diagnostic bytes.Buffer
			if code := printCPUCapacityRuntime(&output, &diagnostic, func() (cpuCapacityRuntime, error) { return value, nil }); code != 1 || output.Len() != 0 || diagnostic.String() != "cpu capacity runtime unavailable\n" {
				t.Fatal("invalid output DTO became a successful observation")
			}
		})
	}
	var diagnostic bytes.Buffer
	if code := printCPUCapacityRuntime(capacityShortWriter{}, &diagnostic, func() (cpuCapacityRuntime, error) { return valid, nil }); code != 1 || diagnostic.String() != "cpu capacity runtime unavailable\n" {
		t.Fatal("short output write was reported as success")
	}
}

func TestCapacityFileReadIsBoundedAndRejectsUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"missing", "empty", "oversize", "directory", "symlink", "fifo", "regular"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "kernel-file")
			switch kind {
			case "empty", "oversize", "regular":
				data := []byte("123\n")
				if kind == "empty" {
					data = nil
				}
				if kind == "oversize" {
					data = bytes.Repeat([]byte("1"), 129)
				}
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.WriteFile(filepath.Join(dir, "private"), []byte("123\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(dir, "private"), path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			data, err := readCapacityFile(path, 128)
			if kind == "regular" {
				if err != nil || string(data) != "123\n" {
					t.Fatal("bounded regular file was not read")
				}
			} else if err != errCPUCapacityRuntime || data != nil {
				t.Fatal("unsafe or unbounded kernel file accepted")
			}
		})
	}
}

func TestFixedCPUCommandNeverStartsWorkerOrReflectsPrivateFailure(t *testing.T) {
	for _, args := range [][]string{{printCPUCapacityArgument, "extra"}, {printCPUCapacityArgument, printCPUCapacityArgument}, {printCPUCapacityArgument + "=/private/path"}, {"--path", printCPUCapacityArgument}} {
		var out, diagnostic bytes.Buffer
		calls := 0
		code := dispatchCPUCapacityCommand(args, &out, &diagnostic, func() { calls++ }, func() (cpuCapacityRuntime, error) {
			calls++
			return cpuCapacityRuntime{}, errors.New("private credentials /path")
		})
		if code != 2 || calls != 0 || out.Len() != 0 || diagnostic.String() != "unsupported CPU capacity arguments\n" {
			t.Fatal("extended mode reached startup or file reader")
		}
	}
	var out, diagnostic bytes.Buffer
	code := dispatchCPUCapacityCommand([]string{printCPUCapacityArgument}, &out, &diagnostic, func() { t.Fatal("CPU mode reached worker startup") }, func() (cpuCapacityRuntime, error) {
		return cpuCapacityRuntime{}, errors.New("private credentials and argv /path")
	})
	if code != 1 || out.Len() != 0 || diagnostic.String() != "cpu capacity runtime unavailable\n" {
		t.Fatal("private read error reflected or succeeded")
	}
}

func TestFixedCPUCommandUsesOnlyItsReaderAndNormalStartupDoesNotRead(t *testing.T) {
	calls := 0
	if code := dispatchCPUCapacityCommand(nil, io.Discard, io.Discard, func() { calls++ }, func() (cpuCapacityRuntime, error) {
		t.Fatal("normal startup read CPU files")
		return cpuCapacityRuntime{}, nil
	}); code != 0 || calls != 1 {
		t.Fatal("normal startup changed")
	}
	files := capacityFiles()
	read, _ := capacityFixture(t, files, files)
	var out, diagnostic bytes.Buffer
	code := dispatchCPUCapacityCommand([]string{printCPUCapacityArgument}, &out, &diagnostic, func() { t.Fatal("reader initialized broker, logger or provider") }, func() (cpuCapacityRuntime, error) { return readCPUCapacityRuntime(read) })
	var fields map[string]json.RawMessage
	if code != 0 || diagnostic.Len() != 0 || json.Unmarshal(out.Bytes(), &fields) != nil || len(fields) != 8 {
		t.Fatal("fixed mode did not return its closed eight-field ABI")
	}
}

func TestEveryKernelReadFailureIsSanitizedBeforeWorkerStartup(t *testing.T) {
	for _, failed := range []string{pid1StatPath, selfCgroupPath, pid1CgroupPath, cpuMaxPath, memoryMaxPath} {
		for _, second := range []bool{false, true} {
			files := capacityFiles()
			seen := map[string]int{}
			read := func(path string, _ int) ([]byte, error) {
				seen[path]++
				if path == failed && (!second || seen[path] == 2) {
					return nil, errors.New("private credential /path")
				}
				return files[path], nil
			}
			var out, diagnostic bytes.Buffer
			code := dispatchCPUCapacityCommand([]string{printCPUCapacityArgument}, &out, &diagnostic, func() { t.Fatal("failed read started worker") }, func() (cpuCapacityRuntime, error) { return readCPUCapacityRuntime(read) })
			if code != 1 || out.Len() != 0 || diagnostic.String() != "cpu capacity runtime unavailable\n" {
				t.Fatal("kernel failure leaked or succeeded")
			}
		}
	}
}

func TestCPUCapacityPreservesUnrelatedCoreStartupArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"--unknown"}, {"ordinary"}, {"--other=value"}} {
		calls := 0
		var out, diagnostic bytes.Buffer
		code := dispatchCPUCapacityCommand(args, &out, &diagnostic, func() { calls++ }, func() (cpuCapacityRuntime, error) {
			t.Fatal("normal Core startup read kernel capacity files")
			return cpuCapacityRuntime{}, nil
		})
		if code != 0 || calls != 1 || out.Len() != 0 || diagnostic.Len() != 0 {
			t.Fatal("unrelated Core startup arguments changed behavior")
		}
	}
}
