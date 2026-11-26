package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

const (
	printCPUCapacityArgument = "--print-cpu-capacity-runtime"
	pid1StatPath             = "/proc/1/stat"
	selfCgroupPath           = "/proc/self/cgroup"
	pid1CgroupPath           = "/proc/1/cgroup"
	cpuMaxPath               = "/sys/fs/cgroup/cpu.max"
	memoryMaxPath            = "/sys/fs/cgroup/memory.max"
	resourceRuntimeMax       = 4096
)

var errCPUCapacityRuntime = errors.New("cpu capacity runtime unavailable")

// This closed DTO is separate from normal RPC and instance configuration.
// Null quota/max plus unlimited=true explicitly represents the kernel's "max" value.
type cpuCapacityRuntime struct {
	SchemaVersion   int     `json:"schemaVersion"`
	PID1StartTicks  uint64  `json:"pid1StartTicks"`
	SameCgroup      bool    `json:"sameCgroup"`
	CPUQuotaMicros  *uint64 `json:"cpuQuotaMicros"`
	CPUPeriodMicros uint64  `json:"cpuPeriodMicros"`
	CPUUnlimited    bool    `json:"cpuUnlimited"`
	MemoryMaxBytes  *uint64 `json:"memoryMaxBytes"`
	MemoryUnlimited bool    `json:"memoryUnlimited"`
}

type capacitySnapshot struct {
	start, quota, period, memory  uint64
	cpuUnlimited, memoryUnlimited bool
}

func printCPUCapacityRuntime(out, diagnostic io.Writer, read func() (cpuCapacityRuntime, error)) int {
	metadata, err := read()
	if err != nil {
		_, _ = io.WriteString(diagnostic, "cpu capacity runtime unavailable\n")
		return 1
	}
	if metadata.SchemaVersion != 1 || metadata.PID1StartTicks == 0 || !metadata.SameCgroup || metadata.CPUPeriodMicros == 0 ||
		metadata.CPUUnlimited != (metadata.CPUQuotaMicros == nil) ||
		metadata.MemoryUnlimited != (metadata.MemoryMaxBytes == nil) ||
		(metadata.CPUQuotaMicros != nil && *metadata.CPUQuotaMicros == 0) {
		_, _ = io.WriteString(diagnostic, "cpu capacity runtime unavailable\n")
		return 1
	}
	raw, err := json.Marshal(metadata)
	if err != nil || len(raw) > resourceRuntimeMax {
		_, _ = io.WriteString(diagnostic, "cpu capacity runtime unavailable\n")
		return 1
	}
	line := append(raw, '\n')
	if n, err := out.Write(line); err != nil || n != len(line) {
		_, _ = io.WriteString(diagnostic, "cpu capacity runtime unavailable\n")
		return 1
	}
	return 0
}

func readFixedCPUCapacityRuntime() (cpuCapacityRuntime, error) {
	if runtime.GOOS != "linux" {
		return cpuCapacityRuntime{}, errCPUCapacityRuntime
	}
	return readCPUCapacityRuntime(readCapacityFile)
}

// read is a private fixture seam, never an argument/environment-selected path.
// Every production read below names one of the five fixed kernel files.
func readCPUCapacityRuntime(read func(string, int) ([]byte, error)) (cpuCapacityRuntime, error) {
	before, err := readCapacitySnapshot(read)
	if err != nil {
		return cpuCapacityRuntime{}, errCPUCapacityRuntime
	}
	after, err := readCapacitySnapshot(read)
	if err != nil || before != after {
		return cpuCapacityRuntime{}, errCPUCapacityRuntime
	}
	result := cpuCapacityRuntime{
		SchemaVersion: 1, PID1StartTicks: before.start, SameCgroup: true,
		CPUPeriodMicros: before.period, CPUUnlimited: before.cpuUnlimited,
		MemoryUnlimited: before.memoryUnlimited,
	}
	if !before.cpuUnlimited {
		quota := before.quota
		result.CPUQuotaMicros = &quota
	}
	if !before.memoryUnlimited {
		memory := before.memory
		result.MemoryMaxBytes = &memory
	}
	return result, nil
}

func readCapacitySnapshot(read func(string, int) ([]byte, error)) (capacitySnapshot, error) {
	var result capacitySnapshot
	stat, err := read(pid1StatPath, resourceRuntimeMax)
	if err != nil {
		return result, errCPUCapacityRuntime
	}
	result.start, err = pid1Start(stat)
	if err != nil {
		return result, errCPUCapacityRuntime
	}
	self, err := read(selfCgroupPath, resourceRuntimeMax)
	if err != nil {
		return result, errCPUCapacityRuntime
	}
	pid1, err := read(pid1CgroupPath, resourceRuntimeMax)
	if err != nil || strings.TrimSpace(string(self)) != "0::/" || strings.TrimSpace(string(pid1)) != "0::/" {
		// A non-root/hybrid hierarchy cannot bind these fixed cgroup-root files
		// to this container. Do not substitute host quotas or follow another path.
		return result, errCPUCapacityRuntime
	}
	cpu, err := read(cpuMaxPath, 128)
	if err != nil {
		return result, errCPUCapacityRuntime
	}
	fields := strings.Fields(string(cpu))
	if len(fields) != 2 {
		return result, errCPUCapacityRuntime
	}
	result.period, err = kernelUint(fields[1])
	if err != nil || result.period == 0 {
		return result, errCPUCapacityRuntime
	}
	if fields[0] == "max" {
		result.cpuUnlimited = true
	} else {
		result.quota, err = kernelUint(fields[0])
		if err != nil || result.quota == 0 {
			return result, errCPUCapacityRuntime
		}
	}
	memory, err := read(memoryMaxPath, 128)
	if err != nil {
		return result, errCPUCapacityRuntime
	}
	fields = strings.Fields(string(memory))
	if len(fields) != 1 {
		return result, errCPUCapacityRuntime
	}
	if fields[0] == "max" {
		result.memoryUnlimited = true
	} else {
		result.memory, err = kernelUint(fields[0])
		if err != nil {
			return result, errCPUCapacityRuntime
		}
	}
	return result, nil
}

func pid1Start(raw []byte) (uint64, error) {
	text := string(raw)
	end := strings.LastIndexByte(text, ')')
	if !strings.HasPrefix(text, "1 (") || end < 3 || end+2 >= len(text) || text[end+1] != ' ' {
		return 0, errCPUCapacityRuntime
	}
	fields := strings.Fields(text[end+2:])
	// Field 3 is state; field 22 is starttime. comm may itself contain spaces
	// and parentheses, and is never included in the public result/diagnostic.
	if len(fields) < 20 || !strings.Contains("RSDI", fields[0]) || len(fields[0]) != 1 {
		return 0, errCPUCapacityRuntime
	}
	start, err := kernelUint(fields[19])
	if err != nil || start == 0 {
		return 0, errCPUCapacityRuntime
	}
	return start, nil
}

func kernelUint(value string) (uint64, error) {
	if value == "" {
		return 0, errCPUCapacityRuntime
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, errCPUCapacityRuntime
		}
	}
	number, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, errCPUCapacityRuntime
	}
	return number, nil
}

func readCapacityFile(path string, limit int) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errCPUCapacityRuntime
	}
	file := os.NewFile(uintptr(fd), "fixed-capacity-kernel-file")
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errCPUCapacityRuntime
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errCPUCapacityRuntime
	}
	if path == cpuMaxPath || path == memoryMaxPath {
		var filesystem syscall.Statfs_t
		// Linux CGROUP2_SUPER_MAGIC, checked on the actual open descriptor.
		if syscall.Fstatfs(fd, &filesystem) != nil || uint64(filesystem.Type) != 0x63677270 {
			return nil, errCPUCapacityRuntime
		}
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(raw) == 0 || len(raw) > limit {
		return nil, errCPUCapacityRuntime
	}
	return raw, nil
}
