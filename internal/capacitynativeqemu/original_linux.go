//go:build linux && nativequalification

// Package capacitynativeqemu owns independently read Linux/QMP returns for
// the limited native qualification realm. It is absent from production builds.
package capacitynativeqemu

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

var ErrOriginalUnknown = errors.New("original native QEMU ownership unavailable; HOLD")

type Process struct {
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	StartTicks uint64 `json:"start_ticks"`
	StatSHA256 string `json:"stat_sha256"`
}
type OriginalIO struct {
	Direction  string    `json:"direction"`
	SHA256     string    `json:"sha256"`
	Bytes      int       `json:"bytes"`
	ReturnedAt time.Time `json:"returned_at"`
}
type UUIDRead struct {
	UUID string `json:"UUID"`
}
type StatusRead struct {
	Running    bool   `json:"running"`
	SingleStep bool   `json:"singlestep"`
	Status     string `json:"status"`
}
type CreatorReturn struct {
	Schema                   string       `json:"schema"`
	Provider                 string       `json:"provider"`
	ResourceID               string       `json:"resource_id"`
	QEMU                     Process      `json:"qemu"`
	QMPSourceDevice          uint64       `json:"qmp_source_device"`
	QMPSourceInode           uint64       `json:"qmp_source_inode"`
	NativeUUIDReadback       UUIDRead     `json:"native_uuid_readback"`
	NativeStatusReadback     StatusRead   `json:"native_status_readback"`
	OriginalReadStartedAt    time.Time    `json:"original_read_started_at"`
	OriginalReadReturnedAt   time.Time    `json:"original_read_returned_at"`
	OriginalIO               []OriginalIO `json:"original_io"`
	Scope                    string       `json:"scope"`
	OriginalClosesReturned   bool         `json:"original_closes_returned"`
	OriginalCreateStartedAt  time.Time    `json:"original_create_started_at"`
	OriginalCreateReturnedAt time.Time    `json:"original_create_returned_at"`
	BeforeCreateStageSHA256  string       `json:"before_create_stage_sha256"`
	OriginalSourceCommit     string       `json:"original_source_commit"`
	CreatorSourceSHA256      string       `json:"creator_source_sha256"`
	QMPOriginalPeer          struct {
		PID int    `json:"pid"`
		UID uint32 `json:"uid"`
		GID uint32 `json:"gid"`
	} `json:"qmp_original_peer"`
	Slot int `json:"slot"`
}
type IndependentReturn struct {
	Schema                               string        `json:"schema"`
	OriginalCreatorSHA256                string        `json:"original_creator_sha256"`
	Original                             CreatorReturn `json:"original"`
	Before                               Process       `json:"before"`
	After                                Process       `json:"after"`
	QMPPeerPID                           int32         `json:"qmp_peer_pid"`
	ExecutableSHA256                     string        `json:"executable_sha256"`
	CommandLineSHA256                    string        `json:"command_line_sha256"`
	OriginalDisk                         OriginalDisk  `json:"original_disk"`
	OriginalDiskFD                       int           `json:"original_disk_fd"`
	OriginalDiskReadReturnedAt           time.Time     `json:"original_disk_read_returned_at"`
	OriginalDiskDirectoryCloseReturnedAt time.Time     `json:"original_disk_directory_close_returned_at"`
	UUID                                 UUIDRead      `json:"uuid"`
	Status                               StatusRead    `json:"status"`
	StartedAt                            time.Time     `json:"started_at"`
	ReadReturnedAt                       time.Time     `json:"read_returned_at"`
	CloseReturnedAt                      time.Time     `json:"close_returned_at"`
	IO                                   []OriginalIO  `json:"io"`
}

func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func validSHA(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}
func validUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

// Kernel files and private immutable stage files are read through the same
// opened descriptor, with actual bounded Read+Close and a post-Close context
// check. A caller-provided complete flag cannot satisfy any of these returns.
func readOpened(ctx context.Context, path string, limit int64, private bool, proc bool) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ErrOriginalUnknown
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrOriginalUnknown
	}
	f := os.NewFile(uintptr(fd), path)
	var stat unix.Stat_t
	var fs unix.Statfs_t
	err = unix.Fstat(fd, &stat)
	if proc {
		err = errors.Join(err, unix.Fstatfs(fd, &fs))
		if fs.Type != unix.PROC_SUPER_MAGIC {
			err = ErrOriginalUnknown
		}
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || (private && stat.Mode&0077 != 0) {
		err = ErrOriginalUnknown
	}
	if err != nil {
		_ = f.Close()
		return nil, ErrOriginalUnknown
	}
	raw, re := io.ReadAll(io.LimitReader(f, limit+1))
	ce := f.Close()
	if re != nil || ce != nil || int64(len(raw)) > limit || ctx.Err() != nil {
		return nil, ErrOriginalUnknown
	}
	return raw, nil
}

func ReadPrivate(ctx context.Context, path string, out any) ([]byte, error) {
	raw, err := readOpened(ctx, path, 2<<20, true, false)
	if err != nil {
		return nil, err
	}
	if closedJSON(raw, out) != nil {
		return nil, ErrOriginalUnknown
	}
	return raw, nil
}

func closedJSON(raw []byte, out any) error {
	if typ := reflect.TypeOf(out); typ != nil && typ.Kind() == reflect.Pointer && typ.Elem().Kind() == reflect.Struct {
		return capacity.DecodeGuestLifecycle(raw, out)
	}
	// Reject duplicate object keys recursively before the typed decode.
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var scan func() error
	scan = func() error {
		token, e := d.Token()
		if e != nil {
			return e
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				name, ok := k.(string)
				folded := strings.ToLower(name)
				if !ok || seen[folded] {
					return ErrOriginalUnknown
				}
				seen[folded] = true
				if e = scan(); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return ErrOriginalUnknown
			}
		case '[':
			for d.More() {
				if e := scan(); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return ErrOriginalUnknown
			}
		default:
			return ErrOriginalUnknown
		}
		return nil
	}
	if scan() != nil {
		return ErrOriginalUnknown
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrOriginalUnknown
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrOriginalUnknown
	}
	return nil
}

func nativeProcess(ctx context.Context, pid int) (Process, error) {
	p := Process{PID: pid}
	if pid < 2 {
		return p, ErrOriginalUnknown
	}
	raw, err := readOpened(ctx, fmt.Sprintf("/proc/%d/stat", pid), 8192, false, true)
	if err != nil {
		return p, err
	}
	end := bytes.LastIndexByte(raw, ')')
	if end < 0 {
		return p, ErrOriginalUnknown
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return p, ErrOriginalUnknown
	}
	p.PPID, err = strconv.Atoi(fields[1])
	p.StartTicks, _ = strconv.ParseUint(fields[19], 10, 64)
	p.StatSHA256 = digest(raw)
	if err != nil || p.PPID < 1 || p.StartTicks < 1 {
		return p, ErrOriginalUnknown
	}
	return p, nil
}

func sameProcess(a, b Process) bool {
	return a.PID == b.PID && a.PPID == b.PPID && a.StartTicks == b.StartTicks
}

// The fixed kernel exe magic link is deliberate. Generic private-file reads
// retain NOFOLLOW; the surrounding original PID/ticks reads fence this open.
func nativeExecutable(ctx context.Context, pid int) (string, error) {
	if ctx.Err() != nil {
		return "", ErrOriginalUnknown
	}
	exe, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", ErrOriginalUnknown
	}
	data, re := io.ReadAll(io.LimitReader(exe, 128<<20))
	ce := exe.Close()
	if re != nil || ce != nil || len(data) == 128<<20 || ctx.Err() != nil {
		return "", ErrOriginalUnknown
	}
	return digest(data), nil
}

func CheckCreator(original CreatorReturn, slot int, resourceID, source, creatorSHA, stageSHA string, redeemedAt, grantExpires, deadline time.Time) error {
	if original.Schema != "original_native_qemu_identity_readback_v1" || original.Provider != "native-qemu" || original.Scope != "original_native_qemu_not_physical_provider_billing_or_guest_admission" || !validUUID(resourceID) || original.ResourceID != resourceID || strings.ToLower(original.NativeUUIDReadback.UUID) != resourceID || original.OriginalSourceCommit != source || original.CreatorSourceSHA256 != creatorSHA || !validSHA(creatorSHA) || original.BeforeCreateStageSHA256 != stageSHA || !validSHA(stageSHA) || original.QEMU.PID < 2 || original.QEMU.PPID < 1 || original.QEMU.StartTicks < 1 || !validSHA(original.QEMU.StatSHA256) || original.QMPSourceInode == 0 || !original.OriginalClosesReturned || !original.NativeStatusReadback.Running || original.NativeStatusReadback.SingleStep || original.NativeStatusReadback.Status != "running" || original.OriginalCreateStartedAt.Before(redeemedAt) || !original.OriginalCreateStartedAt.Before(grantExpires) || original.OriginalCreateReturnedAt.Before(original.OriginalCreateStartedAt) || original.OriginalReadStartedAt.Before(original.OriginalCreateReturnedAt) || original.OriginalReadReturnedAt.Before(original.OriginalReadStartedAt) || !original.OriginalReadReturnedAt.Before(deadline) || len(original.OriginalIO) < 7 || len(original.OriginalIO) > 64 {
		return ErrOriginalUnknown
	}
	if original.Slot != slot || slot < 1 || slot > 2 || original.QMPOriginalPeer.PID != original.QEMU.PID {
		return ErrOriginalUnknown
	}
	previous := original.OriginalReadStartedAt
	reads, writes := 0, 0
	for _, entry := range original.OriginalIO {
		if (entry.Direction != "read" && entry.Direction != "write") || !validSHA(entry.SHA256) || entry.Bytes < 1 || entry.Bytes > 65536 || entry.ReturnedAt.Before(previous) || entry.ReturnedAt.After(original.OriginalReadReturnedAt) {
			return ErrOriginalUnknown
		}
		if entry.Direction == "read" {
			reads++
		} else {
			writes++
		}
		previous = entry.ReturnedAt
	}
	if reads < 4 || writes != 3 {
		return ErrOriginalUnknown
	}
	return nil
}

// Observe independently joins the actual Unix socket's SO_PEERCRED, QMP UUID
// and status with the SAME original process lifetime before and after reads.
// It never sends quit/reset/power commands or starts a replacement process.
func Observe(ctx context.Context, privateSlot string, original CreatorReturn, expectedQEMUSHA string) (IndependentReturn, error) {
	r := IndependentReturn{Schema: "core_independent_original_qemu_read_v1", Original: original, StartedAt: time.Now().UTC(), IO: []OriginalIO{}}
	deadline, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil || !validSHA(expectedQEMUSHA) {
		return r, ErrOriginalUnknown
	}
	var err error
	r.Before, err = nativeProcess(ctx, original.QEMU.PID)
	if err != nil || !sameProcess(r.Before, original.QEMU) {
		return r, ErrOriginalUnknown
	}
	r.ExecutableSHA256, err = nativeExecutable(ctx, original.QEMU.PID)
	if err != nil || r.ExecutableSHA256 != expectedQEMUSHA {
		return r, ErrOriginalUnknown
	}
	cmd, err := readOpened(ctx, fmt.Sprintf("/proc/%d/cmdline", original.QEMU.PID), 65536, false, true)
	if err != nil {
		return r, err
	}
	r.CommandLineSHA256 = digest(cmd)
	disk, fd, readAt, closeAt, diskErr := originalQEMUOpenedDisk(ctx, original.QEMU.PID, privateSlot)
	if diskErr != nil {
		return r, diskErr
	}
	r.OriginalDisk, r.OriginalDiskFD, r.OriginalDiskReadReturnedAt, r.OriginalDiskDirectoryCloseReturnedAt = disk, fd, readAt, closeAt
	arguments := strings.Split(strings.TrimSuffix(string(cmd), "\x00"), "\x00")
	matched := false
	for n := 1; n < len(arguments); n++ {
		if arguments[n-1] == "-uuid" && arguments[n] == original.ResourceID {
			if matched {
				return r, ErrOriginalUnknown
			}
			matched = true
		}
	}
	if !matched {
		return r, ErrOriginalUnknown
	}
	path := filepath.Join(privateSlot, "original-qmp.sock")
	var before unix.Stat_t
	if unix.Lstat(path, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFSOCK || uint64(before.Dev) != original.QMPSourceDevice || before.Ino != original.QMPSourceInode {
		return r, ErrOriginalUnknown
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return r, ErrOriginalUnknown
	}
	closed := false
	defer func() {
		if !closed {
			_ = connection.Close()
		}
	}()
	un, ok := connection.(*net.UnixConn)
	if !ok {
		return r, ErrOriginalUnknown
	}
	raw, err := un.SyscallConn()
	if err != nil {
		return r, ErrOriginalUnknown
	}
	var credential *unix.Ucred
	var nativeErr error
	if raw.Control(func(fd uintptr) {
		credential, nativeErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}) != nil || nativeErr != nil || credential == nil || int(credential.Pid) != original.QEMU.PID {
		return r, ErrOriginalUnknown
	}
	r.QMPPeerPID = credential.Pid
	if connection.SetDeadline(deadline) != nil {
		return r, ErrOriginalUnknown
	}
	reader := bufio.NewReaderSize(connection, 65537)
	row := func() (map[string]json.RawMessage, error) {
		body, e := reader.ReadSlice('\n')
		if e != nil || len(body) > 65536 {
			return nil, ErrOriginalUnknown
		}
		r.IO = append(r.IO, OriginalIO{Direction: "read", SHA256: digest(body), Bytes: len(body), ReturnedAt: time.Now().UTC()})
		var value map[string]json.RawMessage
		if closedJSON(body, &value) != nil {
			return nil, ErrOriginalUnknown
		}
		return value, nil
	}
	greeting, err := row()
	if err != nil || len(greeting) != 1 || greeting["QMP"] == nil {
		return r, ErrOriginalUnknown
	}
	command := func(operation, id string, out any) error {
		body, _ := json.Marshal(struct {
			Execute string `json:"execute"`
			ID      string `json:"id"`
		}{operation, id})
		body = append(body, '\r', '\n')
		n, e := connection.Write(body)
		r.IO = append(r.IO, OriginalIO{Direction: "write", SHA256: digest(body), Bytes: n, ReturnedAt: time.Now().UTC()})
		if e != nil || n != len(body) {
			return ErrOriginalUnknown
		}
		for count := 0; count < 32; count++ {
			response, e := row()
			if e != nil {
				return e
			}
			if response["event"] != nil {
				continue
			}
			var got string
			if len(response) != 2 || json.Unmarshal(response["id"], &got) != nil || got != id || response["return"] == nil || closedJSON(response["return"], out) != nil {
				return ErrOriginalUnknown
			}
			return nil
		}
		return ErrOriginalUnknown
	}
	var capabilities map[string]any
	if command("qmp_capabilities", "core-original-capabilities", &capabilities) != nil || len(capabilities) != 0 || command("query-uuid", "core-original-uuid", &r.UUID) != nil || command("query-status", "core-original-status", &r.Status) != nil {
		return r, ErrOriginalUnknown
	}
	r.ReadReturnedAt = time.Now().UTC()
	err = connection.Close()
	closed = true
	r.CloseReturnedAt = time.Now().UTC()
	executableAfter, executableErr := nativeExecutable(ctx, original.QEMU.PID)
	r.After, nativeErr = nativeProcess(ctx, original.QEMU.PID)
	var after unix.Stat_t
	if err != nil || executableErr != nil || executableAfter != r.ExecutableSHA256 || nativeErr != nil || !sameProcess(r.Before, r.After) || unix.Lstat(path, &after) != nil || after.Dev != before.Dev || after.Ino != before.Ino || strings.ToLower(r.UUID.UUID) != original.ResourceID || r.Status.SingleStep || !r.Status.Running || r.Status.Status != "running" || ctx.Err() != nil {
		return r, ErrOriginalUnknown
	}
	return r, nil
}
