//go:build linux && nativequalification

package repository

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
)

// qualificationNativeRead mirrors the wire of the provider's
// core_independent_original_qemu_read_v1 return without importing the provider
// package (which already imports repository). Stable original identity stays
// raw so the callers compare it against the immutable original native row.
type qualificationNativeRead struct {
	Schema                               string          `json:"schema"`
	OriginalCreatorSHA256                string          `json:"original_creator_sha256"`
	Original                             json.RawMessage `json:"original"`
	Before                               json.RawMessage `json:"before"`
	After                                json.RawMessage `json:"after"`
	QMPPeerPID                           int32           `json:"qmp_peer_pid"`
	ExecutableSHA256                     string          `json:"executable_sha256"`
	CommandLineSHA256                    string          `json:"command_line_sha256"`
	OriginalDisk                         json.RawMessage `json:"original_disk"`
	OriginalDiskFD                       int             `json:"original_disk_fd"`
	OriginalDiskReadReturnedAt           time.Time       `json:"original_disk_read_returned_at"`
	OriginalDiskDirectoryCloseReturnedAt time.Time       `json:"original_disk_directory_close_returned_at"`
	UUID                                 json.RawMessage `json:"uuid"`
	Status                               json.RawMessage `json:"status"`
	StartedAt                            time.Time       `json:"started_at"`
	ReadReturnedAt                       time.Time       `json:"read_returned_at"`
	CloseReturnedAt                      time.Time       `json:"close_returned_at"`
	IO                                   json.RawMessage `json:"io"`
}

// The JSON kind each raw member has on the provider's typed wire: structs are
// objects, the IO list is an array. Nothing else is a raw member.
var qualificationNativeReadRawShapes = map[string]byte{
	"original":      '{',
	"before":        '{',
	"after":         '{',
	"original_disk": '{',
	"uuid":          '{',
	"status":        '{',
	"io":            '[',
}

// The literal member set of the wire (the closed decoder derives the same set
// from the struct; the tests compare it with the real Core wire).
func qualificationNativeReadMembers() map[string]bool {
	members := map[string]bool{}
	for _, f := range reflect.VisibleFields(reflect.TypeOf(qualificationNativeRead{})) {
		members[strings.Split(f.Tag.Get("json"), ",")[0]] = true
	}
	return members
}

// decodeQualificationNativeRead is the qualification-only closed decoder for
// that wire. The shared Guest lifecycle decoder treats json.RawMessage as an
// ordinary slice and so refuses every object member; it stays unchanged.
// Every one of the literal members is required exactly once and non-null,
// unknown, duplicate (at any depth) and trailing data are refused, and each raw
// member must have its typed wire's JSON kind before the struct is decoded
// (decodeQualificationClosed).
func decodeQualificationNativeRead(wire []byte, out *qualificationNativeRead) error {
	if out == nil {
		return fmt.Errorf("closed qualification native read required")
	}
	if decodeQualificationClosed(wire, out, qualificationNativeReadRawShapes, nil) != nil {
		return fmt.Errorf("closed qualification native read required")
	}
	return nil
}
