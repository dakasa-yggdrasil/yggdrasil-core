//go:build linux && nativequalification

package repository

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
)

var qualificationRawMessageType = reflect.TypeOf(json.RawMessage{})

// The source failure cleanup authority body and its physical record carry the
// provider's typed Process and OriginalDisk values as raw members, so the
// signed-body byte comparisons stay exact. On the producer's typed wire both
// are JSON objects, and the closed decoders below also close those subtrees
// against the producer's typed values.
var sourceFailureCleanupRawShapes = map[string]byte{
	"qemu":          '{',
	"original_disk": '{',
}

// Only the recovery epoch is omitempty on the authority body: the original
// (non-recovery) cleanup omits it, the recovery cleanup carries an object.
var sourceFailureCleanupBodyOptional = map[string]bool{"recovery": true}

// decodeSourceFailureCleanupBody is the closed decoder for the signed
// authority body (capacity_source_failure_cleanup_originals.authority_wire).
func decodeSourceFailureCleanupBody(wire []byte, out *SourceFailureCleanupBody) error {
	refused := fmt.Errorf("closed qualification wire required")
	if out == nil {
		return refused
	}
	var b SourceFailureCleanupBody
	if decodeQualificationClosed(wire, &b, sourceFailureCleanupRawShapes, sourceFailureCleanupBodyOptional) != nil || !sourceFailureCleanupRawMembersClosed(b.QEMU, b.OriginalDisk) {
		return refused
	}
	*out = b
	return nil
}

// decodeSourceFailureCleanupPhysical is the closed decoder for the physical
// record (capacity_source_failure_cleanup_physical.physical_wire).
func decodeSourceFailureCleanupPhysical(wire []byte, out *SourceFailureCleanupPhysical) error {
	refused := fmt.Errorf("closed qualification wire required")
	if out == nil {
		return refused
	}
	var f SourceFailureCleanupPhysical
	if decodeQualificationClosed(wire, &f, sourceFailureCleanupRawShapes, nil) != nil || !sourceFailureCleanupRawMembersClosed(f.QEMU, f.OriginalDisk) {
		return refused
	}
	*out = f
	return nil
}

// sourceFailureCleanupQEMU mirrors capacitynativeqemu.Process, the producer
// type of the qemu raw member.
type sourceFailureCleanupQEMU struct {
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	StartTicks uint64 `json:"start_ticks"`
	StatSHA256 string `json:"stat_sha256"`
}

// sourceFailureCleanupRawMembersClosed closes the raw subtrees as well: the
// qemu and original_disk members must decode, with closed keys, required
// presence and non-null typed scalars, as the producer's typed Process and
// OriginalDisk values. The raw bytes themselves are kept unchanged.
func sourceFailureCleanupRawMembersClosed(qemu, originalDisk json.RawMessage) bool {
	var process sourceFailureCleanupQEMU
	var disk GuestNativeQEMUOriginalDisk
	return capacity.DecodeGuestLifecycle(qemu, &process) == nil && capacity.DecodeGuestLifecycle(originalDisk, &disk) == nil
}

// decodeQualificationClosed is the qualification-only closed decoder for a
// struct wire whose top-level members include json.RawMessage values. The
// shared Guest lifecycle decoder treats json.RawMessage as an ordinary slice
// and so refuses every object-valued raw member; it stays unchanged.
//
// Here the literal member set is closed; each member is required exactly once
// unless it is optional (which must be exactly the omitempty members), and a
// present member is never null. Each raw member must have its declared JSON
// kind, and every declared kind must name a raw member. Each non-raw member is
// validated by the shared Guest lifecycle decoder, which keeps its nested
// closed keys and required presence; a non-raw member type that itself
// contains a json.RawMessage is refused, since that decoder cannot validate
// it. Duplicate members at any depth (raw subtrees included) and trailing
// data are refused. The output keeps the wire's exact raw member bytes and is
// written only on success.
func decodeQualificationClosed(wire []byte, out any, rawShapes map[string]byte, optional map[string]bool) error {
	refused := fmt.Errorf("closed qualification wire required")
	target := reflect.ValueOf(out)
	if !target.IsValid() || target.Kind() != reflect.Pointer || target.IsNil() || target.Elem().Kind() != reflect.Struct || len(wire) == 0 || len(wire) > capacity.GuestBootstrapLimit {
		return refused
	}
	typ := target.Elem().Type()
	fields, ok := qualificationClosedFields(typ, rawShapes, optional)
	if !ok {
		return refused
	}
	allowed := make(map[string]bool, len(fields))
	for name := range fields {
		allowed[name] = true
	}
	// Unknown and duplicate top-level members, and trailing data, are refused.
	members, err := capacity.NativeCanonicalObject(wire, allowed)
	if err != nil {
		return refused
	}
	for name, t := range fields {
		raw, present := members[name]
		if !present {
			if optional[name] {
				continue
			}
			return refused
		}
		value := bytes.TrimSpace(raw)
		if len(value) == 0 || bytes.Equal(value, []byte("null")) {
			return refused
		}
		if shape, isRaw := rawShapes[name]; isRaw {
			if value[0] != shape {
				return refused
			}
			continue
		}
		if capacity.DecodeGuestLifecycle(value, reflect.New(t).Interface()) != nil {
			return refused
		}
	}
	// Duplicate members inside raw subtrees, trailing values and typed scalar
	// mismatches are refused by the shared native decoder.
	if capacity.DecodeNativeCapacity(json.RawMessage(wire), reflect.New(typ).Interface()) != nil {
		return refused
	}
	decoded := reflect.New(typ)
	if json.Unmarshal(wire, decoded.Interface()) != nil {
		return refused
	}
	target.Elem().Set(decoded.Elem())
	return nil
}

// qualificationClosedFields returns the literal member set of typ, refusing a
// declaration that does not match the type exactly.
func qualificationClosedFields(typ reflect.Type, rawShapes map[string]byte, optional map[string]bool) (map[string]reflect.Type, bool) {
	fields := map[string]reflect.Type{}
	raws, optionals := 0, 0
	for _, f := range reflect.VisibleFields(typ) {
		if !f.IsExported() {
			continue
		}
		tag := strings.Split(f.Tag.Get("json"), ",")
		name := tag[0]
		if name == "" || name == "-" {
			continue
		}
		if _, dup := fields[name]; dup {
			return nil, false
		}
		omitempty := false
		for _, option := range tag[1:] {
			omitempty = omitempty || option == "omitempty"
		}
		if optional[name] != omitempty {
			return nil, false
		}
		if omitempty {
			optionals++
		}
		shape, declared := rawShapes[name]
		if f.Type == qualificationRawMessageType {
			if !declared || (shape != '{' && shape != '[') {
				return nil, false
			}
			raws++
		} else if declared || qualificationTypeHasRaw(f.Type, map[reflect.Type]bool{}) {
			return nil, false
		}
		fields[name] = f.Type
	}
	for name, yes := range optional {
		if _, ok := fields[name]; !ok || !yes {
			return nil, false
		}
	}
	if raws != len(rawShapes) || optionals != len(optional) || len(fields) == 0 {
		return nil, false
	}
	return fields, true
}

func qualificationTypeHasRaw(t reflect.Type, seen map[reflect.Type]bool) bool {
	if t == qualificationRawMessageType {
		return true
	}
	if seen[t] {
		return false
	}
	seen[t] = true
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return qualificationTypeHasRaw(t.Elem(), seen)
	case reflect.Map:
		return qualificationTypeHasRaw(t.Key(), seen) || qualificationTypeHasRaw(t.Elem(), seen)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if qualificationTypeHasRaw(t.Field(i).Type, seen) {
				return true
			}
		}
	}
	return false
}
