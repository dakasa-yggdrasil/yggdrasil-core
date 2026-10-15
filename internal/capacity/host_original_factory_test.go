package capacity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// These are byte, crypto and graph vectors, not native observations. None of
// these helpers runs a syscall, supplies original owner evidence, changes VCS
// metadata, constructs a native capsule, or populates the compiled registry.
const (
	hostVectorOwner          = "11111111-1111-4111-8111-111111111111"
	hostVectorHandle         = "22222222-2222-4222-8222-222222222222"
	hostVectorSubject        = "33333333-3333-4333-8333-333333333333"
	hostVectorScopeSchema    = "original_host_factory_pre_authority_scope_v4"
	hostVectorRootSchema     = "original_host_factory_root_preparation_v4"
	hostVectorOrdinarySchema = "factory_ordinary_source_binding_v4"
	hostVectorChoiceLiteral  = `{"schema":"original_host_factory_unissued_choice_body_v4","purpose":"original_host_factory_unissued_choice_body_v4","pre_authority_scope_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","alive_registration_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","choice_reservation_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","choice":"sealed_before_possible_create"}`
)

func hostVectorPtr[T any](v T) *T { return &v }
func hostVectorSHA() string       { return strings.Repeat("a", 64) }
func hostVectorTime() time.Time   { return time.Date(2026, 10, 13, 12, 0, 0, 123456789, time.UTC) }
func hostVectorJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func hostVectorRefused(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrHostFactorySourceRefused) {
		t.Fatalf("want stable refusal, got %v", err)
	}
}
func hostVectorChoice() model.HostFactoryUnissuedChoiceBody {
	return model.HostFactoryUnissuedChoiceBody{
		Schema: "original_host_factory_unissued_choice_body_v4", Purpose: "original_host_factory_unissued_choice_body_v4",
		PreAuthorityScopeSHA256: hostVectorSHA(), AliveRegistrationSHA256: strings.Repeat("b", 64),
		ChoiceReservationSHA256: strings.Repeat("c", 64), Choice: "sealed_before_possible_create",
	}
}

func TestHostOriginalFactoryClosedBytes(t *testing.T) {
	tests := []struct {
		name     string
		raw      []byte
		accepted bool
	}{
		{"literal_canonical", []byte(hostVectorChoiceLiteral), true},
		{"omitted_required", []byte(strings.Replace(hostVectorChoiceLiteral, `,"choice":"sealed_before_possible_create"`, "", 1)), false},
		{"null_required", []byte(strings.Replace(hostVectorChoiceLiteral, `"choice":"sealed_before_possible_create"`, `"choice":null`, 1)), false},
		{"duplicate_exact", []byte(strings.Replace(hostVectorChoiceLiteral, `"choice":`, `"choice":"sealed_before_possible_create","choice":`, 1)), false},
		{"case_alias", []byte(strings.Replace(hostVectorChoiceLiteral, `"choice":`, `"Choice":`, 1)), false},
		{"fold_duplicate", []byte(strings.Replace(hostVectorChoiceLiteral, `"choice":`, `"Choice":"sealed_before_possible_create","choice":`, 1)), false},
		{"unknown_future_grant", []byte(strings.TrimSuffix(hostVectorChoiceLiteral, "}") + `,"original_create_grant_id":"` + hostVectorOwner + `"}`), false},
		{"unknown_self_hash", []byte(strings.TrimSuffix(hostVectorChoiceLiteral, "}") + `,"own_sha256":"` + hostVectorSHA() + `"}`), false},
		{"noncanonical_key_order", []byte(strings.Replace(hostVectorChoiceLiteral, `"schema":"original_host_factory_unissued_choice_body_v4","purpose":"original_host_factory_unissued_choice_body_v4"`, `"purpose":"original_host_factory_unissued_choice_body_v4","schema":"original_host_factory_unissued_choice_body_v4"`, 1)), false},
		{"leading_whitespace", []byte(" " + hostVectorChoiceLiteral), false},
		{"trailing_newline", []byte(hostVectorChoiceLiteral + "\n"), false},
		{"trailing_object", []byte(hostVectorChoiceLiteral + "{}"), false},
		{"non_utf8", bytes.Replace([]byte(hostVectorChoiceLiteral), []byte("sealed_before_possible_create"), []byte{0xff}, 1), false},
		{"uppercase_sha", []byte(strings.Replace(hostVectorChoiceLiteral, strings.Repeat("a", 64), strings.Repeat("A", 64), 1)), false},
		{"unknown_choice", []byte(strings.Replace(hostVectorChoiceLiteral, "sealed_before_possible_create", "possible_create", 1)), false},
		{"historic_v2", []byte(strings.ReplaceAll(hostVectorChoiceLiteral, "_v4", "_v2")), false},
		{"envelope_size_plus_one", bytes.Repeat([]byte("x"), 65537), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var value model.HostFactoryUnissuedChoiceBody
			err := DecodeHostFactory(tc.raw, &value)
			if !tc.accepted {
				hostVectorRefused(t, err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			raw, err := CanonicalHostFactory(value)
			if err != nil || !bytes.Equal(raw, tc.raw) {
				t.Fatalf("canonical bytes changed: %s, %v", raw, err)
			}
			if !reflect.DeepEqual(value, hostVectorChoice()) {
				t.Fatal("literal body changed")
			}
		})
	}
	t.Run("unknown_caller_struct", func(t *testing.T) {
		_, err := CanonicalHostFactory(struct {
			Choice string `json:"choice"`
		}{"sealed_before_possible_create"})
		hostVectorRefused(t, err)
	})
	t.Run("map_not_typed_body", func(t *testing.T) {
		_, err := CanonicalHostFactory(map[string]string{"choice": "sealed_before_possible_create"})
		hostVectorRefused(t, err)
	})
	t.Run("nested_omitted_nullable_key", func(t *testing.T) {
		chunk := hostVectorChunk(hostVectorPrimitive("stdout_read", 1, "returned"))
		raw := hostVectorJSON(t, chunk)
		raw = bytes.Replace(raw, []byte(`,"original_eof":false`), nil, 1)
		var out model.HostFactoryCallVectorChunk
		hostVectorRefused(t, DecodeHostFactory(raw, &out))
	})
	t.Run("nested_duplicate_call_id", func(t *testing.T) {
		chunk := hostVectorChunk(hostVectorPrimitive("stdout_read", 1, "returned"))
		raw := hostVectorJSON(t, chunk)
		raw = bytes.Replace(raw, []byte(`"original_call_id":`), []byte(`"original_call_id":"`+hostVectorHandle+`:1","original_call_id":`), 1)
		var out model.HostFactoryCallVectorChunk
		hostVectorRefused(t, DecodeHostFactory(raw, &out))
	})
}

func hostVectorPrimitive(operation string, ordinal uint64, state string) model.HostFactoryPrimitiveIOReturn {
	called := hostVectorTime().Add(time.Duration(ordinal*2) * time.Nanosecond)
	f := model.HostFactoryPrimitiveIOReturn{
		Operation: operation, OriginalHandleID: hostVectorHandle, SubjectOwnerID: hostVectorSubject,
		OriginalState: state, OriginalReturnClass: "unavailable", OriginalHashState: "unknown_original_bytes",
		OriginalOperationDeadline: hostVectorTime().Add(60 * time.Second),
	}
	if state == "not_called" {
		return f
	}
	f.OwnerPrimitiveRawSHA256 = hostVectorPtr(hostVectorSHA())
	f.OriginalCalledAt = &called
	f.OriginalCallOrdinal = &ordinal
	f.OriginalCallID = hostVectorPtr(fmt.Sprintf("%s:%d", hostVectorHandle, ordinal))
	if state == "called_pending" {
		return f
	}
	f.OriginalReturnedAt = hostVectorPtr(called.Add(time.Nanosecond))
	f.OriginalReturnClass = "success"
	switch operation {
	case "worker_wait", "stdout_close":
		kind := "original_file_close"
		if operation == "worker_wait" {
			kind = "original_cmd_wait"
		}
		f.OriginalNativeReturn = &model.HostFactoryNativeCallReturn{Kind: kind, OriginalErrno: hostVectorPtr(uint32(0)), OriginalErrorPresent: hostVectorPtr(false)}
		if operation == "worker_wait" {
			f.OriginalNativeReturn.OriginalExitCode = hostVectorPtr(0)
		} else {
			f.OriginalNativeReturn.InputDescriptorNumber = hostVectorPtr(11)
		}
		f.OriginalHashState = "not_byte_operation"
	case "bootstrap_key64_read":
		f.OriginalCount = hostVectorPtr(int64(64))
		f.OriginalEOF = hostVectorPtr(false)
		f.OriginalHashState = "private_withheld"
	default:
		f.OriginalCount = hostVectorPtr(int64(0))
		f.OriginalSHA256 = hostVectorPtr(HostFactoryRawSHA256(nil))
		f.OriginalEOF = hostVectorPtr(false)
		f.OriginalHashState = "actual_public_bytes"
	}
	return f
}

func TestHostOriginalFactoryPrimitiveStates(t *testing.T) {
	tests := []struct {
		name, operation, state string
		mutate                 func(*model.HostFactoryPrimitiveIOReturn)
		accepted               bool
	}{
		{"not_called_has_no_call_or_bytes", "stdout_read", "not_called", nil, true},
		{"pending_has_original_call_no_return", "stdout_read", "called_pending", nil, true},
		{"actual_empty_eof", "stdout_read", "returned", func(f *model.HostFactoryPrimitiveIOReturn) {
			f.OriginalReturnClass = "eof"
			f.OriginalEOF = hostVectorPtr(true)
		}, true},
		{"actual_partial_zero_is_not_unknown_or_eof", "stdout_read", "returned", func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalReturnClass = "partial" }, true},
		{"private_key_count_withheld_hash", "bootstrap_key64_read", "returned", nil, true},
		{"nonbyte_wait_has_no_byte_fields", "worker_wait", "returned", nil, true},
		{"not_called_invented_zero", "stdout_read", "not_called", func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalCount = hostVectorPtr(int64(0)) }, false},
		{"not_called_invented_call_id", "stdout_read", "not_called", func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalCallID = hostVectorPtr(hostVectorHandle + ":1") }, false},
		{"pending_invented_return", "stdout_read", "called_pending", func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalReturnedAt = hostVectorPtr(hostVectorTime()) }, false},
		{"pending_invented_eof", "stdout_read", "called_pending", func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalEOF = hostVectorPtr(true) }, false},
		{"returned_missing_count", "stdout_read", "returned", func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalCount = nil }, false},
		{"returned_missing_hash", "stdout_read", "returned", func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalSHA256 = nil }, false},
		{"returned_unknown_hash_state", "stdout_read", "returned", func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalHashState = "unknown_original_bytes" }, false},
		{"empty_eof_hash_mismatch", "stdout_read", "returned", func(f *model.HostFactoryPrimitiveIOReturn) {
			f.OriginalReturnClass = "eof"
			f.OriginalEOF = hostVectorPtr(true)
			f.OriginalSHA256 = hostVectorPtr(hostVectorSHA())
		}, false},
		{"eof_class_without_eof", "stdout_read", "returned", func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalReturnClass = "eof" }, false},
		{"private_hash_export_refused", "bootstrap_key64_read", "returned", func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalSHA256 = hostVectorPtr(hostVectorSHA()) }, false},
		{"private_public_hash_state_refused", "bootstrap_key64_read", "returned", func(f *model.HostFactoryPrimitiveIOReturn) {
			f.OriginalHashState = "actual_public_bytes"
			f.OriginalSHA256 = hostVectorPtr(hostVectorSHA())
		}, false},
		{"nonbyte_zero_is_not_byte_return", "worker_wait", "returned", func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalCount = hostVectorPtr(int64(0)) }, false},
		{"nonbyte_empty_hash_refused", "worker_wait", "returned", func(f *model.HostFactoryPrimitiveIOReturn) {
			f.OriginalSHA256 = hostVectorPtr(HostFactoryRawSHA256(nil))
		}, false},
		{"nonbyte_false_eof_refused", "worker_wait", "returned", func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalEOF = hostVectorPtr(false) }, false},
		{"negative_count", "stdout_read", "returned", func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalCount = hostVectorPtr(int64(-1)) }, false},
		{"primitive_count_above_65536", "stdout_read", "returned", func(f *model.HostFactoryPrimitiveIOReturn) {
			f.OriginalCount = hostVectorPtr(int64(65537))
			f.OriginalReturnClass = "oversize"
		}, false},
		{"return_before_call", "stdout_read", "returned", func(f *model.HostFactoryPrimitiveIOReturn) {
			f.OriginalReturnedAt = hostVectorPtr(f.OriginalCalledAt.Add(-time.Nanosecond))
		}, false},
		{"late_diagnostic_retains_original_deadline", "stdout_read", "returned", func(f *model.HostFactoryPrimitiveIOReturn) {
			f.OriginalOperationDeadline = f.OriginalCalledAt.Add(-time.Nanosecond)
		}, true},
		{"missing_called_ordinal", "stdout_read", "called_pending", func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalCallOrdinal = nil }, false},
		{"zero_ordinal", "stdout_read", "returned", func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalCallOrdinal = hostVectorPtr(uint64(0)) }, false},
		{"byte_ordinal_65536_reserved_for_close", "stdout_read", "returned", func(f *model.HostFactoryPrimitiveIOReturn) {
			f.OriginalCallOrdinal = hostVectorPtr(uint64(65536))
			f.OriginalCallID = hostVectorPtr(hostVectorHandle + ":65536")
		}, false},
		{"ordinal_above_65536", "stdout_read", "returned", func(f *model.HostFactoryPrimitiveIOReturn) {
			f.OriginalCallOrdinal = hostVectorPtr(uint64(65537))
			f.OriginalCallID = hostVectorPtr(hostVectorHandle + ":65537")
		}, false},
		{"call_id_leading_zero", "stdout_read", "returned", func(f *model.HostFactoryPrimitiveIOReturn) {
			f.OriginalCallID = hostVectorPtr(hostVectorHandle + ":01")
		}, false},
		{"call_id_foreign_handle", "stdout_read", "returned", func(f *model.HostFactoryPrimitiveIOReturn) {
			f.OriginalCallID = hostVectorPtr(hostVectorSubject + ":1")
		}, false},
		{"unknown_operation", "stdout_read", "returned", func(f *model.HostFactoryPrimitiveIOReturn) { f.Operation = "arbitrary_read" }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := hostVectorPrimitive(tc.operation, 1, tc.state)
			if tc.mutate != nil {
				tc.mutate(&f)
			}
			err := ValidateHostFactory(f)
			if !tc.accepted {
				hostVectorRefused(t, err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var out model.HostFactoryPrimitiveIOReturn
			if err := DecodeHostFactory(hostVectorJSON(t, f), &out); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(out, f) {
				t.Fatal("nullable/state facts changed")
			}
		})
	}
}

func hostVectorChunk(calls ...model.HostFactoryPrimitiveIOReturn) model.HostFactoryCallVectorChunk {
	recorded := hostVectorTime().Add(time.Second)
	if len(calls) == 1 && calls[0].OriginalState == "called_pending" {
		recorded = *calls[0].OriginalCalledAt
	}
	return model.HostFactoryCallVectorChunk{
		Schema: "original_host_factory_call_vector_chunk_v2", Purpose: "original_host_factory_call_vector_chunk_v2",
		BindingSchema: hostVectorScopeSchema, BindingSHA256: hostVectorSHA(), OwnerRole: "host_exterior",
		OriginalOwnerID: hostVectorOwner, OwnerPrimitiveRawSHA256: hostVectorSHA(), Operation: calls[0].Operation,
		OriginalHandleID: hostVectorHandle, FirstOrdinal: *calls[0].OriginalCallOrdinal,
		LastOrdinal: *calls[len(calls)-1].OriginalCallOrdinal, OriginalCalls: calls, RecordedAt: recorded,
	}
}

func TestHostOriginalFactoryChunkShapes(t *testing.T) {
	tests := []struct {
		name     string
		make     func() model.HostFactoryCallVectorChunk
		accepted bool
	}{
		{"returned_terminal_singleton", func() model.HostFactoryCallVectorChunk {
			return hostVectorChunk(hostVectorPrimitive("stdout_read", 1, "returned"))
		}, true},
		{"pending_singleton", func() model.HostFactoryCallVectorChunk {
			return hostVectorChunk(hostVectorPrimitive("stdout_read", 1, "called_pending"))
		}, true},
		{"sixteen_returned_terminal", func() model.HostFactoryCallVectorChunk {
			calls := []model.HostFactoryPrimitiveIOReturn{}
			for i := uint64(1); i <= 16; i++ {
				calls = append(calls, hostVectorPrimitive("stdout_read", i, "returned"))
			}
			return hostVectorChunk(calls...)
		}, true},
		{"mixed_returned_pending", func() model.HostFactoryCallVectorChunk {
			return hostVectorChunk(hostVectorPrimitive("stdout_read", 1, "returned"), hostVectorPrimitive("stdout_read", 2, "called_pending"))
		}, false},
		{"two_pending_in_one_chunk", func() model.HostFactoryCallVectorChunk {
			return hostVectorChunk(hostVectorPrimitive("stdout_read", 1, "called_pending"), hostVectorPrimitive("stdout_read", 2, "called_pending"))
		}, false},
		{"seventeen_terminal_calls", func() model.HostFactoryCallVectorChunk {
			calls := []model.HostFactoryPrimitiveIOReturn{}
			for i := uint64(1); i <= 17; i++ {
				calls = append(calls, hostVectorPrimitive("stdout_read", i, "returned"))
			}
			return hostVectorChunk(calls...)
		}, false},
		{"ordinal_gap", func() model.HostFactoryCallVectorChunk {
			return hostVectorChunk(hostVectorPrimitive("stdout_read", 1, "returned"), hostVectorPrimitive("stdout_read", 3, "returned"))
		}, false},
		{"duplicate_call_id", func() model.HostFactoryCallVectorChunk {
			return hostVectorChunk(hostVectorPrimitive("stdout_read", 1, "returned"), hostVectorPrimitive("stdout_read", 1, "returned"))
		}, false},
		{"foreign_primitive_owner", func() model.HostFactoryCallVectorChunk {
			c := hostVectorChunk(hostVectorPrimitive("stdout_read", 1, "returned"))
			c.OriginalCalls[0].OwnerPrimitiveRawSHA256 = hostVectorPtr(strings.Repeat("b", 64))
			return c
		}, false},
		{"foreign_primitive_handle", func() model.HostFactoryCallVectorChunk {
			c := hostVectorChunk(hostVectorPrimitive("stdout_read", 1, "returned"))
			c.OriginalCalls[0].OriginalHandleID = hostVectorSubject
			c.OriginalCalls[0].OriginalCallID = hostVectorPtr(hostVectorSubject + ":1")
			return c
		}, false},
		{"foreign_primitive_operation", func() model.HostFactoryCallVectorChunk {
			c := hostVectorChunk(hostVectorPrimitive("stdout_read", 1, "returned"))
			c.OriginalCalls[0].Operation = "stderr_read"
			return c
		}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHostFactory(tc.make())
			if !tc.accepted {
				hostVectorRefused(t, err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHostOriginalFactoryPendingSuccessor(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*model.HostFactoryCallVectorChunk, *model.HostFactoryCallVectorChunk)
		accepted bool
	}{
		{"same_singleton_retains_called_facts", nil, true},
		{"different_original_owner", func(p, c *model.HostFactoryCallVectorChunk) { c.OriginalOwnerID = hostVectorSubject }, false},
		{"different_owner_basal_body", func(p, c *model.HostFactoryCallVectorChunk) {
			c.OwnerPrimitiveRawSHA256 = strings.Repeat("b", 64)
			c.OriginalCalls[0].OwnerPrimitiveRawSHA256 = hostVectorPtr(c.OwnerPrimitiveRawSHA256)
		}, false},
		{"different_binding", func(p, c *model.HostFactoryCallVectorChunk) { c.BindingSHA256 = strings.Repeat("b", 64) }, false},
		{"different_subject", func(p, c *model.HostFactoryCallVectorChunk) { c.OriginalCalls[0].SubjectOwnerID = hostVectorOwner }, false},
		{"different_called_nanosecond", func(p, c *model.HostFactoryCallVectorChunk) {
			c.OriginalCalls[0].OriginalCalledAt = hostVectorPtr(c.OriginalCalls[0].OriginalCalledAt.Add(time.Nanosecond))
		}, false},
		{"renewed_original_deadline", func(p, c *model.HostFactoryCallVectorChunk) {
			c.OriginalCalls[0].OriginalOperationDeadline = c.OriginalCalls[0].OriginalOperationDeadline.Add(time.Nanosecond)
		}, false},
		{"different_handle_and_call_id", func(p, c *model.HostFactoryCallVectorChunk) {
			c.OriginalHandleID = hostVectorSubject
			c.OriginalCalls[0].OriginalHandleID = hostVectorSubject
			c.OriginalCalls[0].OriginalCallID = hostVectorPtr(hostVectorSubject + ":16")
		}, false},
		{"different_ordinal", func(p, c *model.HostFactoryCallVectorChunk) {
			c.FirstOrdinal = 17
			c.LastOrdinal = 17
			c.OriginalCalls[0].OriginalCallOrdinal = hostVectorPtr(uint64(17))
			c.OriginalCalls[0].OriginalCallID = hostVectorPtr(hostVectorHandle + ":17")
		}, false},
		{"previous_already_returned", func(p, c *model.HostFactoryCallVectorChunk) { *p = *c }, false},
		{"current_still_pending", func(p, c *model.HostFactoryCallVectorChunk) { *c = *p }, false},
		{"current_republishes_prefix", func(p, c *model.HostFactoryCallVectorChunk) {
			*c = hostVectorChunk(hostVectorPrimitive("stdout_read", 15, "returned"), hostVectorPrimitive("stdout_read", 16, "returned"))
		}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := hostVectorChunk(hostVectorPrimitive("stdout_read", 16, "called_pending"))
			c := hostVectorChunk(hostVectorPrimitive("stdout_read", 16, "returned"))
			if tc.mutate != nil {
				tc.mutate(&p, &c)
			}
			err := ValidateHostFactoryPendingSuccessor(p, c)
			if !tc.accepted {
				hostVectorRefused(t, err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func hostVectorReference(operation string) model.HostFactoryCallVectorReference {
	return model.HostFactoryCallVectorReference{Operation: operation, OriginalHandleID: hostVectorHandle, OriginalOwnerID: hostVectorOwner, SubjectOwnerID: hostVectorSubject, CollectionState: "complete_original_calls"}
}

func TestHostOriginalFactoryIndependentClose(t *testing.T) {
	makeFact := func() model.HostFactoryDiagnosticIOFact {
		// The test describes an unavailable Read and a distinct returned Close.
		// It verifies the DTO relation only, without claiming either syscall ran.
		closeRef := hostVectorReference("stdout_close")
		closeRef.OwnerPrimitiveRawSHA256 = hostVectorPtr(hostVectorSHA())
		closeRef.FirstOrdinal = 1
		closeRef.LastOrdinal = 1
		closeRef.OriginalCallCount = 1
		closeRef.ManifestRootSHA256 = hostVectorPtr(hostVectorSHA())
		return model.HostFactoryDiagnosticIOFact{Operation: "stdout_read", OriginalHandleID: hostVectorHandle, SubjectOwnerID: hostVectorSubject, OriginalState: "not_called", OriginalReturnClass: "unavailable", OriginalHashState: "unknown_original_bytes", OriginalCloseState: "returned", OriginalCloseClass: "success", OriginalCloseReturnedAt: hostVectorPtr(hostVectorTime().Add(time.Second)), OriginalOperationDeadline: hostVectorTime().Add(60 * time.Second), OriginalCallVector: hostVectorReference("stdout_read"), OriginalCloseCallVector: closeRef}
	}
	tests := []struct {
		name     string
		mutate   func(*model.HostFactoryDiagnosticIOFact)
		accepted bool
	}{
		{"close_return_retained_without_read", nil, true},
		{"close_io_refusal_is_retained_diagnostic", func(f *model.HostFactoryDiagnosticIOFact) { f.OriginalCloseClass = "io_refused" }, true},
		{"unacquired_close_has_no_return", func(f *model.HostFactoryDiagnosticIOFact) {
			f.OriginalCloseState = "not_acquired"
			f.OriginalCloseClass = "unavailable"
			f.OriginalCloseReturnedAt = nil
			f.OriginalCloseCallVector = hostVectorReference("stdout_close")
		}, true},
		{"pending_close_has_no_return", func(f *model.HostFactoryDiagnosticIOFact) {
			f.OriginalCloseState = "acquired_pending"
			f.OriginalCloseClass = "unavailable"
			f.OriginalCloseReturnedAt = nil
			f.OriginalCloseCallVector.CollectionState = "same_original_call_pending"
		}, true},
		{"returned_close_missing_time", func(f *model.HostFactoryDiagnosticIOFact) { f.OriginalCloseReturnedAt = nil }, false},
		{"unacquired_close_invented_time", func(f *model.HostFactoryDiagnosticIOFact) {
			f.OriginalCloseState = "not_acquired"
			f.OriginalCloseClass = "unavailable"
		}, false},
		{"pending_close_invented_time", func(f *model.HostFactoryDiagnosticIOFact) {
			f.OriginalCloseState = "acquired_pending"
			f.OriginalCloseClass = "unavailable"
		}, false},
		{"close_does_not_supply_eof", func(f *model.HostFactoryDiagnosticIOFact) { f.OriginalEOF = hostVectorPtr(true) }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := makeFact()
			if tc.mutate != nil {
				tc.mutate(&f)
			}
			err := ValidateHostFactory(f)
			if !tc.accepted {
				hostVectorRefused(t, err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var out model.HostFactoryDiagnosticIOFact
			if err := DecodeHostFactory(hostVectorJSON(t, f), &out); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(f, out) {
				t.Fatal("independent Close changed")
			}
		})
	}
}

func TestHostOriginalFactorySuccessfulReadDeadline(t *testing.T) {
	makeFact := func() model.HostFactoryOriginalIOFact {
		// Intrinsic successful-read consistency only. The opaque manifest hashes
		// must still be resolved/authenticated by an actual external consumer.
		read := hostVectorReference("stdout_read")
		read.OwnerPrimitiveRawSHA256 = hostVectorPtr(hostVectorSHA())
		read.FirstOrdinal, read.LastOrdinal, read.OriginalCallCount = 1, 1, 1
		read.ManifestRootSHA256 = hostVectorPtr(hostVectorSHA())
		close := read
		close.Operation = "stdout_close"
		close.FirstOrdinal, close.LastOrdinal = 2, 2
		close.ManifestRootSHA256 = hostVectorPtr(strings.Repeat("b", 64))
		return model.HostFactoryOriginalIOFact{Operation: "stdout_read", OriginalHandleID: hostVectorHandle, OwnerPrimitiveRawSHA256: hostVectorSHA(), OriginalCalledAt: hostVectorTime(), OriginalReturnedAt: hostVectorTime().Add(time.Nanosecond), OriginalCount: 0, OriginalSHA256: HostFactoryRawSHA256(nil), OriginalReturnClass: "eof", OriginalCloseReturnedAt: hostVectorTime().Add(2 * time.Nanosecond), SubjectOwnerID: hostVectorSubject, OriginalOperationDeadline: hostVectorTime().Add(60 * time.Second), OriginalEOF: true, OriginalCallVector: read, OriginalCloseCallVector: close}
	}
	tests := []struct {
		name     string
		mutate   func(*model.HostFactoryOriginalIOFact)
		accepted bool
	}{
		{"in_bound_empty_eof_read_shape", nil, true},
		{"read_return_after_original_deadline", func(f *model.HostFactoryOriginalIOFact) {
			f.OriginalReturnedAt = f.OriginalOperationDeadline.Add(time.Nanosecond)
			f.OriginalCloseReturnedAt = f.OriginalReturnedAt.Add(time.Nanosecond)
		}, false},
		{"close_return_after_original_deadline", func(f *model.HostFactoryOriginalIOFact) {
			f.OriginalCloseReturnedAt = f.OriginalOperationDeadline.Add(time.Nanosecond)
		}, false},
		{"eof_cannot_replace_close_vector", func(f *model.HostFactoryOriginalIOFact) {
			f.OriginalCloseCallVector = hostVectorReference("stdout_close")
		}, false},
		{"pending_vector_is_not_successful_read", func(f *model.HostFactoryOriginalIOFact) {
			f.OriginalCallVector.CollectionState = "same_original_call_pending"
		}, false},
		{"partial_zero_is_not_successful_eof", func(f *model.HostFactoryOriginalIOFact) { f.OriginalEOF = false; f.OriginalReturnClass = "partial" }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := makeFact()
			if tc.mutate != nil {
				tc.mutate(&f)
			}
			err := ValidateHostFactory(f)
			if !tc.accepted {
				hostVectorRefused(t, err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

type hostVectorPredecessor struct {
	raw   []byte
	index uint32
}
type hostVectorGraph struct {
	reference model.HostFactoryCallVectorReference
	root      model.HostFactoryCallVectorManifest
	bodies    map[string][]byte
	links     map[string]hostVectorPredecessor
}

func (g *hostVectorGraph) store(t *testing.T, body any) string {
	raw := hostVectorJSON(t, body)
	sha := HostFactoryRawSHA256(raw)
	g.bodies[sha] = raw
	return sha
}
func (g *hostVectorGraph) selectRoot(t *testing.T) {
	sha := g.store(t, g.root)
	g.reference.ManifestRootSHA256 = &sha
}
func (g *hostVectorGraph) resolve(sha string) ([]byte, error) {
	raw, ok := g.bodies[sha]
	if !ok {
		return nil, errors.New("source vector missing body")
	}
	return raw, nil
}
func (g *hostVectorGraph) predecessor(sha string, index uint32) ([]byte, uint32, error) {
	// nil,0,nil is returned ONLY for an explicit structural FIRST relation.
	// In production that distinction belongs to the immutable SQL13 lookup.
	p, ok := g.links[fmt.Sprintf("%s:%d", sha, index)]
	if !ok {
		return nil, 0, errors.New("source vector missing immutable relation")
	}
	return p.raw, p.index, nil
}
func (g *hostVectorGraph) first(sha string, count int) {
	for i := 0; i < count; i++ {
		g.links[fmt.Sprintf("%s:%d", sha, i)] = hostVectorPredecessor{}
	}
}
func hostVectorNewGraph(t *testing.T) hostVectorGraph {
	t.Helper()
	g := hostVectorGraph{bodies: map[string][]byte{}, links: map[string]hostVectorPredecessor{}}
	calls := []model.HostFactoryPrimitiveIOReturn{}
	for i := uint64(1); i <= 15; i++ {
		calls = append(calls, hostVectorPrimitive("stdout_read", i, "returned"))
	}
	prefix := g.store(t, hostVectorChunk(calls...))
	g.first(prefix, 15)
	pending := hostVectorChunk(hostVectorPrimitive("stdout_read", 16, "called_pending"))
	pendingRaw := hostVectorJSON(t, pending)
	g.store(t, pending)
	successor := g.store(t, hostVectorChunk(hostVectorPrimitive("stdout_read", 16, "returned")))
	g.links[successor+":0"] = hostVectorPredecessor{pendingRaw, 0}
	g.root = model.HostFactoryCallVectorManifest{Schema: "original_host_factory_call_vector_manifest_v2", Purpose: "original_host_factory_call_vector_manifest_v2", BindingSchema: hostVectorScopeSchema, BindingSHA256: hostVectorSHA(), OwnerRole: "host_exterior", OriginalOwnerID: hostVectorOwner, OwnerPrimitiveRawSHA256: hostVectorSHA(), Operation: "stdout_read", OriginalHandleID: hostVectorHandle, Level: 0, FirstOrdinal: 1, LastOrdinal: 16, OriginalCallCount: 16, ChildBodySHAs: []string{prefix, successor}, CollectionState: "complete_original_calls"}
	g.reference = hostVectorReference("stdout_read")
	g.reference.OwnerPrimitiveRawSHA256 = hostVectorPtr(hostVectorSHA())
	g.reference.FirstOrdinal = 1
	g.reference.LastOrdinal = 16
	g.reference.OriginalCallCount = 16
	g.selectRoot(t)
	return g
}

func TestHostOriginalFactoryCallVectorGraph(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*testing.T, *hostVectorGraph)
		accepted bool
	}{
		{"fifteen_terminal_plus_returned_successor", nil, true},
		{"two_sequential_pending_successors", func(t *testing.T, g *hostVectorGraph) {
			children := []string{}
			for i := uint64(1); i <= 2; i++ {
				pending := hostVectorJSON(t, hostVectorChunk(hostVectorPrimitive("stdout_read", i, "called_pending")))
				successor := g.store(t, hostVectorChunk(hostVectorPrimitive("stdout_read", i, "returned")))
				g.links[successor+":0"] = hostVectorPredecessor{pending, 0}
				children = append(children, successor)
			}
			g.root.LastOrdinal = 2
			g.root.OriginalCallCount = 2
			g.root.ChildBodySHAs = children
			g.reference.LastOrdinal = 2
			g.reference.OriginalCallCount = 2
			g.selectRoot(t)
		}, true},
		{"late_returned_collection_is_retention_only", func(t *testing.T, g *hostVectorGraph) {
			old := g.root.ChildBodySHAs[1]
			c := hostVectorChunk(hostVectorPrimitive("stdout_read", 16, "returned"))
			c.OriginalCalls[0].OriginalReturnedAt = hostVectorPtr(c.OriginalCalls[0].OriginalOperationDeadline.Add(time.Nanosecond))
			c.RecordedAt = c.OriginalCalls[0].OriginalReturnedAt.Add(time.Nanosecond)
			sha := g.store(t, c)
			g.links[sha+":0"] = g.links[old+":0"]
			g.root.ChildBodySHAs[1] = sha
			g.selectRoot(t)
		}, true},
		{"partial_zero_collection_is_retention_only", func(t *testing.T, g *hostVectorGraph) {
			old := g.root.ChildBodySHAs[1]
			c := hostVectorChunk(hostVectorPrimitive("stdout_read", 16, "returned"))
			c.OriginalCalls[0].OriginalReturnClass = "partial"
			sha := g.store(t, c)
			g.links[sha+":0"] = g.links[old+":0"]
			g.root.ChildBodySHAs[1] = sha
			g.selectRoot(t)
		}, true},
		{"missing_child_body", func(t *testing.T, g *hostVectorGraph) { delete(g.bodies, g.root.ChildBodySHAs[1]) }, false},
		{"resolver_bytes_do_not_match_requested_sha", func(t *testing.T, g *hostVectorGraph) {
			key := g.root.ChildBodySHAs[1]
			c := hostVectorChunk(hostVectorPrimitive("stdout_read", 16, "returned"))
			c.RecordedAt = c.RecordedAt.Add(time.Nanosecond)
			g.bodies[key] = hostVectorJSON(t, c)
		}, false},
		{"missing_immutable_first_relation", func(t *testing.T, g *hostVectorGraph) { delete(g.links, g.root.ChildBodySHAs[0]+":0") }, false},
		{"missing_pending_successor_relation", func(t *testing.T, g *hostVectorGraph) { delete(g.links, g.root.ChildBodySHAs[1]+":0") }, false},
		{"wrong_pending_fact_index", func(t *testing.T, g *hostVectorGraph) {
			key := g.root.ChildBodySHAs[1] + ":0"
			p := g.links[key]
			p.index = 1
			g.links[key] = p
		}, false},
		{"foreign_pending_called_time", func(t *testing.T, g *hostVectorGraph) {
			key := g.root.ChildBodySHAs[1] + ":0"
			p := hostVectorChunk(hostVectorPrimitive("stdout_read", 16, "called_pending"))
			p.OriginalCalls[0].OriginalCalledAt = hostVectorPtr(p.OriginalCalls[0].OriginalCalledAt.Add(time.Nanosecond))
			p.RecordedAt = *p.OriginalCalls[0].OriginalCalledAt
			g.links[key] = hostVectorPredecessor{hostVectorJSON(t, p), 0}
		}, false},
		{"terminal_gap", func(t *testing.T, g *hostVectorGraph) {
			calls := []model.HostFactoryPrimitiveIOReturn{}
			for i := uint64(1); i <= 14; i++ {
				calls = append(calls, hostVectorPrimitive("stdout_read", i, "returned"))
			}
			sha := g.store(t, hostVectorChunk(calls...))
			g.first(sha, 14)
			g.root.ChildBodySHAs[0] = sha
			g.selectRoot(t)
		}, false},
		{"duplicate_child_overlap", func(t *testing.T, g *hostVectorGraph) {
			g.root.ChildBodySHAs = append(g.root.ChildBodySHAs, g.root.ChildBodySHAs[1])
			g.selectRoot(t)
		}, false},
		{"historic_pending_and_successor_selected_together", func(t *testing.T, g *hostVectorGraph) {
			sha := g.store(t, hostVectorChunk(hostVectorPrimitive("stdout_read", 16, "called_pending")))
			g.root.ChildBodySHAs = append(g.root.ChildBodySHAs, sha)
			g.selectRoot(t)
		}, false},
		{"manifest_claimed_count_wrong", func(t *testing.T, g *hostVectorGraph) { g.root.OriginalCallCount = 15; g.selectRoot(t) }, false},
		{"reference_claimed_count_wrong", func(t *testing.T, g *hostVectorGraph) { g.reference.OriginalCallCount = 15 }, false},
		{"foreign_reference_subject", func(t *testing.T, g *hostVectorGraph) { g.reference.SubjectOwnerID = hostVectorOwner }, false},
		{"foreign_reference_owner", func(t *testing.T, g *hostVectorGraph) { g.reference.OriginalOwnerID = hostVectorSubject }, false},
		{"foreign_manifest_binding", func(t *testing.T, g *hostVectorGraph) {
			g.root.BindingSHA256 = strings.Repeat("b", 64)
			g.selectRoot(t)
		}, false},
		{"mixed_manifest_level", func(t *testing.T, g *hostVectorGraph) { g.root.Level = 1; g.selectRoot(t) }, false},
		{"manifest_depth_above_three", func(t *testing.T, g *hostVectorGraph) { g.root.Level = 4; g.selectRoot(t) }, false},
		{"more_than_sixteen_children", func(t *testing.T, g *hostVectorGraph) {
			children := []string{}
			for i := 0; i < 17; i++ {
				children = append(children, g.root.ChildBodySHAs[1])
			}
			g.root.ChildBodySHAs = children
			g.selectRoot(t)
		}, false},
		{"incomplete_retention_not_complete", func(t *testing.T, g *hostVectorGraph) { g.reference.CollectionState = "incomplete_retention" }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := hostVectorNewGraph(t)
			if tc.mutate != nil {
				tc.mutate(t, &g)
			}
			err := ValidateHostFactoryCallVector(g.reference, g.resolve, g.predecessor)
			if !tc.accepted {
				hostVectorRefused(t, err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("resolver_callback_required", func(t *testing.T) {
		g := hostVectorNewGraph(t)
		hostVectorRefused(t, ValidateHostFactoryCallVector(g.reference, nil, g.predecessor))
	})
	t.Run("predecessor_callback_required", func(t *testing.T) {
		g := hostVectorNewGraph(t)
		hostVectorRefused(t, ValidateHostFactoryCallVector(g.reference, g.resolve, nil))
	})
	t.Run("predecessor_error_not_first", func(t *testing.T) {
		g := hostVectorNewGraph(t)
		hostVectorRefused(t, ValidateHostFactoryCallVector(g.reference, g.resolve, func(string, uint32) ([]byte, uint32, error) { return nil, 0, errors.New("missing SQL13 association") }))
	})
	t.Run("pending_only_cannot_claim_complete", func(t *testing.T) {
		g := hostVectorNewGraph(t)
		sha := g.store(t, hostVectorChunk(hostVectorPrimitive("stdout_read", 1, "called_pending")))
		g.first(sha, 1)
		g.root.LastOrdinal = 1
		g.root.OriginalCallCount = 1
		g.root.ChildBodySHAs = []string{sha}
		g.reference.LastOrdinal = 1
		g.reference.OriginalCallCount = 1
		g.selectRoot(t)
		hostVectorRefused(t, ValidateHostFactoryCallVector(g.reference, g.resolve, g.predecessor))
	})
}

func TestHostOriginalFactoryOperationTuples(t *testing.T) {
	tests := []struct {
		name, operation, owner, subject, stage, binding, envelope string
		accepted                                                  bool
	}{
		{"ordinary_original_start_tuple", "qemu_start", "factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", hostVectorOrdinarySchema, "HostFactoryRootSignedEnvelope", true},
		{"ordinary_native_observer_tuple", "boot_id_read", "host_registrar", "factory_ordinary_worker", "native_alive", hostVectorOrdinarySchema, "HostFactoryRootSignedEnvelope", true},
		{"ordinary_bootstrap_close_tuple", "ordinary_bootstrap_reader_close", "factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_bootstrap", hostVectorOrdinarySchema, "HostFactoryRootSignedEnvelope", true},
		{"ordinary_cleanup_close_tuple", "ordinary_bootstrap_reader_close", "factory_ordinary_worker", "factory_ordinary_worker", "cleanup", hostVectorOrdinarySchema, "HostFactoryRootSignedEnvelope", true},
		{"native_reader_flags_sealed_prepared_create_unreviewed", "native_reader_flags", "host_worker", "host_worker", "prepared_create", hostVectorScopeSchema, "HostFactorySignedEnvelope", false},
		{"native_reader_flags_ordinary_prepared_create_unreviewed", "native_reader_flags", "factory_ordinary_worker", "factory_ordinary_worker", "prepared_create", hostVectorOrdinarySchema, "HostFactoryRootSignedEnvelope", false},
		{"ordinary_start_host_subject_alias", "qemu_start", "factory_ordinary_worker", "host_worker", "ordinary_before_start", hostVectorOrdinarySchema, "HostFactoryRootSignedEnvelope", false},
		{"ordinary_start_host_scope_alias", "qemu_start", "factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", hostVectorScopeSchema, "HostFactoryRootSignedEnvelope", false},
		{"ordinary_start_host_envelope_alias", "qemu_start", "factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", hostVectorOrdinarySchema, "HostFactorySignedEnvelope", false},
		{"ordinary_start_host_signer_alias", "qemu_start", "host_worker", "factory_ordinary_worker", "ordinary_before_start", hostVectorOrdinarySchema, "HostFactoryRootSignedEnvelope", false},
		{"ordinary_native_stage_cartesian_alias", "boot_id_read", "host_registrar", "factory_ordinary_worker", "initial_empty", hostVectorOrdinarySchema, "HostFactoryRootSignedEnvelope", false},
		{"ordinary_generic_eof_alias", "bootstrap_eof_read", "factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_bootstrap", hostVectorOrdinarySchema, "HostFactoryRootSignedEnvelope", false},
		{"historic_credential_close_alias", "ordinary_credential_close", "factory_ordinary_worker", "factory_ordinary_worker", "ordinary_early_credential", hostVectorOrdinarySchema, "HostFactoryRootSignedEnvelope", false},
		{"unknown_operation", "shell_exec", "factory_ordinary_worker", "factory_ordinary_worker", "ordinary_before_start", hostVectorOrdinarySchema, "HostFactoryRootSignedEnvelope", false},
		{"unknown_role", "qemu_start", "unknown", "factory_ordinary_worker", "ordinary_before_start", hostVectorOrdinarySchema, "HostFactoryRootSignedEnvelope", false},
		{"unknown_stage", "qemu_start", "factory_ordinary_worker", "factory_ordinary_worker", "future_start", hostVectorOrdinarySchema, "HostFactoryRootSignedEnvelope", false},
		{"new_worker_getfl_exact_tuple", "fcntl_getfl", "host_worker", "host_worker", "worker_bootstrap", hostVectorScopeSchema, "HostFactorySignedEnvelope", true},
		{"getfl_not_generic_observer_permission", "fcntl_getfl", "host_worker", "host_registrar", "worker_bootstrap", hostVectorScopeSchema, "HostFactorySignedEnvelope", false},
		{"conditional_setfl_exact_worker_tuple", "fcntl_setfl", "host_worker", "host_worker", "worker_bootstrap", hostVectorScopeSchema, "HostFactorySignedEnvelope", true},
		{"conditional_setfl_not_exterior_cartesian", "fcntl_setfl", "host_exterior", "host_worker", "worker_bootstrap", hostVectorScopeSchema, "HostFactorySignedEnvelope", false},
		{"getdents_raw_independent_initial_tuple", "task_inventory_getdents", "host_registrar", "host_exterior", "initial_empty", hostVectorRootSchema, "HostFactoryRootSignedEnvelope", true},
		{"getdents_not_ordinary_terminal_absence", "task_inventory_getdents", "host_registrar", "factory_ordinary_worker", "terminal_read", hostVectorOrdinarySchema, "HostFactoryRootSignedEnvelope", false},
		{"initial_ledger_exclusive_original_root_tuple", "initial_ledger_open_exclusive", "host_exterior", "host_exterior", "root_prepare", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", true},
		{"initial_ledger_not_rootpreparation_alias", "initial_ledger_open_exclusive", "host_exterior", "host_exterior", "root_prepare", hostVectorRootSchema, "HostFactoryRootSignedEnvelope", false},
		{"initial_ledger_not_other_owner", "initial_ledger_open_exclusive", "host_registrar", "host_exterior", "root_prepare", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", false},
		{"source_directory_not_control_observer_cartesian", "source_directory_open", "host_registrar", "host_exterior", "root_prepare", "original_host_factory_source_approval_v4", "HostFactoryRootSignedEnvelope", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHostFactoryOperation(tc.operation, tc.owner, tc.subject, tc.stage, tc.binding, tc.envelope)
			if !tc.accepted {
				hostVectorRefused(t, err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("fixed_operation_caps", func(t *testing.T) {
		for operation, want := range map[string]int64{"stdout_read": 65536, "bootstrap_key64_read": 64, "bootstrap_eof_read": 1, "executable_read": 134217728, "original_disk_read": 536870912, "worker_wait": 0} {
			got, err := HostFactoryOperationCap(operation)
			if err != nil || got != want {
				t.Fatalf("%s cap=%d,err=%v", operation, got, err)
			}
		}
	})
	t.Run("historic_alias_has_no_cap", func(t *testing.T) {
		_, err := HostFactoryOperationCap("ordinary_credential_close")
		hostVectorRefused(t, err)
	})
}

func hostVectorReservation() model.HostFactoryUnissuedChoiceReservation {
	return model.HostFactoryUnissuedChoiceReservation{Schema: "original_host_factory_unissued_choice_reservation_v4", Purpose: "original_host_factory_unissued_choice_reservation_v4", PreAuthorityScopeSHA256: hostVectorSHA(), AliveRegistrationSHA256: strings.Repeat("b", 64), ReservationID: hostVectorOwner, Choice: "sealed_before_possible_create", ReservedAt: hostVectorTime(), OriginalChoiceDeadline: hostVectorTime().Add(60 * time.Second)}
}
func hostVectorApprovalAndScope() (model.HostFactorySourceApproval, model.HostFactoryPreAuthorityScope) {
	// The distinct CODE/PUB scalars are protocol inputs, never an override of
	// debug.ReadBuildInfo or an assertion that this Go test is a native supplier.
	approval := model.HostFactorySourceApproval{
		Schema: "original_host_factory_source_approval_v4", Purpose: "original_host_factory_source_approval_v4",
		FactoryRegistrySHA256: hostVectorSHA(), FactorySourceClosureSHA256: hostVectorSHA(), ApprovedPeerSourceCODE: strings.Repeat("a", 40), ActualBuildSourceCommit: strings.Repeat("b", 40), BuildReceiptSHA256: hostVectorSHA(), SourceInputsSHA256: hostVectorSHA(), MetadataEquivalenceRawSHA256: hostVectorSHA(), CredentialRoleInventorySHA256: hostVectorSHA(),
		AllowedNamespace: "dakasa", AllowedPolicyID: hostVectorOwner, AllowedWorkflowID: hostVectorHandle, AllowedOriginalStepID: "original-create", AllowedMutationBindingName: "native-qemu", AllowedSlot: 1, ScopeRootID: hostVectorSubject, ApprovedAt: hostVectorTime().Add(-time.Second), OriginalApprovalDeadline: hostVectorTime().Add(600 * time.Second), AllowedFactoryEntryClasses: []string{"sealed_a0", "sealed_a1", "ordinary_original_create"}, AllowedAssessStepID: "original-assess", AllowedClaimStepID: "original-claim",
	}
	scope := model.HostFactoryPreAuthorityScope{
		Schema: hostVectorScopeSchema, Purpose: hostVectorScopeSchema, FactoryRealmID: hostVectorOwner, FactoryAttemptID: hostVectorHandle, CreatorOwnerID: hostVectorSubject, Namespace: "dakasa", PolicyID: hostVectorOwner, PolicyChecksum: hostVectorSHA(), WorkflowID: hostVectorHandle, WorkflowChecksum: hostVectorSHA(), OriginalStepID: "original-create", OriginalStepTimeoutSeconds: 600, Generation: 1, Fence: 1, LeaseOwnerSHA256: hostVectorSHA(), ExecutorID: hostVectorOwner, MutationBindingName: "native-qemu", Slot: 1, PlannedDesiredSpecSHA256: hostVectorSHA(), PlannedMutationRequestSHA256: hostVectorSHA(), ProfileManifestSHA256: hostVectorSHA(), FactoryRegistrySHA256: hostVectorSHA(), FactorySourceClosureSHA256: hostVectorSHA(), CoreActualSourceCommit: strings.Repeat("b", 40), BootstrapChallengeSetSHA256: hostVectorSHA(), OriginalContextStartedAt: hostVectorTime(), OriginalContextDeadline: hostVectorTime().Add(600 * time.Second), OriginalLeaseExpiresAt: hostVectorTime().Add(300 * time.Second), ApprovedProvisioningBudgetSeconds: 420, ScopeRootID: hostVectorSubject, InitialEmptyRealmReadSHA256: hostVectorSHA(), OriginalLeaseProvenanceSHA256: hostVectorSHA(), StableOriginalTargetSHA256: hostVectorSHA(), FactoryEntryClass: "sealed_a0",
	}
	return approval, scope
}

func TestHostOriginalFactoryCryptoDomains(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	public := key.Public().(ed25519.PublicKey)
	body := hostVectorReservation()
	makeEnvelope := func(t *testing.T) ([]byte, model.HostFactorySignedEnvelope) {
		t.Helper()
		raw, err := SignHostFactoryEnvelope(body, "host_core_issuer", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		if err != nil {
			t.Fatal(err)
		}
		var e model.HostFactorySignedEnvelope
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		return raw, e
	}
	t.Run("host_exact_nul_domain", func(t *testing.T) {
		raw, e := makeEnvelope(t)
		bodyRaw := hostVectorJSON(t, body)
		signature, err := base64.StdEncoding.DecodeString(e.SignatureBase64)
		if err != nil {
			t.Fatal(err)
		}
		domain := []byte(strings.Join([]string{"original_host_factory_signed_envelope_v4", body.Purpose, "host_core_issuer", hostVectorOwner, hostVectorSHA()}, "\x00") + "\x00")
		domain = append(domain, bodyRaw...)
		if !ed25519.Verify(public, domain, signature) {
			t.Fatal("Host NUL domain changed")
		}
		var out model.HostFactoryUnissuedChoiceReservation
		if err := VerifyHostFactoryEnvelope(raw, &out, "host_core_issuer", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), public); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(out, body) {
			t.Fatal("signed body changed")
		}
		if HostFactoryRawSHA256(raw) == HostFactoryRawSHA256(bodyRaw) {
			t.Fatal("envelope digest aliased body digest")
		}
	})
	t.Run("root_exact_nul_binding_domain", func(t *testing.T) {
		approval, _ := hostVectorApprovalAndScope()
		bodyRaw := hostVectorJSON(t, approval)
		binding := HostFactoryRawSHA256(bodyRaw)
		raw, err := SignHostFactoryEnvelope(approval, "host_source_approver", hostVectorOwner, approval.Schema, binding, key)
		if err != nil {
			t.Fatal(err)
		}
		var e model.HostFactoryRootSignedEnvelope
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		signature, err := base64.StdEncoding.DecodeString(e.SignatureBase64)
		if err != nil {
			t.Fatal(err)
		}
		domain := []byte(strings.Join([]string{"original_host_factory_root_signed_envelope_v4", approval.Purpose, "host_source_approver", hostVectorOwner, approval.Schema, binding}, "\x00") + "\x00")
		domain = append(domain, bodyRaw...)
		if !ed25519.Verify(public, domain, signature) {
			t.Fatal("Root NUL binding domain changed")
		}
		var out model.HostFactorySourceApproval
		if err := VerifyHostFactoryEnvelope(raw, &out, "host_source_approver", hostVectorOwner, approval.Schema, binding, public); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(approval, out) {
			t.Fatal("Root signed body changed")
		}
	})
	tests := []struct {
		name                      string
		mutate                    func(*model.HostFactorySignedEnvelope)
		role, keyID, binding, sha string
		pub                       ed25519.PublicKey
	}{
		{"different_purpose", func(e *model.HostFactorySignedEnvelope) {
			e.Purpose = "original_host_factory_issued_choice_reservation_v4"
		}, "host_core_issuer", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), public},
		{"different_role", func(e *model.HostFactorySignedEnvelope) { e.Role = "host_worker" }, "host_core_issuer", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), public},
		{"different_scoped_key_id", nil, "host_core_issuer", hostVectorSubject, hostVectorScopeSchema, hostVectorSHA(), public},
		{"different_scope_body_sha", nil, "host_core_issuer", hostVectorOwner, hostVectorScopeSchema, strings.Repeat("b", 64), public},
		{"root_binding_cannot_alias_host", nil, "host_core_issuer", hostVectorOwner, hostVectorRootSchema, hostVectorSHA(), public},
		{"different_body_same_valid_shape", func(e *model.HostFactorySignedEnvelope) {
			changed := body
			changed.ReservationID = hostVectorSubject
			e.BodyBase64 = base64.StdEncoding.EncodeToString(hostVectorJSON(t, changed))
		}, "host_core_issuer", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), public},
		{"different_public_key", nil, "host_core_issuer", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x32}, ed25519.SeedSize)).Public().(ed25519.PublicKey)},
		{"short_public_key", nil, "host_core_issuer", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), ed25519.PublicKey{1}},
		{"base64_signature_newline", func(e *model.HostFactorySignedEnvelope) { e.SignatureBase64 += "\n" }, "host_core_issuer", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), public},
		{"base64_body_newline", func(e *model.HostFactorySignedEnvelope) { e.BodyBase64 += "\n" }, "host_core_issuer", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), public},
		{"short_signature", func(e *model.HostFactorySignedEnvelope) {
			e.SignatureBase64 = base64.StdEncoding.EncodeToString(make([]byte, 63))
		}, "host_core_issuer", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), public},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, e := makeEnvelope(t)
			if tc.mutate != nil {
				tc.mutate(&e)
			}
			var out model.HostFactoryUnissuedChoiceReservation
			hostVectorRefused(t, VerifyHostFactoryEnvelope(hostVectorJSON(t, e), &out, tc.role, tc.keyID, tc.binding, tc.sha, tc.pub))
		})
	}
	t.Run("unsigned_gate_body_is_not_signature_stage", func(t *testing.T) {
		_, err := SignHostFactoryEnvelope(hostVectorChoice(), "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		hostVectorRefused(t, err)
	})
	t.Run("short_private_key_refused", func(t *testing.T) {
		_, err := SignHostFactoryEnvelope(body, "host_core_issuer", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), ed25519.PrivateKey{1})
		hostVectorRefused(t, err)
	})
	t.Run("private_key64_public_half_mismatch_refused", func(t *testing.T) {
		malformed := append(ed25519.PrivateKey(nil), key...)
		malformed[ed25519.SeedSize] ^= 1
		raw, err := SignHostFactoryEnvelope(body, "host_core_issuer", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), malformed)
		hostVectorRefused(t, err)
		if len(raw) != 0 {
			t.Fatal("malformed private key emitted an envelope")
		}
	})
	t.Run("signature_without_nul_separators_refused", func(t *testing.T) {
		_, e := makeEnvelope(t)
		wrongDomain := append([]byte(e.Schema+e.Purpose+e.Role+e.KeyID+e.PreAuthorityScopeSHA256), hostVectorJSON(t, body)...)
		e.SignatureBase64 = base64.StdEncoding.EncodeToString(ed25519.Sign(key, wrongDomain))
		var out model.HostFactoryUnissuedChoiceReservation
		hostVectorRefused(t, VerifyHostFactoryEnvelope(hostVectorJSON(t, e), &out, "host_core_issuer", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), public))
	})
	t.Run("root_binding_schema_is_signed", func(t *testing.T) {
		approval, _ := hostVectorApprovalAndScope()
		binding := HostFactoryRawSHA256(hostVectorJSON(t, approval))
		raw, err := SignHostFactoryEnvelope(approval, "host_source_approver", hostVectorOwner, approval.Schema, binding, key)
		if err != nil {
			t.Fatal(err)
		}
		var e model.HostFactoryRootSignedEnvelope
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		e.BindingSchema = hostVectorRootSchema
		var out model.HostFactorySourceApproval
		hostVectorRefused(t, VerifyHostFactoryEnvelope(hostVectorJSON(t, e), &out, "host_source_approver", hostVectorOwner, approval.Schema, binding, public))
	})
	t.Run("root_binding_body_sha_is_signed", func(t *testing.T) {
		approval, _ := hostVectorApprovalAndScope()
		binding := HostFactoryRawSHA256(hostVectorJSON(t, approval))
		raw, err := SignHostFactoryEnvelope(approval, "host_source_approver", hostVectorOwner, approval.Schema, binding, key)
		if err != nil {
			t.Fatal(err)
		}
		var e model.HostFactoryRootSignedEnvelope
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		e.BindingSHA256 = strings.Repeat("c", 64)
		var out model.HostFactorySourceApproval
		hostVectorRefused(t, VerifyHostFactoryEnvelope(hostVectorJSON(t, e), &out, "host_source_approver", hostVectorOwner, approval.Schema, binding, public))
	})
}

func TestHostOriginalFactorySourceBinding(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*model.HostFactorySourceApproval, *model.HostFactoryPreAuthorityScope)
		accepted bool
	}{
		{"reviewed_code_distinct_actual_pub", nil, true},
		{"reviewed_code_not_compiled_source_alias", func(a *model.HostFactorySourceApproval, s *model.HostFactoryPreAuthorityScope) {
			s.CoreActualSourceCommit = a.ApprovedPeerSourceCODE
		}, false},
		{"actual_build_source_mismatch", func(a *model.HostFactorySourceApproval, s *model.HostFactoryPreAuthorityScope) {
			a.ActualBuildSourceCommit = strings.Repeat("c", 40)
		}, false},
		{"metadata_equivalence_digest_missing", func(a *model.HostFactorySourceApproval, s *model.HostFactoryPreAuthorityScope) {
			a.MetadataEquivalenceRawSHA256 = ""
		}, false},
		{"source_input_digest_missing", func(a *model.HostFactorySourceApproval, s *model.HostFactoryPreAuthorityScope) {
			a.SourceInputsSHA256 = ""
		}, false},
		{"wrong_registry", func(a *model.HostFactorySourceApproval, s *model.HostFactoryPreAuthorityScope) {
			s.FactoryRegistrySHA256 = strings.Repeat("b", 64)
		}, false},
		{"wrong_source_closure", func(a *model.HostFactorySourceApproval, s *model.HostFactoryPreAuthorityScope) {
			s.FactorySourceClosureSHA256 = strings.Repeat("b", 64)
		}, false},
		{"wrong_namespace", func(a *model.HostFactorySourceApproval, s *model.HostFactoryPreAuthorityScope) {
			s.Namespace = "foreign"
		}, false},
		{"wrong_policy", func(a *model.HostFactorySourceApproval, s *model.HostFactoryPreAuthorityScope) {
			s.PolicyID = hostVectorSubject
		}, false},
		{"wrong_workflow", func(a *model.HostFactorySourceApproval, s *model.HostFactoryPreAuthorityScope) {
			s.WorkflowID = hostVectorSubject
		}, false},
		{"wrong_original_step", func(a *model.HostFactorySourceApproval, s *model.HostFactoryPreAuthorityScope) {
			s.OriginalStepID = "foreign-create"
		}, false},
		{"wrong_binding", func(a *model.HostFactorySourceApproval, s *model.HostFactoryPreAuthorityScope) {
			s.MutationBindingName = "foreign-qemu"
		}, false},
		{"wrong_slot", func(a *model.HostFactorySourceApproval, s *model.HostFactoryPreAuthorityScope) { s.Slot = 2 }, false},
		{"wrong_root", func(a *model.HostFactorySourceApproval, s *model.HostFactoryPreAuthorityScope) {
			s.ScopeRootID = hostVectorOwner
		}, false},
		{"entry_class_not_approved", func(a *model.HostFactorySourceApproval, s *model.HostFactoryPreAuthorityScope) {
			a.AllowedFactoryEntryClasses = []string{"sealed_a1"}
		}, false},
		{"approval_deadline_precedes_context", func(a *model.HostFactorySourceApproval, s *model.HostFactoryPreAuthorityScope) {
			a.OriginalApprovalDeadline = s.OriginalContextStartedAt.Add(-time.Nanosecond)
		}, false},
		{"budget_exceeds_original_step", func(a *model.HostFactorySourceApproval, s *model.HostFactoryPreAuthorityScope) {
			s.ApprovedProvisioningBudgetSeconds = 601
		}, false},
		{"slot_outside_new_host_bound", func(a *model.HostFactorySourceApproval, s *model.HostFactoryPreAuthorityScope) {
			a.AllowedSlot = 65
			s.Slot = 65
		}, false},
		{"step_is_ascii_identifier_not_uuid", func(a *model.HostFactorySourceApproval, s *model.HostFactoryPreAuthorityScope) {
			a.AllowedOriginalStepID = "native.create-1"
			s.OriginalStepID = "native.create-1"
		}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, s := hostVectorApprovalAndScope()
			if tc.mutate != nil {
				tc.mutate(&a, &s)
			}
			err := ValidateHostFactorySourceBinding(a, s)
			if !tc.accepted {
				hostVectorRefused(t, err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if a.ApprovedPeerSourceCODE == s.CoreActualSourceCommit {
				t.Fatal("test lost CODE/PUB distinction")
			}
		})
	}
}

func TestHostOriginalFactoryRegistryUnavailable(t *testing.T) {
	t.Run("compiled_registry_empty", func(t *testing.T) {
		a, err := ApprovedHostFactorySource()
		if !errors.Is(err, ErrHostFactorySourceUnavailable) {
			t.Fatalf("registry unavailable: %v", err)
		}
		if !reflect.DeepEqual(a, model.HostFactorySourceApproval{}) {
			t.Fatal("unavailable registry supplied partial approval")
		}
	})
	t.Run("valid_dto_crypto_relation_does_not_populate_registry", func(t *testing.T) {
		a, s := hostVectorApprovalAndScope()
		if err := ValidateHostFactorySourceBinding(a, s); err != nil {
			t.Fatal(err)
		}
		selected, err := ApprovedHostFactorySource()
		if !errors.Is(err, ErrHostFactorySourceUnavailable) || !reflect.DeepEqual(selected, model.HostFactorySourceApproval{}) {
			t.Fatal("caller DTO populated trust")
		}
	})
}

// Successor byte vectors below declare internally consistent values solely to
// exercise the closed codec. They are synthetic, are not kernel/syscall/SQL
// observations, and cannot populate ApprovedHostFactorySource or native proof.
func hostVectorBothCodecs(t *testing.T, value any, accepted bool) {
	t.Helper()
	_, encodeErr := CanonicalHostFactory(value)
	out := reflect.New(reflect.TypeOf(value))
	decodeErr := DecodeHostFactory(hostVectorJSON(t, value), out.Interface())
	if accepted {
		if encodeErr != nil || decodeErr != nil {
			t.Fatalf("declared byte shape refused: encode=%v decode=%v", encodeErr, decodeErr)
		}
		if !reflect.DeepEqual(value, out.Elem().Interface()) {
			t.Fatal("declared original fields changed")
		}
	} else {
		hostVectorRefused(t, encodeErr)
		hostVectorRefused(t, decodeErr)
	}
}

func hostVectorPositiveIO(operation, closeOperation, handle string, called time.Time, count int64, digest string) model.HostFactoryOriginalIOFact {
	read := hostVectorReference(operation)
	read.OriginalHandleID = handle
	read.OwnerPrimitiveRawSHA256 = hostVectorPtr(hostVectorSHA())
	read.FirstOrdinal, read.LastOrdinal, read.OriginalCallCount = 1, 1, 1
	read.ManifestRootSHA256 = hostVectorPtr(hostVectorSHA())
	close := read
	close.Operation = closeOperation
	close.FirstOrdinal, close.LastOrdinal = 2, 2
	return model.HostFactoryOriginalIOFact{Operation: operation, OriginalHandleID: handle, OwnerPrimitiveRawSHA256: hostVectorSHA(), OriginalCalledAt: called, OriginalReturnedAt: called.Add(time.Nanosecond), OriginalCount: count, OriginalSHA256: digest, OriginalReturnClass: "eof", OriginalCloseReturnedAt: called.Add(2 * time.Nanosecond), SubjectOwnerID: hostVectorSubject, OriginalOperationDeadline: hostVectorTime().Add(60 * time.Second), OriginalEOF: true, OriginalCallVector: read, OriginalCloseCallVector: close}
}

func TestHostOriginalFactoryPositiveIOProjectionBytes(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*model.HostFactoryOriginalIOFact)
		accepted bool
	}{
		{"same_original_stdout_close", nil, true},
		{"wait_cannot_replace_close", func(f *model.HostFactoryOriginalIOFact) { f.OriginalCloseCallVector.Operation = "worker_wait" }, false},
		{"stderr_close_cannot_close_stdout", func(f *model.HostFactoryOriginalIOFact) { f.OriginalCloseCallVector.Operation = "stderr_close" }, false},
		{"foreign_close_subject", func(f *model.HostFactoryOriginalIOFact) { f.OriginalCloseCallVector.SubjectOwnerID = hostVectorOwner }, false},
		{"foreign_close_basal", func(f *model.HostFactoryOriginalIOFact) {
			f.OriginalCloseCallVector.OwnerPrimitiveRawSHA256 = hostVectorPtr(strings.Repeat("b", 64))
		}, false},
		{"foreign_close_owner", func(f *model.HostFactoryOriginalIOFact) {
			f.OriginalCloseCallVector.OriginalOwnerID = hostVectorSubject
		}, false},
		{"foreign_close_handle", func(f *model.HostFactoryOriginalIOFact) {
			f.OriginalCloseCallVector.OriginalHandleID = hostVectorSubject
		}, false},
		{"empty_outer_count_requires_empty_sha", func(f *model.HostFactoryOriginalIOFact) { f.OriginalSHA256 = hostVectorSHA() }, false},
		{"native_reader_specific_close", func(f *model.HostFactoryOriginalIOFact) {
			f.Operation = "boot_id_read"
			f.OriginalCallVector.Operation = f.Operation
			f.OriginalCloseCallVector.Operation = "native_reader_close"
		}, true},
		{"artifact_specific_close", func(f *model.HostFactoryOriginalIOFact) {
			f.Operation = "original_disk_read"
			f.OriginalCallVector.Operation = f.Operation
			f.OriginalCloseCallVector.Operation = "artifact_reader_close"
		}, true},
		{"artifact_cannot_borrow_native_close", func(f *model.HostFactoryOriginalIOFact) {
			f.Operation = "original_disk_read"
			f.OriginalCallVector.Operation = f.Operation
			f.OriginalCloseCallVector.Operation = "native_reader_close"
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := hostVectorPositiveIO("stdout_read", "stdout_close", hostVectorHandle, hostVectorTime(), 0, HostFactoryRawSHA256(nil))
			if c.mutate != nil {
				c.mutate(&f)
			}
			hostVectorBothCodecs(t, f, c.accepted)
		})
	}
}

func hostVectorNativeDeclaredBytes() model.HostFactoryNativeProcess {
	tm := hostVectorTime()
	n := model.HostFactoryNativeProcess{HostBootID: hostVectorOwner, PID: 17, PPID: 1, StartTicks: 1, ProcessNonceSHA256: hostVectorSHA(), BootstrapReturnSHA256: hostVectorSHA(), UID: 0, GID: 0, OriginalNativeReadStartedAt: tm}
	ops := [5]string{"boot_id_read", "stat_before_read", "executable_read", "cmdline_read", "stat_after_read"}
	counts := [5]int64{36, 10, 4, 3, 10}
	for i, op := range ops {
		n.NativeReadOperations[i] = hostVectorPositiveIO(op, "native_reader_close", fmt.Sprintf("55555555-5555-4555-8555-%012d", i+1), tm.Add(time.Duration(i)*10*time.Nanosecond), counts[i], strings.Repeat(string(rune('a'+i)), 64))
	}
	exe, cmdline := n.NativeReadOperations[2], n.NativeReadOperations[3]
	n.Execution = model.HostFactoryBinaryExecution{ExecutionClass: "linux_owned_binary_subprocess_v1", ScriptMode: "none_compiled_binary", BuildReceiptSHA256: hostVectorSHA(), ActualBinarySourceCommit: strings.Repeat("b", 40), ExecutableSHA256: exe.OriginalSHA256, ExecutableDevice: 1, ExecutableInode: 1, ExecutableLinkCount: 1, ExecutableUID: 0, ExecutableGID: 0, ExecutableMode: 0100755, FixedArgvSHA256: hostVectorSHA(), OriginalCmdlineReadSHA256: cmdline.OriginalSHA256, OriginalExecutableReadStartedAt: exe.OriginalCalledAt, OriginalExecutableReadBytes: int(exe.OriginalCount), OriginalExecutableReadReturnedAt: exe.OriginalReturnedAt, OriginalExecutableCloseReturnedAt: exe.OriginalCloseReturnedAt, OriginalCmdlineReadBytes: int(cmdline.OriginalCount), OriginalCmdlineReadReturnedAt: cmdline.OriginalReturnedAt, OriginalCmdlineCloseReturnedAt: cmdline.OriginalCloseReturnedAt}
	n.OriginalStatBeforeSHA256 = n.NativeReadOperations[1].OriginalSHA256
	n.OriginalStatAfterSHA256 = n.NativeReadOperations[4].OriginalSHA256
	n.OriginalNativeReadReturnedAt = n.NativeReadOperations[4].OriginalReturnedAt
	n.OriginalNativeCloseReturnedAt = n.NativeReadOperations[4].OriginalCloseReturnedAt
	hostVectorDeclaredNativeExtras(&n)
	return n
}

func TestHostOriginalFactoryNativeProjectionBytes(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*model.HostFactoryNativeProcess)
		accepted bool
	}{
		{"consistent_declared_bytes_only", nil, true},
		{"stat_before_projection_mismatch", func(n *model.HostFactoryNativeProcess) { n.OriginalStatBeforeSHA256 = hostVectorSHA() }, false},
		{"stat_after_projection_mismatch", func(n *model.HostFactoryNativeProcess) { n.OriginalStatAfterSHA256 = hostVectorSHA() }, false},
		{"executable_digest_projection_mismatch", func(n *model.HostFactoryNativeProcess) { n.Execution.ExecutableSHA256 = hostVectorSHA() }, false},
		{"executable_count_projection_mismatch", func(n *model.HostFactoryNativeProcess) { n.Execution.OriginalExecutableReadBytes++ }, false},
		{"cmdline_digest_projection_mismatch", func(n *model.HostFactoryNativeProcess) { n.Execution.OriginalCmdlineReadSHA256 = hostVectorSHA() }, false},
		{"cmdline_count_projection_mismatch", func(n *model.HostFactoryNativeProcess) { n.Execution.OriginalCmdlineReadBytes++ }, false},
		{"executable_return_projection_mismatch", func(n *model.HostFactoryNativeProcess) {
			n.Execution.OriginalExecutableReadReturnedAt = n.Execution.OriginalExecutableReadReturnedAt.Add(time.Nanosecond)
		}, false},
		{"executable_close_projection_mismatch", func(n *model.HostFactoryNativeProcess) {
			n.Execution.OriginalExecutableCloseReturnedAt = n.Execution.OriginalExecutableCloseReturnedAt.Add(time.Nanosecond)
		}, false},
		{"cmdline_close_projection_mismatch", func(n *model.HostFactoryNativeProcess) {
			n.Execution.OriginalCmdlineCloseReturnedAt = n.Execution.OriginalCmdlineCloseReturnedAt.Add(time.Nanosecond)
		}, false},
		{"read_before_declared_native_start", func(n *model.HostFactoryNativeProcess) {
			n.OriginalNativeReadStartedAt = n.OriginalNativeReadStartedAt.Add(time.Nanosecond)
		}, false},
		{"read_after_declared_native_return", func(n *model.HostFactoryNativeProcess) {
			n.OriginalNativeReadReturnedAt = n.OriginalNativeReadReturnedAt.Add(-time.Nanosecond)
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := hostVectorNativeDeclaredBytes()
			if c.mutate != nil {
				c.mutate(&n)
			}
			hostVectorBothCodecs(t, n, c.accepted)
		})
	}
}

func hostVectorIssuerFact(operation string, ordinal uint64, called time.Time) model.HostFactoryDiagnosticIOFact {
	ref := hostVectorReference(operation)
	ref.OwnerPrimitiveRawSHA256 = hostVectorPtr(hostVectorSHA())
	ref.FirstOrdinal, ref.LastOrdinal, ref.OriginalCallCount = ordinal, ordinal, 1
	ref.ManifestRootSHA256 = hostVectorPtr(hostVectorSHA())
	return model.HostFactoryDiagnosticIOFact{Operation: operation, OriginalHandleID: hostVectorHandle, OwnerPrimitiveRawSHA256: hostVectorPtr(hostVectorSHA()), OriginalState: "returned", OriginalCalledAt: hostVectorPtr(called), OriginalReturnedAt: hostVectorPtr(called.Add(time.Nanosecond)), OriginalReturnClass: "success", OriginalCloseState: "not_acquired", OriginalCloseClass: "unavailable", SubjectOwnerID: hostVectorSubject, OriginalOperationDeadline: hostVectorTime().Add(60 * time.Second), OriginalHashState: "not_byte_operation", OriginalCallVector: ref, OriginalCloseCallVector: hostVectorReference("issuer_signing_key_close")}
}

func hostVectorRootDeclaredBytes() model.HostFactoryRootPreparation {
	tm := hostVectorTime()
	dir := model.HostFactoryBootstrapDescriptorSource{Role: "gate_directory", Device: 1, Inode: 1, Type: "directory", Mode: 0040700, LinkCount: 1, UID: 0, GID: 0, Flags: 0x30800, OriginalDescriptorNumber: 12, DescriptorFlags: 1, OriginalFstatReturnedAt: tm, OwnerPrimitiveRawSHA256: hostVectorSHA()}
	hostVectorDeclaredDescriptor(&dir)
	keySource := dir
	keySource.Role = "bootstrap_reader"
	keySource.Inode = 2
	keySource.Type = "regular"
	keySource.Mode = 0100600
	keySource.Flags = 0x20800
	keySource.OriginalDescriptorNumber = 13
	key := hostVectorIssuerFact("issuer_signing_key64_read", 1, tm.Add(time.Nanosecond))
	key.OriginalCount = hostVectorPtr(int64(64))
	key.OriginalHashState = "private_withheld"
	key.OriginalEOF = hostVectorPtr(false)
	eof := hostVectorIssuerFact("issuer_signing_key_eof_read", 2, tm.Add(3*time.Nanosecond))
	eof.OriginalCount = hostVectorPtr(int64(0))
	eof.OriginalHashState = "private_withheld"
	eof.OriginalEOF = hostVectorPtr(true)
	eof.OriginalReturnClass = "eof"
	close := hostVectorIssuerFact("issuer_signing_key_close", 3, tm.Add(5*time.Nanosecond))
	return model.HostFactoryRootPreparation{Schema: "original_host_factory_root_preparation_v4", Purpose: "original_host_factory_root_preparation_v4", FactoryRootID: hostVectorOwner, SourceApprovalSHA256: hostVectorSHA(), CoreBasalOwnerRawSHA256: hostVectorSHA(), FactoryRegistrySHA256: hostVectorSHA(), FactorySourceClosureSHA256: hostVectorSHA(), RootDirectorySource: dir, InitialControlLedgerSHA256: hostVectorSHA(), InitialControlLedgerBytes: 1, OriginalRootOperations: []model.HostFactoryDiagnosticIOFact{}, OriginalContextStartedAt: tm, OriginalContextDeadline: tm.Add(600 * time.Second), FactoryEntryClass: "sealed_a0", InitialProtectedAdmissionSHA256: hostVectorSHA(), OriginalIssuerSigningKeySource: keySource, OriginalIssuerSigningKeyReadReturns: [3]model.HostFactoryDiagnosticIOFact{key, eof, close}, IssuerApprovedPublicKeySHA256: hostVectorSHA(), OriginalHandleInventorySHAs: []string{hostVectorSHA()}}
}

func hostVectorUnavailableIssuer(f *model.HostFactoryDiagnosticIOFact, state string) {
	f.OriginalState = state
	f.OriginalCount = nil
	f.OriginalSHA256 = nil
	f.OriginalReturnedAt = nil
	f.OriginalEOF = nil
	f.OriginalReturnClass = "unavailable"
	f.OriginalHashState = "unknown_original_bytes"
	if state == "not_called" {
		f.OriginalCalledAt = nil
		f.OriginalCallVector = hostVectorReference(f.Operation)
	} else {
		f.OriginalCallVector.CollectionState = "same_original_call_pending"
	}
}

func TestHostOriginalFactoryIssuerPreparationBytes(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*model.HostFactoryRootPreparation)
		accepted bool
	}{
		{"declared_key64_eof_close_sequence_only", nil, true},
		{"not_called_is_diagnostic_not_preparation", func(x *model.HostFactoryRootPreparation) {
			for i := range x.OriginalIssuerSigningKeyReadReturns {
				hostVectorUnavailableIssuer(&x.OriginalIssuerSigningKeyReadReturns[i], "not_called")
			}
		}, false},
		{"pending_key_cannot_prepare", func(x *model.HostFactoryRootPreparation) {
			hostVectorUnavailableIssuer(&x.OriginalIssuerSigningKeyReadReturns[0], "called_pending")
		}, false},
		{"short_key_cannot_prepare", func(x *model.HostFactoryRootPreparation) {
			x.OriginalIssuerSigningKeyReadReturns[0].OriginalCount = hostVectorPtr(int64(63))
			x.OriginalIssuerSigningKeyReadReturns[0].OriginalReturnClass = "partial"
		}, false},
		{"private_key_hash_export", func(x *model.HostFactoryRootPreparation) {
			x.OriginalIssuerSigningKeyReadReturns[0].OriginalSHA256 = hostVectorPtr(hostVectorSHA())
		}, false},
		{"eof_probe_missing_actual_eof", func(x *model.HostFactoryRootPreparation) {
			x.OriginalIssuerSigningKeyReadReturns[1].OriginalEOF = hostVectorPtr(false)
			x.OriginalIssuerSigningKeyReadReturns[1].OriginalReturnClass = "success"
		}, false},
		{"eof_probe_extra_byte", func(x *model.HostFactoryRootPreparation) {
			x.OriginalIssuerSigningKeyReadReturns[1].OriginalCount = hostVectorPtr(int64(1))
		}, false},
		{"eof_private_digest_export", func(x *model.HostFactoryRootPreparation) {
			x.OriginalIssuerSigningKeyReadReturns[1].OriginalSHA256 = hostVectorPtr(HostFactoryRawSHA256(nil))
		}, false},
		{"missing_original_close", func(x *model.HostFactoryRootPreparation) {
			hostVectorUnavailableIssuer(&x.OriginalIssuerSigningKeyReadReturns[2], "not_called")
		}, false},
		{"close_nonbyte_cannot_report_zero_bytes", func(x *model.HostFactoryRootPreparation) {
			x.OriginalIssuerSigningKeyReadReturns[2].OriginalCount = hostVectorPtr(int64(0))
		}, false},
		{"late_close_retained_only_in_diagnostic", func(x *model.HostFactoryRootPreparation) {
			f := &x.OriginalIssuerSigningKeyReadReturns[2]
			f.OriginalReturnedAt = hostVectorPtr(f.OriginalOperationDeadline.Add(time.Nanosecond))
		}, false},
		{"foreign_key_handle", func(x *model.HostFactoryRootPreparation) {
			f := &x.OriginalIssuerSigningKeyReadReturns[1]
			f.OriginalHandleID = hostVectorSubject
			f.OriginalCallVector.OriginalHandleID = hostVectorSubject
			f.OriginalCloseCallVector.OriginalHandleID = hostVectorSubject
		}, false},
		{"foreign_key_owner", func(x *model.HostFactoryRootPreparation) {
			x.OriginalIssuerSigningKeyReadReturns[1].OriginalCallVector.OriginalOwnerID = hostVectorSubject
		}, false},
		{"foreign_key_subject", func(x *model.HostFactoryRootPreparation) {
			f := &x.OriginalIssuerSigningKeyReadReturns[1]
			f.SubjectOwnerID = hostVectorOwner
			f.OriginalCallVector.SubjectOwnerID = hostVectorOwner
		}, false},
		{"foreign_key_basal", func(x *model.HostFactoryRootPreparation) {
			f := &x.OriginalIssuerSigningKeyReadReturns[1]
			f.OwnerPrimitiveRawSHA256 = hostVectorPtr(strings.Repeat("b", 64))
			f.OriginalCallVector.OwnerPrimitiveRawSHA256 = f.OwnerPrimitiveRawSHA256
		}, false},
		{"vector_basal_disagrees_with_key_record", func(x *model.HostFactoryRootPreparation) {
			x.OriginalIssuerSigningKeyReadReturns[0].OriginalCallVector.OwnerPrimitiveRawSHA256 = hostVectorPtr(strings.Repeat("b", 64))
		}, false},
		{"source_descriptor_basal_mismatch", func(x *model.HostFactoryRootPreparation) {
			x.OriginalIssuerSigningKeySource.OwnerPrimitiveRawSHA256 = strings.Repeat("b", 64)
		}, false},
		{"reordered_source_returns", func(x *model.HostFactoryRootPreparation) {
			x.OriginalIssuerSigningKeyReadReturns[0], x.OriginalIssuerSigningKeyReadReturns[1] = x.OriginalIssuerSigningKeyReadReturns[1], x.OriginalIssuerSigningKeyReadReturns[0]
		}, false},
		{"overlapping_key_and_eof_calls", func(x *model.HostFactoryRootPreparation) {
			x.OriginalIssuerSigningKeyReadReturns[1].OriginalCalledAt = hostVectorPtr(hostVectorTime().Add(time.Nanosecond))
		}, false},
		{"same_close_cannot_be_copied_into_key_read", func(x *model.HostFactoryRootPreparation) {
			f := &x.OriginalIssuerSigningKeyReadReturns[0]
			f.OriginalCloseState = "returned"
			f.OriginalCloseClass = "success"
			f.OriginalCloseReturnedAt = x.OriginalIssuerSigningKeyReadReturns[2].OriginalReturnedAt
			f.OriginalCloseCallVector = x.OriginalIssuerSigningKeyReadReturns[2].OriginalCallVector
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := hostVectorRootDeclaredBytes()
			if c.mutate != nil {
				c.mutate(&x)
			}
			hostVectorBothCodecs(t, x, c.accepted)
		})
	}
	t.Run("same_not_called_values_remain_diagnostic", func(t *testing.T) {
		x := hostVectorRootDeclaredBytes()
		for _, f := range x.OriginalIssuerSigningKeyReadReturns {
			hostVectorUnavailableIssuer(&f, "not_called")
			hostVectorBothCodecs(t, f, true)
		}
	})
	t.Run("same_late_close_remains_diagnostic", func(t *testing.T) {
		f := hostVectorRootDeclaredBytes().OriginalIssuerSigningKeyReadReturns[2]
		f.OriginalReturnedAt = hostVectorPtr(f.OriginalOperationDeadline.Add(time.Nanosecond))
		hostVectorBothCodecs(t, f, true)
	})
}

func hostVectorSegment(operation string, expected int, ordinal uint64) model.HostFactoryBootstrapSegmentReturn {
	ref := hostVectorReference(operation)
	ref.OwnerPrimitiveRawSHA256 = hostVectorPtr(hostVectorSHA())
	ref.FirstOrdinal, ref.LastOrdinal, ref.OriginalCallCount = ordinal, ordinal, 1
	ref.ManifestRootSHA256 = hostVectorPtr(hostVectorSHA())
	state := "actual_public_bytes"
	sha := hostVectorPtr(hostVectorSHA())
	if expected == 64 {
		state = "private_withheld"
		sha = nil
	}
	return model.HostFactoryBootstrapSegmentReturn{Operation: operation, OwnerPrimitiveRawSHA256: hostVectorSHA(), OriginalHandleID: hostVectorHandle, ExpectedBytes: expected, OriginalCallVector: ref, OriginalTotalBytes: expected, OriginalSegmentHashState: state, OriginalSegmentSHA256: sha, OriginalReturnedAt: hostVectorTime().Add(time.Duration(ordinal) * time.Nanosecond)}
}

func TestHostOriginalFactoryBootstrapSegmentBytes(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*model.HostFactoryBootstrapSegmentReturn)
		accepted bool
	}{
		{"declared_complete_public_segment", nil, true},
		{"segment_vector_basal_mismatch", func(s *model.HostFactoryBootstrapSegmentReturn) {
			s.OriginalCallVector.OwnerPrimitiveRawSHA256 = hostVectorPtr(strings.Repeat("b", 64))
		}, false},
		{"segment_vector_missing_basal", func(s *model.HostFactoryBootstrapSegmentReturn) { s.OriginalCallVector.OwnerPrimitiveRawSHA256 = nil }, false},
		{"segment_vector_other_handle", func(s *model.HostFactoryBootstrapSegmentReturn) {
			s.OriginalCallVector.OriginalHandleID = hostVectorSubject
		}, false},
		{"segment_vector_other_operation", func(s *model.HostFactoryBootstrapSegmentReturn) {
			s.OriginalCallVector.Operation = "bootstrap_binding_digest32_read"
		}, false},
		{"segment_pending_vector", func(s *model.HostFactoryBootstrapSegmentReturn) {
			s.OriginalCallVector.CollectionState = "same_original_call_pending"
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := hostVectorSegment("bootstrap_challenge32_read", 32, 1)
			if c.mutate != nil {
				c.mutate(&s)
			}
			hostVectorBothCodecs(t, s, c.accepted)
		})
	}
	// The parent tests the three segments together without forging native FD or
	// syscall evidence. A valid local segment cannot substitute a foreign owner.
	segments := [3]model.HostFactoryBootstrapSegmentReturn{hostVectorSegment("bootstrap_challenge32_write", 32, 1), hostVectorSegment("bootstrap_key64_write", 64, 2), hostVectorSegment("bootstrap_binding_digest32_write", 32, 3)}
	source := model.HostFactoryBootstrapDescriptorSource{Role: "bootstrap_writer", Device: 1, Inode: 1, Type: "pipe", Mode: 0010600, LinkCount: 1, UID: 0, GID: 0, Flags: 0x801, OriginalDescriptorNumber: 11, DescriptorFlags: 1, OriginalFstatReturnedAt: hostVectorTime(), OwnerPrimitiveRawSHA256: hostVectorSHA()}
	hostVectorDeclaredDescriptor(&source)
	close := hostVectorIssuerFact("bootstrap_writer_close", 4, hostVectorTime().Add(4*time.Nanosecond))
	close.OriginalCallVector.Operation = "bootstrap_writer_close"
	close.OriginalCloseCallVector.Operation = "bootstrap_writer_close"
	makeParent := func() model.HostFactoryBootstrapWriteReturn {
		return model.HostFactoryBootstrapWriteReturn{Schema: "original_host_factory_bootstrap_write_return_v4", Purpose: "original_host_factory_bootstrap_write_return_v4", BindingSchema: hostVectorScopeSchema, BindingSHA256: hostVectorSHA(), RecipientOwnerID: hostVectorSubject, WriterPrimitiveRawSHA256: hostVectorSHA(), OriginalWriterSource: source, SegmentReturns: segments, OriginalWriterCloseReturn: close}
	}
	parents := []struct {
		name     string
		mutate   func(*model.HostFactoryBootstrapWriteReturn)
		accepted bool
	}{
		{"declared_parent_segment_owner_join", nil, true},
		{"parent_top_recipient_foreign", func(x *model.HostFactoryBootstrapWriteReturn) { x.RecipientOwnerID = hostVectorOwner }, false},
		{"parent_all_vectors_foreign_recipient", func(x *model.HostFactoryBootstrapWriteReturn) {
			for i := range x.SegmentReturns {
				x.SegmentReturns[i].OriginalCallVector.SubjectOwnerID = hostVectorOwner
			}
			x.OriginalWriterCloseReturn.SubjectOwnerID = hostVectorOwner
			x.OriginalWriterCloseReturn.OriginalCallVector.SubjectOwnerID = hostVectorOwner
		}, false},
		{"parent_and_segment_basal_mismatch", func(x *model.HostFactoryBootstrapWriteReturn) { x.WriterPrimitiveRawSHA256 = strings.Repeat("b", 64) }, false},
		{"segment_other_owner_same_basal", func(x *model.HostFactoryBootstrapWriteReturn) {
			x.SegmentReturns[1].OriginalCallVector.OriginalOwnerID = hostVectorSubject
		}, false},
		{"segment_other_subject_same_owner", func(x *model.HostFactoryBootstrapWriteReturn) {
			x.SegmentReturns[1].OriginalCallVector.SubjectOwnerID = hostVectorOwner
		}, false},
		{"segment_reused_ordinal", func(x *model.HostFactoryBootstrapWriteReturn) {
			x.SegmentReturns[1].OriginalCallVector.FirstOrdinal = 1
			x.SegmentReturns[1].OriginalCallVector.LastOrdinal = 1
		}, false},
		{"parent_close_other_owner", func(x *model.HostFactoryBootstrapWriteReturn) {
			x.OriginalWriterCloseReturn.OriginalCallVector.OriginalOwnerID = hostVectorSubject
		}, false},
		{"parent_close_other_subject", func(x *model.HostFactoryBootstrapWriteReturn) {
			x.OriginalWriterCloseReturn.SubjectOwnerID = hostVectorOwner
			x.OriginalWriterCloseReturn.OriginalCallVector.SubjectOwnerID = hostVectorOwner
		}, false},
	}
	for _, c := range parents {
		t.Run(c.name, func(t *testing.T) {
			x := makeParent()
			if c.mutate != nil {
				c.mutate(&x)
			}
			hostVectorBothCodecs(t, x, c.accepted)
		})
	}
}

func hostVectorFailureDeclaredBytes() model.HostFactoryFailureDiagnostic {
	return model.HostFactoryFailureDiagnostic{Schema: "original_host_factory_failure_diagnostic_v4", Purpose: "original_host_factory_failure_diagnostic_v4", BindingSchema: hostVectorScopeSchema, BindingSHA256: hostVectorSHA(), OriginalStage: "cleanup", OriginalContextStartedAt: hostVectorTime(), OriginalContextDeadline: hostVectorTime().Add(600 * time.Second), OriginalOperationDeadline: hostVectorTime().Add(60 * time.Second), FailureCode: "storage_unknown", OriginalRecordState: "not_acquired", Operations: []model.HostFactoryCallVectorReference{}, RecordedAt: hostVectorTime().Add(time.Second), FailureCollectionID: hostVectorHandle, PartOrdinal: 1, FinalPart: true, RetentionState: "complete_original_calls"}
}

func TestHostOriginalFactoryFailureStageRetentionBytes(t *testing.T) {
	// Literal expected vocabulary is independent of the production slice.
	stages := []string{"native_alive", "initial_empty", "poststart_empty", "terminal_read", "prepared_create", "root_bootstrap", "registrar_bootstrap", "worker_bootstrap", "ordinary_early_bootstrap", "ordinary_late_grant", "ordinary_early_credential", "root_prepare", "choice_write", "ordinary_before_start", "worker_exterior_join", "registrar_exterior_join", "ordinary_redeem", "worker_start", "registrar_start", "cleanup", "root_completion", "ordinary_bootstrap", "choice_control", "before_original_issue", "issuer_signer_bootstrap"}
	for _, stage := range stages {
		t.Run("declared_stage_"+stage, func(t *testing.T) {
			f := hostVectorFailureDeclaredBytes()
			f.OriginalStage = stage
			hostVectorBothCodecs(t, f, true)
		})
	}
	cases := []struct {
		name     string
		mutate   func(*model.HostFactoryFailureDiagnostic)
		accepted bool
	}{
		{"unknown_future_stage", func(f *model.HostFactoryFailureDiagnostic) { f.OriginalStage = "future_stage" }, false},
		{"unknown_historical_stage", func(f *model.HostFactoryFailureDiagnostic) { f.OriginalStage = "root_bootstrap_v2" }, false},
		{"duplicate_same_logical_handle_reference", func(f *model.HostFactoryFailureDiagnostic) {
			r := hostVectorReference("stdout_read")
			f.Operations = []model.HostFactoryCallVectorReference{r, r}
			f.OriginalVectorReferenceCount = 2
		}, false},
		{"complete_part_cannot_include_incomplete_reference", func(f *model.HostFactoryFailureDiagnostic) {
			r := hostVectorReference("stdout_read")
			r.OwnerPrimitiveRawSHA256 = hostVectorPtr(hostVectorSHA())
			r.FirstOrdinal, r.LastOrdinal, r.OriginalCallCount = 1, 1, 1
			r.CollectionState = "incomplete_retention"
			f.Operations = []model.HostFactoryCallVectorReference{r}
			f.OriginalVectorReferenceCount = 1
		}, false},
		{"complete_part_cannot_include_pending_reference", func(f *model.HostFactoryFailureDiagnostic) {
			r := hostVectorReference("stdout_read")
			r.OwnerPrimitiveRawSHA256 = hostVectorPtr(hostVectorSHA())
			r.FirstOrdinal, r.LastOrdinal, r.OriginalCallCount = 1, 1, 1
			r.ManifestRootSHA256 = hostVectorPtr(hostVectorSHA())
			r.CollectionState = "same_original_call_pending"
			f.Operations = []model.HostFactoryCallVectorReference{r}
			f.OriginalVectorReferenceCount = 1
		}, false},
		{"truthful_zero_vector_failure", nil, true},
		{"truthful_incomplete_reference_retained", func(f *model.HostFactoryFailureDiagnostic) {
			r := hostVectorReference("stdout_read")
			r.OwnerPrimitiveRawSHA256 = hostVectorPtr(hostVectorSHA())
			r.FirstOrdinal, r.LastOrdinal, r.OriginalCallCount = 1, 1, 1
			r.CollectionState = "incomplete_retention"
			f.Operations = []model.HostFactoryCallVectorReference{r}
			f.OriginalVectorReferenceCount = 1
			f.RetentionState = "incomplete_retention"
		}, true},
		{"truthful_actual_empty_partial_raw", func(f *model.HostFactoryFailureDiagnostic) {
			f.OriginalRecordState = "original_bytes_read"
			f.OriginalRawBytes = hostVectorPtr(0)
			f.OriginalRecordSHA256 = hostVectorPtr(HostFactoryRawSHA256(nil))
			f.RetentionState = "incomplete_retention"
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := hostVectorFailureDeclaredBytes()
			if c.mutate != nil {
				c.mutate(&f)
			}
			hostVectorBothCodecs(t, f, c.accepted)
		})
	}
}

func hostVectorSelectNested(t *testing.T, g *hostVectorGraph) {
	t.Helper()
	prefix := g.root
	prefix.LastOrdinal = 15
	prefix.OriginalCallCount = 15
	prefix.ChildBodySHAs = []string{g.root.ChildBodySHAs[0]}
	successor := g.root
	successor.FirstOrdinal = 16
	successor.OriginalCallCount = 1
	successor.ChildBodySHAs = []string{g.root.ChildBodySHAs[1]}
	g.root.Level = 1
	g.root.ChildBodySHAs = []string{g.store(t, prefix), g.store(t, successor)}
	g.selectRoot(t)
}

func hostVectorReplaceSuccessorTimes(t *testing.T, g *hostVectorGraph, called, returned time.Time) {
	t.Helper()
	old := g.root.ChildBodySHAs[1]
	pending := hostVectorChunk(hostVectorPrimitive("stdout_read", 16, "called_pending"))
	pending.OriginalCalls[0].OriginalCalledAt = &called
	pending.RecordedAt = called
	current := hostVectorChunk(hostVectorPrimitive("stdout_read", 16, "returned"))
	current.OriginalCalls[0].OriginalCalledAt = &called
	current.OriginalCalls[0].OriginalReturnedAt = &returned
	current.RecordedAt = returned.Add(time.Nanosecond)
	sha := g.store(t, current)
	g.links[sha+":0"] = hostVectorPredecessor{hostVectorJSON(t, pending), 0}
	g.root.ChildBodySHAs[1] = sha
	delete(g.links, old+":0")
	g.selectRoot(t)
}

func TestHostOriginalFactoryCallVectorBoundaryChronology(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*testing.T, *hostVectorGraph)
		accepted bool
	}{
		{"original_prefix_successor_sequential", nil, true},
		{"two_successor_singletons_overlap", func(t *testing.T, g *hostVectorGraph) {
			children := []string{}
			for ordinal := uint64(1); ordinal <= 2; ordinal++ {
				p := hostVectorChunk(hostVectorPrimitive("stdout_read", ordinal, "called_pending"))
				c := hostVectorChunk(hostVectorPrimitive("stdout_read", ordinal, "returned"))
				if ordinal == 2 {
					called := hostVectorTime().Add(time.Nanosecond)
					p.OriginalCalls[0].OriginalCalledAt = &called
					p.RecordedAt = called
					c.OriginalCalls[0].OriginalCalledAt = &called
				}
				sha := g.store(t, c)
				g.links[sha+":0"] = hostVectorPredecessor{hostVectorJSON(t, p), 0}
				children = append(children, sha)
			}
			g.root.FirstOrdinal, g.root.LastOrdinal, g.root.OriginalCallCount = 1, 2, 2
			g.root.ChildBodySHAs = children
			g.reference.FirstOrdinal, g.reference.LastOrdinal, g.reference.OriginalCallCount = 1, 2, 2
			g.selectRoot(t)
		}, false},
		{"overlap_across_terminal_and_successor", func(t *testing.T, g *hostVectorGraph) {
			hostVectorReplaceSuccessorTimes(t, g, hostVectorTime().Add(14*time.Nanosecond), hostVectorTime().Add(17*time.Nanosecond))
		}, false},
		{"overlap_across_nested_manifests", func(t *testing.T, g *hostVectorGraph) {
			hostVectorReplaceSuccessorTimes(t, g, hostVectorTime().Add(14*time.Nanosecond), hostVectorTime().Add(17*time.Nanosecond))
			hostVectorSelectNested(t, g)
		}, false},
		{"nested_original_sequential", func(t *testing.T, g *hostVectorGraph) { hostVectorSelectNested(t, g) }, true},
		{"late_but_ordered_retention_does_not_extend_deadline", func(t *testing.T, g *hostVectorGraph) {
			hostVectorReplaceSuccessorTimes(t, g, hostVectorTime().Add(61*time.Second), hostVectorTime().Add(61*time.Second+time.Nanosecond))
			hostVectorSelectNested(t, g)
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := hostVectorNewGraph(t)
			if c.mutate != nil {
				c.mutate(t, &g)
			}
			err := ValidateHostFactoryCallVector(g.reference, g.resolve, g.predecessor)
			if c.accepted {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				hostVectorRefused(t, err)
			}
		})
	}
	t.Run("same_overlap_inside_one_chunk_refused", func(t *testing.T) {
		first := hostVectorPrimitive("stdout_read", 1, "returned")
		first.OriginalReturnedAt = hostVectorPtr(hostVectorTime().Add(10 * time.Nanosecond))
		second := hostVectorPrimitive("stdout_read", 2, "returned")
		second.OriginalCalledAt = hostVectorPtr(hostVectorTime().Add(7 * time.Nanosecond))
		second.OriginalReturnedAt = hostVectorPtr(hostVectorTime().Add(11 * time.Nanosecond))
		hostVectorBothCodecs(t, hostVectorChunk(first, second), false)
	})
}

func TestHostOriginalFactoryCallVectorCallbackBodyCaps(t *testing.T) {
	// The cap is a fixed65536 BODY bound; these Source-only cases are not an
	// oversized benchmark. The source short circuits length before SHA/decode.
	for _, c := range []struct {
		name string
		body []byte
	}{{"root_empty_body", []byte{}}, {"root_cap_plus_one", bytes.Repeat([]byte("x"), 65537)}} {
		t.Run(c.name, func(t *testing.T) {
			g := hostVectorNewGraph(t)
			original := g.resolve
			reads := 0
			resolver := func(sha string) ([]byte, error) {
				if sha == *g.reference.ManifestRootSHA256 {
					reads++
					return c.body, nil
				}
				return original(sha)
			}
			hostVectorRefused(t, ValidateHostFactoryCallVector(g.reference, resolver, g.predecessor))
			if reads != 1 {
				t.Fatal("root was reread or repaired")
			}
		})
	}
	for _, c := range []struct {
		name string
		body []byte
	}{{"predecessor_empty_non_nil_body", []byte{}}, {"predecessor_cap_plus_one", bytes.Repeat([]byte("x"), 65537)}} {
		t.Run(c.name, func(t *testing.T) {
			g := hostVectorNewGraph(t)
			original := g.predecessor
			sha := g.root.ChildBodySHAs[1]
			reads := 0
			prior := func(current string, index uint32) ([]byte, uint32, error) {
				if current == sha {
					reads++
					return c.body, 0, nil
				}
				return original(current, index)
			}
			hostVectorRefused(t, ValidateHostFactoryCallVector(g.reference, g.resolve, prior))
			if reads != 1 {
				t.Fatal("predecessor was reread or repaired")
			}
		})
	}
	t.Run("bounded_first_and_successor_still_join", func(t *testing.T) {
		g := hostVectorNewGraph(t)
		if err := ValidateHostFactoryCallVector(g.reference, g.resolve, g.predecessor); err != nil {
			t.Fatal(err)
		}
	})
}

// New fixtures are synthetic declared source bytes ONLY; they are neither a
// kernel return nor an approval, and never construct a native realm.
func hostVectorDeclaredDescriptor(d *model.HostFactoryBootstrapDescriptorSource) {
	d.OriginalHandleID = hostVectorHandle
	refs := []*model.HostFactoryCallVectorReference{&d.OriginalFstatCallVector, &d.OriginalGetflCallVector, &d.OriginalGetfdCallVector}
	for i, r := range refs {
		*r = hostVectorReference([]string{"descriptor_fstat", "fcntl_getfl", "fcntl_getfd"}[i])
		r.OwnerPrimitiveRawSHA256 = hostVectorPtr(d.OwnerPrimitiveRawSHA256)
		r.FirstOrdinal = uint64(i + 1)
		r.LastOrdinal = uint64(i + 1)
		r.OriginalCallCount = 1
		r.CollectionState = "complete_original_calls"
		r.ManifestRootSHA256 = hostVectorPtr(hostVectorSHA())
	}
	d.OriginalFstatCallID = hostVectorHandle + ":1"
	d.OriginalGetflCallID = hostVectorHandle + ":2"
	d.OriginalGetfdCallID = hostVectorHandle + ":3"
	acquired := hostVectorDeclaredRef("bootstrap_pipe_create", hostVectorHandle, 1, 1, 1)
	d.OriginalAcquisitionCallVector = &acquired
}
func hostVectorDeclaredRef(op, handle string, first, last, count uint64) model.HostFactoryCallVectorReference {
	r := hostVectorReference(op)
	r.OriginalHandleID = handle
	r.OwnerPrimitiveRawSHA256 = hostVectorPtr(hostVectorSHA())
	r.ManifestRootSHA256 = hostVectorPtr(hostVectorSHA())
	r.FirstOrdinal = first
	r.LastOrdinal = last
	r.OriginalCallCount = count
	r.CollectionState = "complete_original_calls"
	return r
}
func hostVectorDeclaredNativeExtras(n *model.HostFactoryNativeProcess) {
	exe := n.NativeReadOperations[2]
	exe.OriginalCallVector = hostVectorDeclaredRef("executable_read", exe.OriginalHandleID, 3, 3, 1)
	exe.OriginalCloseCallVector = hostVectorDeclaredRef("native_reader_close", exe.OriginalHandleID, 5, 5, 1)
	n.NativeReadOperations[2] = exe
	st := model.HostFactoryNativeStatReturn{Device: 1, Inode: 1, Mode: 0100755, LinkCount: 1, UID: 0, GID: 0, Size: exe.OriginalCount}
	n.OriginalHeldExecutableRead = model.HostFactoryHeldExecutableRead{OriginalHandleID: exe.OriginalHandleID, OwnerPrimitiveRawSHA256: hostVectorSHA(), SubjectOwnerID: hostVectorSubject, OriginalDescriptorNumber: 11, OriginalBeforeStat: st, OriginalAfterStat: st, OriginalOpenCallVector: hostVectorDeclaredRef("native_reader_open", exe.OriginalHandleID, 1, 1, 1), OriginalFstatCallVector: hostVectorDeclaredRef("native_reader_fstat", exe.OriginalHandleID, 2, 4, 2), OriginalBeforeFstatCallID: exe.OriginalHandleID + ":2", OriginalAfterFstatCallID: exe.OriginalHandleID + ":4", OriginalRead: exe, OriginalHandleInventorySHA256: hostVectorSHA()}
	handle := "77777777-7777-4777-8777-777777777777"
	n.OriginalProcessOwnerRead = model.HostFactoryProcessOwnerRead{SubjectOwnerID: hostVectorSubject, SubjectBootID: n.HostBootID, SubjectPID: n.PID, SubjectStartTicks: n.StartTicks, OriginalHandleID: handle, OwnerPrimitiveRawSHA256: hostVectorSHA(), OriginalDescriptorNumber: 12, OriginalStat: model.HostFactoryNativeStatReturn{Device: 1, Inode: 2, Mode: 0040700, LinkCount: 1, UID: n.UID, GID: n.GID, Size: 0}, OriginalOpenCallVector: hostVectorDeclaredRef("proc_owner_directory_open", handle, 1, 1, 1), OriginalFstatCallVector: hostVectorDeclaredRef("proc_owner_directory_fstat", handle, 2, 2, 1), OriginalCloseCallVector: hostVectorDeclaredRef("proc_owner_directory_close", handle, 3, 3, 1), OriginalHandleInventorySHA256: hostVectorSHA(), OriginalCalledAt: hostVectorTime(), OriginalReturnedAt: hostVectorTime(), OriginalCloseReturnedAt: hostVectorTime()}
	pinHandle := "88888888-8888-4888-8888-888888888888"
	open := hostVectorDeclaredRef("native_subject_pidfd_open", pinHandle, 1, 1, 1)
	n.OriginalSubjectNativePin = model.HostFactoryNativeSubjectPin{OriginalHandleID: pinHandle, ObserverOwnerID: hostVectorOwner, ObserverPrimitiveRawSHA256: hostVectorSHA(), SubjectOwnerID: hostVectorSubject, SubjectBootID: n.HostBootID, SubjectPID: n.PID, SubjectStartTicks: n.StartTicks, OriginalDescriptorNumber: 13, OriginalStat: model.HostFactoryNativeStatReturn{Device: 1, Inode: 3, Mode: 0600, LinkCount: 1, UID: 0, GID: 0, Size: 0}, OriginalOpenCallVector: &open, OriginalFstatCallVector: hostVectorDeclaredRef("native_subject_pidfd_fstat", pinHandle, 2, 2, 1), OriginalAlivePollCallVector: hostVectorDeclaredRef("native_subject_alive_poll", pinHandle, 3, 4, 2), OriginalBeforePollCallID: pinHandle + ":3", OriginalAfterPollCallID: pinHandle + ":4", OriginalHandleInventorySHA256: hostVectorSHA(), OriginalObservedAt: n.OriginalNativeCloseReturnedAt}
	n.NativeHandleInventorySHAs = []string{hostVectorSHA()}
}

// Synthetic request/return shapes only. These values do not stand for an
// executed syscall, original process, reviewed source key or native approval.
func hostVectorNativeCall(kind string) model.HostFactoryNativeCallReturn {
	n := model.HostFactoryNativeCallReturn{Kind: kind, OriginalErrorPresent: hostVectorPtr(false), OriginalErrno: hostVectorPtr(uint32(0))}
	switch kind {
	case "unix_open", "unix_openat":
		n.RequestedFlags, n.RequestedMode = hostVectorPtr(uint32(0x20800)), hostVectorPtr(uint32(0))
		if kind == "unix_openat" {
			n.InputDescriptorNumber, n.ParentHandleID = hostVectorPtr(10), hostVectorPtr(hostVectorOwner)
		}
		n.OriginalScalar = hostVectorPtr(int64(11))
		n.ReturnedDescriptors = []model.HostFactoryNativeAcquiredDescriptor{{OriginalHandleID: hostVectorHandle, OriginalDescriptorNumber: 11}}
	case "unix_mkdirat":
		n.InputDescriptorNumber, n.ParentHandleID, n.RequestedMode = hostVectorPtr(10), hostVectorPtr(hostVectorOwner), hostVectorPtr(uint32(0700))
	case "unix_fstat":
		n.InputDescriptorNumber = hostVectorPtr(11)
		n.OriginalStat = &model.HostFactoryNativeStatReturn{Device: 1, Inode: 1, LinkCount: 1, Mode: 0100600, Size: 0}
	case "fcntl_getfl", "fcntl_getfd", "fcntl_setfl", "fcntl_dupfd_cloexec":
		n.InputDescriptorNumber, n.RequestedArgument = hostVectorPtr(11), hostVectorPtr(int64(0))
		n.RequestedFcntlCommand = hostVectorPtr(map[string]int{"fcntl_getfl": 3, "fcntl_getfd": 1, "fcntl_setfl": 4, "fcntl_dupfd_cloexec": 1030}[kind])
		n.OriginalScalar = hostVectorPtr(int64(0))
		if kind == "fcntl_getfd" {
			n.OriginalScalar = hostVectorPtr(int64(1))
		}
		if kind == "fcntl_setfl" {
			n.RequestedArgument = hostVectorPtr(int64(0x800))
		}
		if kind == "fcntl_dupfd_cloexec" {
			n.ParentHandleID, n.OriginalScalar = hostVectorPtr(hostVectorOwner), hostVectorPtr(int64(12))
			n.ReturnedDescriptors = []model.HostFactoryNativeAcquiredDescriptor{{OriginalHandleID: hostVectorHandle, OriginalDescriptorNumber: 12}}
		}
	case "unix_getdents64":
		n.InputDescriptorNumber, n.RequestedArgument, n.OriginalScalar = hostVectorPtr(11), hostVectorPtr(int64(4096)), hostVectorPtr(int64(0))
	case "unix_pidfd_open":
		n.RequestedPID, n.RequestedFlags, n.OriginalScalar = hostVectorPtr(17), hostVectorPtr(uint32(0)), hostVectorPtr(int64(11))
		n.ReturnedDescriptors = []model.HostFactoryNativeAcquiredDescriptor{{OriginalHandleID: hostVectorHandle, OriginalDescriptorNumber: 11}}
	case "unix_poll":
		n.InputDescriptorNumber, n.RequestedFlags, n.RequestedArgument = hostVectorPtr(11), hostVectorPtr(uint32(1)), hostVectorPtr(int64(0))
		n.OriginalScalar, n.OriginalPollRevents = hostVectorPtr(int64(0)), hostVectorPtr(uint32(0))
	case "unix_pidfd_send_signal":
		n.InputDescriptorNumber, n.RequestedFlags, n.RequestedArgument = hostVectorPtr(11), hostVectorPtr(uint32(0)), hostVectorPtr(int64(9))
	case "unix_close", "original_file_close", "original_file_sync":
		n.InputDescriptorNumber = hostVectorPtr(11)
	case "original_os_pipe":
		n.ReturnedDescriptors = []model.HostFactoryNativeAcquiredDescriptor{{OriginalHandleID: hostVectorHandle, OriginalDescriptorNumber: 11}, {OriginalHandleID: hostVectorSubject, OriginalDescriptorNumber: 12}}
	case "original_cmd_start":
		n.ReturnedPID = hostVectorPtr(17)
	case "original_cmd_wait":
		n.OriginalExitCode = hostVectorPtr(0)
	}
	return n
}

func TestHostOriginalFactoryNativeReturnSlots(t *testing.T) {
	// Literal reviewed kinds rather than an iteration over the validator enum.
	kinds := []string{"unix_open", "unix_openat", "unix_mkdirat", "unix_fstat", "fcntl_getfl", "fcntl_getfd", "fcntl_setfl", "fcntl_dupfd_cloexec", "unix_getdents64", "unix_pidfd_open", "unix_poll", "unix_pidfd_send_signal", "unix_close", "original_file_close", "original_file_sync", "original_os_pipe", "original_cmd_start", "original_cmd_wait"}
	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			n := hostVectorNativeCall(kind)
			hostVectorBothCodecs(t, n, true)
			hostFactoryClearNativeOutputs(&n)
			hostVectorBothCodecs(t, n, true) // known requests, no returned outputs
			n.OriginalErrno = hostVectorPtr(uint32(0))
			hostVectorBothCodecs(t, n, false) // pending cannot acquire an output
		})
	}
	mutations := []struct {
		name, kind string
		change     func(*model.HostFactoryNativeCallReturn)
		accepted   bool
	}{
		{"fstat_does_not_expose_status_zero", "unix_fstat", func(n *model.HostFactoryNativeCallReturn) { n.OriginalScalar = hostVectorPtr(int64(0)) }, false},
		{"fstat_error_cannot_supply_stat", "unix_fstat", func(n *model.HostFactoryNativeCallReturn) {
			n.OriginalErrorPresent = hostVectorPtr(true)
			n.OriginalErrno = hostVectorPtr(uint32(5))
		}, false},
		{"fstat_error_unknown_stat_retained", "unix_fstat", func(n *model.HostFactoryNativeCallReturn) {
			n.OriginalErrorPresent = hostVectorPtr(true)
			n.OriginalErrno = hostVectorPtr(uint32(5))
			n.OriginalStat = nil
		}, true},
		{"open_error_negative_scalar_retained", "unix_open", func(n *model.HostFactoryNativeCallReturn) {
			n.OriginalErrorPresent = hostVectorPtr(true)
			n.OriginalErrno = hostVectorPtr(uint32(13))
			n.OriginalScalar = hostVectorPtr(int64(-1))
			n.ReturnedDescriptors = nil
		}, true},
		{"open_scalar_descriptor_mismatch", "unix_open", func(n *model.HostFactoryNativeCallReturn) { n.OriginalScalar = hostVectorPtr(int64(12)) }, false},
		{"openat_parent_cannot_be_returned_handle", "unix_openat", func(n *model.HostFactoryNativeCallReturn) { n.ParentHandleID = hostVectorPtr(hostVectorHandle) }, false},
		{"pipe_endpoint_not_duplicated", "original_os_pipe", func(n *model.HostFactoryNativeCallReturn) { n.ReturnedDescriptors[1] = n.ReturnedDescriptors[0] }, false},
		{"getter_command_not_alias", "fcntl_getfl", func(n *model.HostFactoryNativeCallReturn) { n.RequestedFcntlCommand = hostVectorPtr(1) }, false},
		{"getfd_unknown_bits_refused", "fcntl_getfd", func(n *model.HostFactoryNativeCallReturn) { n.OriginalScalar = hostVectorPtr(int64(2)) }, false},
		{"poll_return_mask_not_requested_mask", "unix_poll", func(n *model.HostFactoryNativeCallReturn) {
			n.OriginalScalar = hostVectorPtr(int64(1))
			n.OriginalPollRevents = hostVectorPtr(uint32(17))
		}, true},
		{"poll_missing_observed_mask", "unix_poll", func(n *model.HostFactoryNativeCallReturn) { n.OriginalPollRevents = nil }, false},
		{"wait_signal_exit_retained", "original_cmd_wait", func(n *model.HostFactoryNativeCallReturn) {
			n.OriginalErrorPresent = hostVectorPtr(true)
			n.OriginalErrno = nil
			n.OriginalExitCode = hostVectorPtr(-1)
		}, true},
		{"close_no_synthetic_scalar", "original_file_close", func(n *model.HostFactoryNativeCallReturn) { n.OriginalScalar = hostVectorPtr(int64(0)) }, false},
		{"mkdirat_no_synthetic_scalar", "unix_mkdirat", func(n *model.HostFactoryNativeCallReturn) { n.OriginalScalar = hostVectorPtr(int64(0)) }, false},
		{"mkdirat_wrong_mode", "unix_mkdirat", func(n *model.HostFactoryNativeCallReturn) { n.RequestedMode = hostVectorPtr(uint32(0755)) }, false},
		{"start_pid_missing", "original_cmd_start", func(n *model.HostFactoryNativeCallReturn) { n.ReturnedPID = nil }, false},
	}
	for _, c := range mutations {
		t.Run(c.name, func(t *testing.T) {
			n := hostVectorNativeCall(c.kind)
			c.change(&n)
			hostVectorBothCodecs(t, n, c.accepted)
		})
	}
	for _, name := range []string{"omitted_nullable_output_key", "case_folded_output_key", "duplicate_output_key", "unknown_future_scalar", "noncanonical_null_array"} {
		t.Run(name, func(t *testing.T) {
			raw := hostVectorJSON(t, hostVectorNativeCall("unix_fstat"))
			switch name {
			case "omitted_nullable_output_key":
				raw = bytes.Replace(raw, []byte(`,"returned_descriptors":null`), nil, 1)
			case "case_folded_output_key":
				raw = bytes.Replace(raw, []byte(`"original_scalar"`), []byte(`"Original_Scalar"`), 1)
			case "duplicate_output_key":
				raw = bytes.Replace(raw, []byte(`"original_scalar":null`), []byte(`"original_scalar":null,"original_scalar":null`), 1)
			case "unknown_future_scalar":
				raw = bytes.Replace(raw, []byte(`"original_scalar":null`), []byte(`"original_scalar":null,"raw_status":0`), 1)
			case "noncanonical_null_array":
				raw = bytes.Replace(raw, []byte(`"returned_descriptors":null`), []byte(`"returned_descriptors":[]`), 1)
			}
			var out model.HostFactoryNativeCallReturn
			hostVectorRefused(t, DecodeHostFactory(raw, &out))
		})
	}
}

func TestHostOriginalFactoryNativePendingRequests(t *testing.T) {
	for _, name := range []string{"same_request", "changed_input_fd", "changed_parent_handle", "changed_flags", "changed_mode", "new_request_object"} {
		t.Run(name, func(t *testing.T) {
			ret := hostVectorPrimitive("initial_ledger_open_exclusive", 1, "returned")
			ret.OriginalCount, ret.OriginalSHA256, ret.OriginalEOF = nil, nil, nil
			ret.OriginalHashState = "not_byte_operation"
			n := hostVectorNativeCall("unix_openat")
			n.RequestedMode = hostVectorPtr(uint32(0600))
			n.RequestedFlags = hostVectorPtr(uint32(1 | 64 | 128 | 2048 | 131072 | 524288))
			ret.OriginalNativeReturn = &n
			pending := ret
			old := n
			hostFactoryClearNativeOutputs(&old)
			pending.OriginalNativeReturn = &old
			pending.OriginalState = "called_pending"
			pending.OriginalReturnedAt = nil
			pending.OriginalReturnClass = "unavailable"
			pending.OriginalHashState = "unknown_original_bytes"
			switch name {
			case "changed_input_fd":
				n.InputDescriptorNumber = hostVectorPtr(9)
			case "changed_parent_handle":
				n.ParentHandleID = hostVectorPtr(hostVectorSubject)
			case "changed_flags":
				n.RequestedFlags = hostVectorPtr(uint32(0))
			case "changed_mode":
				n.RequestedMode = hostVectorPtr(uint32(0))
			case "new_request_object":
				pending.OriginalNativeReturn = nil
			}
			p, c := hostVectorChunk(pending), hostVectorChunk(ret)
			err := ValidateHostFactoryPendingSuccessor(p, c)
			if name == "same_request" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				hostVectorRefused(t, err)
			}
		})
	}
}

func hostVectorDirent(name string, ino uint64, kind byte) []byte {
	length := (19 + len(name) + 1 + 7) &^ 7
	raw := make([]byte, length)
	binary.LittleEndian.PutUint64(raw[:8], ino)
	binary.LittleEndian.PutUint16(raw[16:18], uint16(length))
	raw[18] = kind
	copy(raw[19:], name)
	return raw
}

func TestHostOriginalFactoryRawTaskDirents(t *testing.T) {
	cases := []struct {
		name     string
		buffers  [][]byte
		want     []int
		accepted bool
	}{
		{"actual_buffer_order_sorted_projection", [][]byte{append(hostVectorDirent("17", 1, 4), hostVectorDirent("3", 2, 0)...)}, []int{3, 17}, true},
		{"dot_records_not_name_hash", [][]byte{append(hostVectorDirent(".", 0, 0), hostVectorDirent("..", 0, 0)...)}, []int{}, true},
		{"empty_projection_not_native_absence", [][]byte{}, []int{}, true},
		{"unknown_original_buffers", nil, nil, false},
		{"missing_call_bytes", [][]byte{{}}, nil, false},
		{"leading_zero_tid", [][]byte{hostVectorDirent("017", 1, 4)}, nil, false},
		{"noncanonical_plus_tid", [][]byte{hostVectorDirent("+17", 1, 4)}, nil, false},
		{"duplicate_tid", [][]byte{hostVectorDirent("17", 1, 4), hostVectorDirent("17", 2, 4)}, nil, false},
		{"numeric_zero_inode", [][]byte{hostVectorDirent("17", 0, 4)}, nil, false},
		{"numeric_regular_type", [][]byte{hostVectorDirent("17", 1, 8)}, nil, false},
		{"unsupported_name", [][]byte{hostVectorDirent("child", 1, 4)}, nil, false},
		{"embedded_slash", [][]byte{hostVectorDirent("17/3", 1, 4)}, nil, false},
		{"pid_overflow", [][]byte{hostVectorDirent("2147483648", 1, 4)}, nil, false},
		{"record_cannot_cross_calls", [][]byte{hostVectorDirent("17", 1, 4)[:20], hostVectorDirent("17", 1, 4)[20:]}, nil, false},
		{"unaligned_reclen", [][]byte{{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 0, 4, '1', 0, 0, 0, 0}}, nil, false},
		{"whole_buffer_cap", [][]byte{make([]byte, 65537)}, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := DecodeHostFactoryTaskDirents(c.buffers)
			if c.accepted {
				if err != nil || !reflect.DeepEqual(got, c.want) {
					t.Fatalf("want %v, got %v error=%v", c.want, got, err)
				}
			} else {
				hostVectorRefused(t, err)
			}
		})
	}
}

func hostVectorInterleavedInventory(t *testing.T) (model.HostFactoryHandleCallInventory, hostVectorGraph) {
	t.Helper()
	g := hostVectorGraph{bodies: map[string][]byte{}, links: map[string]hostVectorPredecessor{}}
	children := map[string][]string{}
	for ordinal := uint64(1); ordinal <= 3; ordinal++ {
		op := "fcntl_getfl"
		if ordinal == 2 {
			op = "fcntl_getfd"
		}
		p := hostVectorPrimitive(op, ordinal, "returned")
		p.OriginalCount, p.OriginalSHA256, p.OriginalEOF = nil, nil, nil
		p.OriginalHashState = "not_byte_operation"
		n := hostVectorNativeCall(op)
		p.OriginalNativeReturn = &n
		sha := g.store(t, hostVectorChunk(p))
		g.first(sha, 1)
		children[op] = append(children[op], sha)
	}
	refs := []model.HostFactoryCallVectorReference{}
	for _, op := range []string{"fcntl_getfl", "fcntl_getfd"} {
		first, last, count := uint64(1), uint64(3), uint64(2)
		if op == "fcntl_getfd" {
			first, last, count = 2, 2, 1
		}
		m := model.HostFactoryCallVectorManifest{Schema: "original_host_factory_call_vector_manifest_v2", Purpose: "original_host_factory_call_vector_manifest_v2", BindingSchema: hostVectorScopeSchema, BindingSHA256: hostVectorSHA(), OwnerRole: "host_exterior", OriginalOwnerID: hostVectorOwner, OwnerPrimitiveRawSHA256: hostVectorSHA(), Operation: op, OriginalHandleID: hostVectorHandle, Level: 0, FirstOrdinal: first, LastOrdinal: last, OriginalCallCount: count, ChildBodySHAs: children[op], CollectionState: "complete_original_calls"}
		ref := hostVectorDeclaredRef(op, hostVectorHandle, first, last, count)
		ref.ManifestRootSHA256 = hostVectorPtr(g.store(t, m))
		refs = append(refs, ref)
	}
	value := model.HostFactoryHandleCallInventory{Schema: "original_host_factory_handle_call_inventory_v1", Purpose: "original_host_factory_handle_call_inventory_v1", BindingSchema: hostVectorScopeSchema, BindingSHA256: hostVectorSHA(), OwnerRole: "host_exterior", OriginalOwnerID: hostVectorOwner, OwnerPrimitiveRawSHA256: hostVectorPtr(hostVectorSHA()), OriginalHandleID: hostVectorHandle, OriginalAcquisitionState: "acquired_held", FirstOrdinal: 1, LastOrdinal: 3, OriginalCallCount: 3, OperationVectors: refs, CollectionState: "complete_original_calls", OriginalOperationDeadline: hostVectorTime().Add(60 * time.Second), RecordedAt: hostVectorTime().Add(time.Second)}
	return value, g
}

func TestHostOriginalFactoryWholeHandleCoverage(t *testing.T) {
	cases := []struct {
		name     string
		change   func(*model.HostFactoryHandleCallInventory, *hostVectorGraph)
		accepted bool
	}{
		{"getfl_one_three_getfd_two_union", nil, true},
		{"foreign_inventory_binding", func(v *model.HostFactoryHandleCallInventory, g *hostVectorGraph) {
			v.BindingSHA256 = strings.Repeat("b", 64)
		}, false},
		{"unknown_first_relation", func(v *model.HostFactoryHandleCallInventory, g *hostVectorGraph) {
			g.links = map[string]hostVectorPredecessor{}
		}, false},
		{"missing_ordinal_two", func(v *model.HostFactoryHandleCallInventory, g *hostVectorGraph) {
			v.OperationVectors = v.OperationVectors[:1]
		}, false},
		{"duplicate_operation_vector", func(v *model.HostFactoryHandleCallInventory, g *hostVectorGraph) {
			v.OperationVectors = append(v.OperationVectors, v.OperationVectors[0])
		}, false},
		{"changed_count", func(v *model.HostFactoryHandleCallInventory, g *hostVectorGraph) { v.OriginalCallCount = 2 }, false},
		{"renewed_call_upper_bound_refused", func(v *model.HostFactoryHandleCallInventory, g *hostVectorGraph) {
			v.OriginalOperationDeadline = v.OriginalOperationDeadline.Add(-time.Nanosecond)
		}, false},
		{"pending_inventory_not_complete", func(v *model.HostFactoryHandleCallInventory, g *hostVectorGraph) {
			v.CollectionState = "same_original_call_pending"
		}, false},
		{"incomplete_retention_not_complete", func(v *model.HostFactoryHandleCallInventory, g *hostVectorGraph) {
			v.CollectionState = "incomplete_retention"
		}, false},
		{"inventory_recorded_before_original_return", func(v *model.HostFactoryHandleCallInventory, g *hostVectorGraph) { v.RecordedAt = hostVectorTime() }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, g := hostVectorInterleavedInventory(t)
			if c.change != nil {
				c.change(&v, &g)
			}
			err := ValidateHostFactoryHandleInventory(v, g.resolve, g.predecessor)
			if c.accepted {
				hostVectorBothCodecs(t, v, true)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				hostVectorRefused(t, err)
			}
		})
	}
	t.Run("sparse_vector_alone_refused", func(t *testing.T) {
		v, g := hostVectorInterleavedInventory(t)
		hostVectorRefused(t, ValidateHostFactoryCallVector(v.OperationVectors[0], g.resolve, g.predecessor))
	})
	t.Run("sparse_terminal_chunk_refused", func(t *testing.T) {
		p := hostVectorPrimitive("fcntl_getfl", 1, "returned")
		p.OriginalCount, p.OriginalSHA256, p.OriginalEOF = nil, nil, nil
		p.OriginalHashState = "not_byte_operation"
		n := hostVectorNativeCall("fcntl_getfl")
		p.OriginalNativeReturn = &n
		q := p
		q.OriginalCallOrdinal = hostVectorPtr(uint64(3))
		q.OriginalCallID = hostVectorPtr(hostVectorHandle + ":3")
		c := hostVectorChunk(p, q)
		hostVectorBothCodecs(t, c, false)
	})
	t.Run("empty_diagnostic_graph_not_native_absence", func(t *testing.T) {
		v, g := hostVectorInterleavedInventory(t)
		v.FirstOrdinal, v.LastOrdinal, v.OriginalCallCount = 0, 0, 0
		v.OperationVectors = []model.HostFactoryCallVectorReference{}
		v.OriginalAcquisitionState = "not_acquired"
		hostVectorBothCodecs(t, v, true)
		if err := ValidateHostFactoryHandleInventory(v, g.resolve, g.predecessor); err != nil {
			t.Fatal(err)
		}
		if _, err := ApprovedHostFactorySource(); err == nil {
			t.Fatal("empty consistency graph installed Source approval")
		}
	})
}

func TestHostOriginalFactoryNativeSourceJoins(t *testing.T) {
	cases := []struct {
		name     string
		change   func(*model.HostFactoryNativeProcess)
		accepted bool
	}{
		{"held_same_executable_and_independent_pin", nil, true},
		{"held_after_stat_cannot_reopen", func(n *model.HostFactoryNativeProcess) { n.OriginalHeldExecutableRead.OriginalAfterStat.Inode++ }, false},
		{"held_size_must_match_original_read", func(n *model.HostFactoryNativeProcess) {
			n.OriginalHeldExecutableRead.OriginalBeforeStat.Size++
			n.OriginalHeldExecutableRead.OriginalAfterStat.Size++
		}, false},
		{"held_before_after_call_ids_not_reversed", func(n *model.HostFactoryNativeProcess) {
			h := &n.OriginalHeldExecutableRead
			h.OriginalBeforeFstatCallID, h.OriginalAfterFstatCallID = h.OriginalAfterFstatCallID, h.OriginalBeforeFstatCallID
		}, false},
		{"process_uid_not_executable_owner", func(n *model.HostFactoryNativeProcess) { n.OriginalProcessOwnerRead.OriginalStat.UID++ }, false},
		{"process_owner_wrong_birth", func(n *model.HostFactoryNativeProcess) { n.OriginalProcessOwnerRead.SubjectStartTicks++ }, false},
		{"foreign_observer_basal", func(n *model.HostFactoryNativeProcess) {
			n.OriginalSubjectNativePin.ObserverPrimitiveRawSHA256 = strings.Repeat("b", 64)
		}, false},
		{"pin_same_poll_id_refused", func(n *model.HostFactoryNativeProcess) {
			n.OriginalSubjectNativePin.OriginalAfterPollCallID = n.OriginalSubjectNativePin.OriginalBeforePollCallID
		}, false},
		{"pin_original_poll_order_not_reversed", func(n *model.HostFactoryNativeProcess) {
			p := &n.OriginalSubjectNativePin
			p.OriginalBeforePollCallID, p.OriginalAfterPollCallID = p.OriginalAfterPollCallID, p.OriginalBeforePollCallID
		}, false},
		{"pin_observed_before_original_reads", func(n *model.HostFactoryNativeProcess) {
			n.OriginalSubjectNativePin.OriginalObservedAt = hostVectorTime()
		}, false},
		{"independent_pin_not_basal_self_alias", func(n *model.HostFactoryNativeProcess) {
			n.OriginalSubjectNativePin.OriginalOpenCallVector = nil
			n.OriginalSubjectNativePin.OriginalBasalSelfPIDFDSourceSHA256 = hostVectorPtr(hostVectorSHA())
		}, false},
		{"missing_native_handle_inventory", func(n *model.HostFactoryNativeProcess) { n.NativeHandleInventorySHAs = []string{} }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := hostVectorNativeDeclaredBytes()
			if c.change != nil {
				c.change(&n)
			}
			hostVectorBothCodecs(t, n, c.accepted)
		})
	}
	t.Run("descriptor_exact_selected_call_ids", func(t *testing.T) {
		d := hostVectorRootDeclaredBytes().RootDirectorySource
		hostVectorBothCodecs(t, d, true)
		d.OriginalGetflCallID = d.OriginalFstatCallID
		hostVectorBothCodecs(t, d, false)
	})
	t.Run("descriptor_inherited_or_acquired_exclusive", func(t *testing.T) {
		d := hostVectorRootDeclaredBytes().RootDirectorySource
		d.OriginalInheritedFromHandleID = hostVectorPtr(hostVectorSubject)
		hostVectorBothCodecs(t, d, false)
	})
	t.Run("descriptor_foreign_getfd_basal", func(t *testing.T) {
		d := hostVectorRootDeclaredBytes().RootDirectorySource
		d.OriginalGetfdCallVector.OwnerPrimitiveRawSHA256 = hostVectorPtr(strings.Repeat("b", 64))
		hostVectorBothCodecs(t, d, false)
	})
}

func TestHostOriginalFactoryUnsignedSourceAudit(t *testing.T) {
	tm := hostVectorTime()
	base := func() model.HostFactorySourceAuditReturn {
		return model.HostFactorySourceAuditReturn{Schema: "original_host_factory_source_audit_return_v1", Purpose: "source_audit_only_no_host_native_authority", FactoryRootID: hostVectorOwner, OriginalAuditHandleID: hostVectorHandle, OriginalCallID: hostVectorPtr(hostVectorHandle + ":1"), Operation: "public_workflow_body_read", OriginalState: "returned", OriginalCalledAt: hostVectorPtr(tm), OriginalReturnedAt: hostVectorPtr(tm.Add(time.Nanosecond)), OriginalOperationDeadline: tm.Add(5 * time.Second), OriginalErrorPresent: hostVectorPtr(false), OriginalCount: hostVectorPtr(int64(0)), OriginalSHA256: hostVectorPtr(HostFactoryRawSHA256(nil)), OriginalHashState: "actual_public_bytes", OriginalEOF: hostVectorPtr(true), OriginalReadScope: hostVectorPtr("complete_original_body_read"), RetainedPrefixBytes: hostVectorPtr(int64(0)), RetainedPrefixSHA256: hostVectorPtr(HostFactoryRawSHA256(nil))}
	}
	cases := []struct {
		name     string
		change   func(*model.HostFactorySourceAuditReturn)
		accepted bool
	}{
		{"actual_empty_eof_not_missing_read", nil, true},
		{"partial_65537_bounded_not_whole_response", func(a *model.HostFactorySourceAuditReturn) {
			a.OriginalCount = hostVectorPtr(int64(65537))
			a.OriginalSHA256 = hostVectorPtr(strings.Repeat("b", 64))
			a.OriginalEOF = hostVectorPtr(false)
			a.OriginalReadScope = hostVectorPtr("incomplete_original_body_read")
			a.RetainedPrefixBytes = hostVectorPtr(int64(65536))
			a.RetainedPrefixSHA256 = hostVectorPtr(strings.Repeat("c", 64))
		}, true},
		{"complete_oversize_refused", func(a *model.HostFactorySourceAuditReturn) { a.OriginalCount = hostVectorPtr(int64(65537)) }, false},
		{"private_digest_withheld", func(a *model.HostFactorySourceAuditReturn) { a.OriginalHashState = "private_withheld" }, false},
		{"private_GET_complete_empty_EOF_no_digest", func(a *model.HostFactorySourceAuditReturn) {
			a.OriginalHashState = "private_withheld"
			a.OriginalSHA256 = nil
			a.RetainedPrefixSHA256 = nil
		}, true},
		{"private_GET_complete_nonempty_no_digest", func(a *model.HostFactorySourceAuditReturn) {
			a.OriginalHashState = "private_withheld"
			a.OriginalSHA256 = nil
			a.RetainedPrefixSHA256 = nil
			a.OriginalCount = hostVectorPtr(int64(17))
			a.RetainedPrefixBytes = hostVectorPtr(int64(17))
		}, true},
		{"private_GET_incomplete_actual_error_no_digest", func(a *model.HostFactorySourceAuditReturn) {
			a.OriginalHashState = "private_withheld"
			a.OriginalSHA256 = nil
			a.RetainedPrefixSHA256 = nil
			a.OriginalCount = hostVectorPtr(int64(17))
			a.RetainedPrefixBytes = hostVectorPtr(int64(17))
			a.OriginalReadScope = hostVectorPtr("incomplete_original_body_read")
			a.OriginalErrorPresent = hostVectorPtr(true)
			a.OriginalEOF = hostVectorPtr(false)
		}, true},
		{"private_GET_limit_plus_one_no_digest", func(a *model.HostFactorySourceAuditReturn) {
			a.OriginalHashState = "private_withheld"
			a.OriginalSHA256 = nil
			a.RetainedPrefixSHA256 = nil
			a.OriginalCount = hostVectorPtr(int64(65537))
			a.RetainedPrefixBytes = hostVectorPtr(int64(65536))
			a.OriginalReadScope = hostVectorPtr("incomplete_original_body_read")
			a.OriginalEOF = hostVectorPtr(false)
		}, true},
		{"private_GET_aggregate_digest_forbidden", func(a *model.HostFactorySourceAuditReturn) {
			a.OriginalHashState = "private_withheld"
			a.RetainedPrefixSHA256 = nil
		}, false},
		{"private_GET_prefix_digest_forbidden", func(a *model.HostFactorySourceAuditReturn) {
			a.OriginalHashState = "private_withheld"
			a.OriginalSHA256 = nil
		}, false},
		{"private_GET_complete_requires_actual_EOF", func(a *model.HostFactorySourceAuditReturn) {
			a.OriginalHashState = "private_withheld"
			a.OriginalSHA256 = nil
			a.RetainedPrefixSHA256 = nil
			a.OriginalEOF = hostVectorPtr(false)
		}, false},
		{"private_GET_complete_requires_nil_Read_error", func(a *model.HostFactorySourceAuditReturn) {
			a.OriginalHashState = "private_withheld"
			a.OriginalSHA256 = nil
			a.RetainedPrefixSHA256 = nil
			a.OriginalErrorPresent = hostVectorPtr(true)
		}, false},
		{"private_GET_partial_prefix_count_exact", func(a *model.HostFactorySourceAuditReturn) {
			a.OriginalHashState = "private_withheld"
			a.OriginalSHA256 = nil
			a.RetainedPrefixSHA256 = nil
			a.OriginalCount = hostVectorPtr(int64(17))
			a.RetainedPrefixBytes = hostVectorPtr(int64(16))
			a.OriginalReadScope = hostVectorPtr("incomplete_original_body_read")
			a.OriginalErrorPresent = hostVectorPtr(true)
			a.OriginalEOF = hostVectorPtr(false)
		}, false},
		{"private_GET_incomplete_requires_error_or_actual_cap_plus_one", func(a *model.HostFactorySourceAuditReturn) {
			a.OriginalHashState = "private_withheld"
			a.OriginalSHA256 = nil
			a.RetainedPrefixSHA256 = nil
			a.OriginalReadScope = hostVectorPtr("incomplete_original_body_read")
		}, false},
		{"public_complete_missing_prefix_digest_refused", func(a *model.HostFactorySourceAuditReturn) { a.RetainedPrefixSHA256 = nil }, false},
		{"unknown_POST_actual_complete_scope_digests_unavailable", func(a *model.HostFactorySourceAuditReturn) {
			a.OriginalHashState = "unknown_original_bytes"
			a.OriginalSHA256 = nil
			a.RetainedPrefixSHA256 = nil
		}, true},
		{"original_status_not_zero_default", func(a *model.HostFactorySourceAuditReturn) { a.OriginalStatusCode = hostVectorPtr(0) }, false},
		{"foreign_call_handle", func(a *model.HostFactorySourceAuditReturn) {
			a.OriginalCallID = hostVectorPtr(hostVectorSubject + ":1")
		}, false},
		{"source_audit_not_native_op_alias", func(a *model.HostFactorySourceAuditReturn) { a.Operation = "native_reader_close" }, false},
		{"source_audit_no_Host_purpose_alias", func(a *model.HostFactorySourceAuditReturn) { a.Purpose = a.Schema }, false},
		{"SQL_original_raw_not_public_digest", func(a *model.HostFactorySourceAuditReturn) { a.Operation = "db_original_query" }, false},
		{"full_eof_original_error_independent", func(a *model.HostFactorySourceAuditReturn) { a.OriginalErrorPresent = hostVectorPtr(true) }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := base()
			if c.change != nil {
				c.change(&a)
			}
			hostVectorBothCodecs(t, a, c.accepted)
		})
	}
	t.Run("no_read_retains_unknown_original_and_empty_local_buffer", func(t *testing.T) {
		a := base()
		a.OriginalState = "not_called"
		a.OriginalCallID = nil
		a.OriginalCalledAt = nil
		a.OriginalReturnedAt = nil
		a.OriginalErrorPresent = nil
		a.OriginalCount = nil
		a.OriginalSHA256 = nil
		a.OriginalEOF = nil
		a.OriginalHashState = "unknown_original_bytes"
		a.OriginalReadScope = hostVectorPtr("no_original_body_read")
		hostVectorBothCodecs(t, a, true)
		a.OriginalSHA256 = hostVectorPtr(HostFactoryRawSHA256(nil))
		hostVectorBothCodecs(t, a, false)
		a.OriginalSHA256 = nil
		a.RetainedPrefixSHA256 = nil
		hostVectorBothCodecs(t, a, true) // no read and no public buffer digest available
	})
	t.Run("unsigned_Source_audit_cannot_choose_Host_envelope", func(t *testing.T) {
		_, err := HostFactoryEnvelopeSchema(base(), "host_exterior", hostVectorScopeSchema)
		hostVectorRefused(t, err)
	})
}

func TestHostOriginalFactoryGetdentsReturnClass(t *testing.T) {
	cases := []struct {
		name     string
		change   func(*model.HostFactoryPrimitiveIOReturn)
		accepted bool
	}{
		{"native_zero_nil_not_io_eof", nil, true},
		{"actual_positive_raw_bytes", func(p *model.HostFactoryPrimitiveIOReturn) {
			p.OriginalNativeReturn.OriginalScalar = hostVectorPtr(int64(24))
			p.OriginalCount = hostVectorPtr(int64(24))
			p.OriginalSHA256 = hostVectorPtr(hostVectorSHA())
			p.OriginalReturnClass = "success"
		}, true},
		{"io_eof_is_not_native_zero", func(p *model.HostFactoryPrimitiveIOReturn) {
			p.OriginalEOF = hostVectorPtr(true)
			p.OriginalReturnClass = "eof"
		}, false},
		{"native_zero_requires_actual_empty_buffer_sha", func(p *model.HostFactoryPrimitiveIOReturn) { p.OriginalSHA256 = hostVectorPtr(hostVectorSHA()) }, false},
		{"native_scalar_count_disagrees", func(p *model.HostFactoryPrimitiveIOReturn) {
			p.OriginalNativeReturn.OriginalScalar = hostVectorPtr(int64(24))
		}, false},
		{"failed_native_count_unknown", func(p *model.HostFactoryPrimitiveIOReturn) {
			p.OriginalNativeReturn.OriginalScalar = hostVectorPtr(int64(-1))
			p.OriginalNativeReturn.OriginalErrorPresent = hostVectorPtr(true)
			p.OriginalNativeReturn.OriginalErrno = hostVectorPtr(uint32(5))
			p.OriginalCount = nil
			p.OriginalSHA256 = nil
			p.OriginalHashState = "unknown_original_bytes"
			p.OriginalReturnClass = "io_refused"
		}, true},
		{"failed_native_cannot_fabricate_empty_success", func(p *model.HostFactoryPrimitiveIOReturn) {
			p.OriginalNativeReturn.OriginalErrorPresent = hostVectorPtr(true)
			p.OriginalNativeReturn.OriginalErrno = hostVectorPtr(uint32(5))
		}, false},
		{"native_requested_buffer_not_zero", func(p *model.HostFactoryPrimitiveIOReturn) {
			p.OriginalNativeReturn.RequestedArgument = hostVectorPtr(int64(0))
		}, false},
		{"native_return_cannot_exceed_actual_requested_buffer", func(p *model.HostFactoryPrimitiveIOReturn) {
			p.OriginalNativeReturn.RequestedArgument = hostVectorPtr(int64(1))
			p.OriginalNativeReturn.OriginalScalar = hostVectorPtr(int64(24))
			p.OriginalCount = hostVectorPtr(int64(24))
			p.OriginalSHA256 = hostVectorPtr(hostVectorSHA())
			p.OriginalReturnClass = "success"
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := hostVectorPrimitive("task_inventory_getdents", 1, "returned")
			n := hostVectorNativeCall("unix_getdents64")
			p.OriginalNativeReturn = &n
			p.OriginalCount = hostVectorPtr(int64(0))
			p.OriginalEOF = hostVectorPtr(false)
			p.OriginalReturnClass = "native_zero_return"
			if c.change != nil {
				c.change(&p)
			}
			hostVectorBothCodecs(t, p, c.accepted)
		})
	}
}

// Isolated successor Source vectors only; these constructors execute no OS
// operations and cannot supply a native realm, approved key or SQL relation.
func hostVectorNativeReference() model.HostFactoryNativeObservationReference {
	return model.HostFactoryNativeObservationReference{ObservationID: hostVectorHandle, ObservationKind: "process", OriginalBodySHA256: hostVectorSHA(), OriginalEnvelopeSHA256: strings.Repeat("b", 64), ObserverOwnerID: hostVectorOwner, ObserverPrimitiveRawSHA256: hostVectorSHA(), SubjectOwnerID: hostVectorSubject, SubjectPrimitiveRawSHA256: strings.Repeat("c", 64)}
}
func hostVectorNativeRecord() model.HostFactoryNativeObservationRecord {
	p := hostVectorNativeDeclaredBytes()
	return model.HostFactoryNativeObservationRecord{Schema: "original_host_factory_native_observation_record_v1", Purpose: "original_host_factory_native_observation_record_v1", FactoryRootID: hostVectorOwner, BindingSchema: hostVectorScopeSchema, BindingSHA256: hostVectorSHA(), ObservationID: hostVectorHandle, ObservationKind: "process", ObserverRole: "host_registrar", ObserverOwnerID: hostVectorOwner, ObserverPrimitiveRawSHA256: hostVectorSHA(), SubjectRole: "host_worker", SubjectOwnerID: hostVectorSubject, SubjectPrimitiveRawSHA256: strings.Repeat("c", 64), OriginalOperationDeadline: hostVectorTime().Add(60 * time.Second), Process: &p}
}
func hostVectorNativeManifest() model.HostFactoryNativeObservationManifest {
	r := hostVectorNativeReference()
	r.ObservationKind = "thread_children"
	return model.HostFactoryNativeObservationManifest{Schema: "original_host_factory_native_observation_manifest_v1", Purpose: "original_host_factory_native_observation_manifest_v1", FactoryRootID: hostVectorOwner, BindingSchema: hostVectorScopeSchema, BindingSHA256: hostVectorSHA(), CollectionID: hostVectorSubject, ObservationKind: "thread_children", ObserverRole: "host_registrar", ObserverOwnerID: hostVectorOwner, ObserverPrimitiveRawSHA256: hostVectorSHA(), Level: 0, FirstOrdinal: 1, LastOrdinal: 1, OriginalObservationCount: 1, Observations: []model.HostFactoryNativeObservationReference{r}, Children: []model.HostFactoryNativeObservationManifestReference{}, OriginalOperationDeadline: hostVectorTime().Add(60 * time.Second), RecordedAt: hostVectorTime().Add(time.Second)}
}
func TestHostOriginalFactoryNativeRepresentationBytes(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*model.HostFactoryNativeObservationRecord)
		accepted bool
	}{
		{"whole_process_shape_only", nil, true},
		{"missing_all_payloads", func(r *model.HostFactoryNativeObservationRecord) { r.Process = nil }, false},
		{"two_payloads", func(r *model.HostFactoryNativeObservationRecord) {
			r.TaskDirectory = &model.HostFactoryTaskDirectoryRead{}
		}, false},
		{"kind_payload_mismatch", func(r *model.HostFactoryNativeObservationRecord) { r.ObservationKind = "thread_children" }, false},
		{"process_forged_collection", func(r *model.HostFactoryNativeObservationRecord) {
			r.OriginalCensusCollectionID = hostVectorPtr(hostVectorSubject)
			r.OriginalCensusOrdinal = hostVectorPtr(uint32(1))
		}, false},
		{"collection_half_present", func(r *model.HostFactoryNativeObservationRecord) { r.OriginalCensusOrdinal = hostVectorPtr(uint32(1)) }, false},
		{"foreign_observer_basal", func(r *model.HostFactoryNativeObservationRecord) {
			r.ObserverPrimitiveRawSHA256 = strings.Repeat("d", 64)
		}, false},
		{"foreign_observer_owner", func(r *model.HostFactoryNativeObservationRecord) { r.ObserverOwnerID = hostVectorSubject }, false},
		{"foreign_subject_owner", func(r *model.HostFactoryNativeObservationRecord) { r.SubjectOwnerID = hostVectorOwner }, false},
		{"unissued_approval_binding", func(r *model.HostFactoryNativeObservationRecord) {
			r.BindingSchema = "original_host_factory_source_approval_v4"
		}, false},
		{"subject_cannot_sign_observer", func(r *model.HostFactoryNativeObservationRecord) { r.ObserverRole = "host_worker" }, false},
		{"unknown_subject_role", func(r *model.HostFactoryNativeObservationRecord) { r.SubjectRole = "native_from_flags" }, false},
		{"unknown_observation_kind", func(r *model.HostFactoryNativeObservationRecord) { r.ObservationKind = "native_complete" }, false},
		{"missing_source_identifier", func(r *model.HostFactoryNativeObservationRecord) { r.ObservationID = "" }, false},
		{"invalid_script_mode_not_native_proof", func(r *model.HostFactoryNativeObservationRecord) {
			r.Process.NativeHandleInventorySHAs = []string{}
			for i := 0; i < 64; i++ {
				r.Process.NativeHandleInventorySHAs = append(r.Process.NativeHandleInventorySHAs, fmt.Sprintf("%064x", i))
			}
			r.Process.Execution.ScriptMode = "invalid"
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := hostVectorNativeRecord()
			if c.mutate != nil {
				c.mutate(&r)
			}
			hostVectorBothCodecs(t, r, c.accepted)
		})
	}
	t.Run("case_alias_required_pointer", func(t *testing.T) {
		raw := hostVectorJSON(t, hostVectorNativeRecord())
		raw = bytes.Replace(raw, []byte(`"task_directory":null`), []byte(`"Task_Directory":null`), 1)
		var out model.HostFactoryNativeObservationRecord
		hostVectorRefused(t, DecodeHostFactory(raw, &out))
	})
	t.Run("omitted_nullable_pointer", func(t *testing.T) {
		raw := hostVectorJSON(t, hostVectorNativeRecord())
		raw = bytes.Replace(raw, []byte(`,"task_directory":null`), nil, 1)
		var out model.HostFactoryNativeObservationRecord
		hostVectorRefused(t, DecodeHostFactory(raw, &out))
	})
}
func TestHostOriginalFactoryNativeReferenceManifestBytes(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*model.HostFactoryNativeObservationManifest)
		accepted bool
	}{
		{"one_whole_observation_reference", nil, true},
		{"zero_references_not_empty_native_proof", func(m *model.HostFactoryNativeObservationManifest) {
			m.Observations = []model.HostFactoryNativeObservationReference{}
			m.OriginalObservationCount = 0
		}, false},
		{"leaf_child_mixture", func(m *model.HostFactoryNativeObservationManifest) {
			m.Children = []model.HostFactoryNativeObservationManifestReference{{}}
		}, false},
		{"duplicate_original_id", func(m *model.HostFactoryNativeObservationManifest) {
			m.Observations = append(m.Observations, m.Observations[0])
			m.LastOrdinal = 2
			m.OriginalObservationCount = 2
		}, false},
		{"foreign_leaf_observer", func(m *model.HostFactoryNativeObservationManifest) {
			m.Observations[0].ObserverOwnerID = hostVectorSubject
		}, false},
		{"foreign_leaf_basal", func(m *model.HostFactoryNativeObservationManifest) {
			m.Observations[0].ObserverPrimitiveRawSHA256 = strings.Repeat("d", 64)
		}, false},
		{"wrong_leaf_kind", func(m *model.HostFactoryNativeObservationManifest) { m.Observations[0].ObservationKind = "process" }, false},
		{"count_not_range", func(m *model.HostFactoryNativeObservationManifest) { m.LastOrdinal = 2 }, false},
		{"zero_ordinal", func(m *model.HostFactoryNativeObservationManifest) { m.FirstOrdinal = 0 }, false},
		{"range_exceeds_existing_4096", func(m *model.HostFactoryNativeObservationManifest) { m.LastOrdinal = 4097 }, false},
		{"level_exceeds_three", func(m *model.HostFactoryNativeObservationManifest) { m.Level = 4 }, false},
		{"internal_without_children", func(m *model.HostFactoryNativeObservationManifest) {
			m.Level = 1
			m.Observations = []model.HostFactoryNativeObservationReference{}
		}, false},
		{"nil_original_references", func(m *model.HostFactoryNativeObservationManifest) { m.Observations = nil }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := hostVectorNativeManifest()
			if c.mutate != nil {
				c.mutate(&m)
			}
			hostVectorBothCodecs(t, m, c.accepted)
		})
	}
}

// This complete BYTE graph has synthetic FIRST rows, syscall return shapes and
// keys. It tests joins in CI only, never supplies a native approval or VM fact.
type hostVectorNativeGraph struct {
	bodies, envelopes, io map[string][]byte
	relations             map[string]map[string]string
	record                model.HostFactoryNativeObservationRecord
	reference             model.HostFactoryNativeObservationReference
	key                   ed25519.PrivateKey
}

func hostVectorSyntheticNativeGraph(t *testing.T) hostVectorNativeGraph {
	t.Helper()
	g := hostVectorNativeGraph{bodies: map[string][]byte{}, envelopes: map[string][]byte{}, io: map[string][]byte{}, relations: map[string]map[string]string{}, record: hostVectorNativeRecord(), key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{23}, 32))}
	n := g.record.Process
	refs := map[string]model.HostFactoryCallVectorReference{}
	var gather func(reflect.Value)
	gather = func(v reflect.Value) {
		if v.Kind() == reflect.Pointer {
			if !v.IsNil() {
				gather(v.Elem())
			}
			return
		}
		if v.Type() == reflect.TypeOf(model.HostFactoryCallVectorReference{}) {
			r := v.Interface().(model.HostFactoryCallVectorReference)
			refs[r.OriginalHandleID+"/"+r.Operation] = r
			return
		}
		if v.Kind() == reflect.Struct {
			for i := 0; i < v.NumField(); i++ {
				gather(v.Field(i))
			}
		}
		if v.Kind() == reflect.Array || v.Kind() == reflect.Slice {
			for i := 0; i < v.Len(); i++ {
				gather(v.Index(i))
			}
		}
	}
	gather(reflect.ValueOf(n))
	facts := map[string]model.HostFactoryOriginalIOFact{}
	for _, f := range n.NativeReadOperations {
		facts[f.OriginalHandleID+"/"+f.Operation] = f
		facts[f.OriginalHandleID+"/"+f.OriginalCloseCallVector.Operation] = f
	}
	byHandle := map[string][]model.HostFactoryCallVectorReference{}
	for key, r := range refs {
		ords := []uint64{}
		if r.OriginalCallCount == 1 {
			ords = []uint64{r.FirstOrdinal}
		} else {
			ords = []uint64{r.FirstOrdinal, r.LastOrdinal}
		}
		chunks := []string{}
		for _, ord := range ords {
			tm := hostVectorTime()
			called, returned := tm, tm
			f, readFact := facts[key]
			primitive := model.HostFactoryPrimitiveIOReturn{Operation: r.Operation, OriginalHandleID: r.OriginalHandleID, OwnerPrimitiveRawSHA256: hostVectorPtr(hostVectorSHA()), OriginalState: "returned", OriginalCalledAt: &called, OriginalReturnedAt: &returned, OriginalReturnClass: "success", SubjectOwnerID: hostVectorSubject, OriginalOperationDeadline: g.record.OriginalOperationDeadline, OriginalHashState: "not_byte_operation", OriginalCallOrdinal: hostVectorPtr(ord), OriginalCallID: hostVectorPtr(fmt.Sprintf("%s:%d", r.OriginalHandleID, ord))}
			if readFact && r.Operation == f.Operation {
				called, returned = f.OriginalCalledAt, f.OriginalReturnedAt
				primitive.OriginalCount = hostVectorPtr(f.OriginalCount)
				primitive.OriginalSHA256 = hostVectorPtr(f.OriginalSHA256)
				primitive.OriginalEOF = hostVectorPtr(true)
				primitive.OriginalReturnClass = "eof"
				primitive.OriginalHashState = "actual_public_bytes"
			} else {
				kind := "unix_fstat"
				fd := 11
				if r.Operation == "native_reader_close" || r.Operation == "proc_owner_directory_close" {
					kind = "original_file_close"
				}
				if r.Operation == "native_reader_open" || r.Operation == "proc_owner_directory_open" {
					kind = "unix_open"
				}
				if r.Operation == "native_subject_pidfd_open" {
					kind = "unix_pidfd_open"
					fd = 13
				}
				if r.Operation == "native_subject_alive_poll" {
					kind = "unix_poll"
					fd = 13
				}
				if r.OriginalHandleID == n.OriginalProcessOwnerRead.OriginalHandleID {
					fd = 12
				}
				native := hostVectorNativeCall(kind)
				if native.InputDescriptorNumber != nil {
					native.InputDescriptorNumber = hostVectorPtr(fd)
				}
				if kind == "unix_open" || kind == "unix_pidfd_open" {
					native.OriginalScalar = hostVectorPtr(int64(fd))
					native.ReturnedDescriptors = []model.HostFactoryNativeAcquiredDescriptor{{OriginalHandleID: r.OriginalHandleID, OriginalDescriptorNumber: fd}}
				}
				if kind == "unix_fstat" {
					stat := n.OriginalHeldExecutableRead.OriginalBeforeStat
					if r.OriginalHandleID == n.OriginalProcessOwnerRead.OriginalHandleID {
						stat = n.OriginalProcessOwnerRead.OriginalStat
					}
					if r.OriginalHandleID == n.OriginalSubjectNativePin.OriginalHandleID {
						stat = n.OriginalSubjectNativePin.OriginalStat
						native.InputDescriptorNumber = hostVectorPtr(13)
					}
					native.OriginalStat = &stat
				}
				if readFact && r.Operation == f.OriginalCloseCallVector.Operation {
					called, returned = f.OriginalCloseReturnedAt, f.OriginalCloseReturnedAt
				}
				if r.OriginalHandleID == n.OriginalHeldExecutableRead.OriginalHandleID {
					switch ord {
					case 1:
						called = n.OriginalHeldExecutableRead.OriginalRead.OriginalCalledAt.Add(-2 * time.Nanosecond)
					case 2:
						called = n.OriginalHeldExecutableRead.OriginalRead.OriginalCalledAt.Add(-time.Nanosecond)
					case 4:
						called = n.OriginalHeldExecutableRead.OriginalRead.OriginalReturnedAt
					}
					if ord != 5 {
						returned = called
					}
				}
				if r.OriginalHandleID == n.OriginalSubjectNativePin.OriginalHandleID {
					called = tm.Add((time.Duration(ord) - 5) * time.Nanosecond)
					if ord == 4 {
						called = n.OriginalNativeCloseReturnedAt
					}
					returned = called
				}
				primitive.OriginalNativeReturn = &native
			}
			chunk := hostVectorChunk(primitive)
			chunk.OriginalHandleID = r.OriginalHandleID
			chunk.OwnerRole = "host_registrar"
			chunk.RecordedAt = returned
			raw, e := CanonicalHostFactory(chunk)
			if e != nil {
				t.Fatalf("synthetic chunk %s:%d %v", key, ord, e)
			}
			sha := HostFactoryRawSHA256(raw)
			g.io[sha] = raw
			chunks = append(chunks, sha)
		}
		m := model.HostFactoryCallVectorManifest{Schema: "original_host_factory_call_vector_manifest_v2", Purpose: "original_host_factory_call_vector_manifest_v2", BindingSchema: hostVectorScopeSchema, BindingSHA256: hostVectorSHA(), OwnerRole: "host_registrar", OriginalOwnerID: hostVectorOwner, OwnerPrimitiveRawSHA256: hostVectorSHA(), Operation: r.Operation, OriginalHandleID: r.OriginalHandleID, Level: 0, FirstOrdinal: r.FirstOrdinal, LastOrdinal: r.LastOrdinal, OriginalCallCount: r.OriginalCallCount, ChildBodySHAs: chunks, CollectionState: "complete_original_calls"}
		raw, e := CanonicalHostFactory(m)
		if e != nil {
			t.Fatal(e)
		}
		sha := HostFactoryRawSHA256(raw)
		g.io[sha] = raw
		r.ManifestRootSHA256 = &sha
		refs[key] = r
		byHandle[r.OriginalHandleID] = append(byHandle[r.OriginalHandleID], r)
	}
	n.NativeHandleInventorySHAs = []string{}
	inventoryByHandle := map[string]string{}
	handles := []string{}
	for handle := range byHandle {
		handles = append(handles, handle)
	}
	sort.Strings(handles)
	for _, handle := range handles {
		vs := byHandle[handle]
		sort.Slice(vs, func(i, j int) bool { return vs[i].FirstOrdinal < vs[j].FirstOrdinal })
		count, last := uint64(0), uint64(0)
		for _, r := range vs {
			count += r.OriginalCallCount
			if r.LastOrdinal > last {
				last = r.LastOrdinal
			}
		}
		inv := model.HostFactoryHandleCallInventory{Schema: "original_host_factory_handle_call_inventory_v1", Purpose: "original_host_factory_handle_call_inventory_v1", BindingSchema: hostVectorScopeSchema, BindingSHA256: hostVectorSHA(), OwnerRole: "host_registrar", OriginalOwnerID: hostVectorOwner, OwnerPrimitiveRawSHA256: hostVectorPtr(hostVectorSHA()), OriginalHandleID: handle, OriginalAcquisitionState: "original_close_returned", FirstOrdinal: 1, LastOrdinal: last, OriginalCallCount: count, OperationVectors: vs, CollectionState: "complete_original_calls", OriginalOperationDeadline: g.record.OriginalOperationDeadline, RecordedAt: hostVectorTime().Add(time.Second)}
		raw, e := CanonicalHostFactory(inv)
		if e != nil {
			t.Fatal(e)
		}
		sha := HostFactoryRawSHA256(raw)
		g.io[sha] = raw
		inventoryByHandle[handle] = sha
		n.NativeHandleInventorySHAs = append(n.NativeHandleInventorySHAs, sha)
	}
	var replace func(reflect.Value)
	replace = func(v reflect.Value) {
		if v.Kind() == reflect.Pointer {
			if !v.IsNil() {
				replace(v.Elem())
			}
			return
		}
		if v.Type() == reflect.TypeOf(model.HostFactoryCallVectorReference{}) {
			r := v.Interface().(model.HostFactoryCallVectorReference)
			v.Set(reflect.ValueOf(refs[r.OriginalHandleID+"/"+r.Operation]))
			return
		}
		if v.Kind() == reflect.Struct {
			for i := 0; i < v.NumField(); i++ {
				if v.Type().Field(i).Name == "OriginalHandleInventorySHA256" {
					h := v.FieldByName("OriginalHandleID").String()
					v.Field(i).SetString(inventoryByHandle[h])
				} else {
					replace(v.Field(i))
				}
			}
		}
		if v.Kind() == reflect.Array || v.Kind() == reflect.Slice {
			for i := 0; i < v.Len(); i++ {
				replace(v.Index(i))
			}
		}
	}
	replace(reflect.ValueOf(n))
	g.relations[g.record.ObservationID] = map[string]string{}
	for _, v := range refs {
		raw, e := CanonicalHostFactory(v)
		if e != nil {
			t.Fatal(e)
		}
		g.relations[g.record.ObservationID][HostFactoryRawSHA256(raw)] = inventoryByHandle[v.OriginalHandleID]
	}
	raw, e := CanonicalHostFactory(g.record)
	if e != nil {
		t.Fatal(e)
	}
	env, e := SignHostFactoryEnvelope(g.record, "host_registrar", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.key)
	if e != nil {
		t.Fatal(e)
	}
	g.reference = hostVectorNativeReference()
	g.reference.OriginalBodySHA256 = HostFactoryRawSHA256(raw)
	g.reference.OriginalEnvelopeSHA256 = HostFactoryRawSHA256(env)
	g.bodies[g.reference.OriginalBodySHA256] = raw
	g.envelopes[g.reference.OriginalEnvelopeSHA256] = env
	return g
}
func (g hostVectorNativeGraph) original(a, b string) ([]byte, []byte, error) {
	x, xok := g.bodies[a]
	y, yok := g.envelopes[b]
	if !xok || !yok {
		return nil, nil, errors.New("synthetic missing exact pair")
	}
	return x, y, nil
}
func (g hostVectorNativeGraph) observer(role, key, id, primitive, binding, sha string) (ed25519.PublicKey, error) {
	if role != "host_registrar" || key != hostVectorOwner || id != hostVectorOwner || primitive != hostVectorSHA() || binding != hostVectorScopeSchema || sha != hostVectorSHA() {
		return nil, errors.New("synthetic unexpected binding")
	}
	return g.key.Public().(ed25519.PublicKey), nil
}
func (g hostVectorNativeGraph) resolveIO(sha string) ([]byte, error) {
	raw, ok := g.io[sha]
	if !ok {
		return nil, errors.New("synthetic missing IO")
	}
	return raw, nil
}
func (g hostVectorNativeGraph) first(sha string, index uint32) ([]byte, uint32, error) {
	raw, ok := g.io[sha]
	var c model.HostFactoryCallVectorChunk
	if !ok || DecodeHostFactory(raw, &c) != nil || index >= uint32(len(c.OriginalCalls)) {
		return nil, 0, errors.New("synthetic unknown FIRST")
	}
	return nil, 0, nil
}
func TestHostOriginalFactoryNativeWholeGraph(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*hostVectorNativeGraph)
		accepted bool
	}{
		{"synthetic_complete_original_byte_graph_ONLY", nil, true},
		{"missing_body", func(g *hostVectorNativeGraph) { delete(g.bodies, g.reference.OriginalBodySHA256) }, false},
		{"missing_envelope", func(g *hostVectorNativeGraph) { delete(g.envelopes, g.reference.OriginalEnvelopeSHA256) }, false},
		{"body_hash_rebound", func(g *hostVectorNativeGraph) { g.bodies[g.reference.OriginalBodySHA256] = []byte(`{}`) }, false},
		{"envelope_hash_rebound", func(g *hostVectorNativeGraph) { g.envelopes[g.reference.OriginalEnvelopeSHA256] = []byte(`{}`) }, false},
		{"body_cap_plus_one", func(g *hostVectorNativeGraph) {
			raw := bytes.Repeat([]byte("x"), 65537)
			g.reference.OriginalBodySHA256 = HostFactoryRawSHA256(raw)
			g.bodies[g.reference.OriginalBodySHA256] = raw
		}, false},
		{"envelope_cap_plus_one", func(g *hostVectorNativeGraph) {
			raw := bytes.Repeat([]byte("x"), 65537)
			g.reference.OriginalEnvelopeSHA256 = HostFactoryRawSHA256(raw)
			g.envelopes[g.reference.OriginalEnvelopeSHA256] = raw
		}, false},
		{"body_empty", func(g *hostVectorNativeGraph) {
			g.reference.OriginalBodySHA256 = HostFactoryRawSHA256(nil)
			g.bodies[g.reference.OriginalBodySHA256] = []byte{}
		}, false},
		{"envelope_empty", func(g *hostVectorNativeGraph) {
			g.reference.OriginalEnvelopeSHA256 = HostFactoryRawSHA256(nil)
			g.envelopes[g.reference.OriginalEnvelopeSHA256] = []byte{}
		}, false},
		{"foreign_observation_id", func(g *hostVectorNativeGraph) { g.reference.ObservationID = hostVectorSubject }, false},
		{"foreign_subject_basal", func(g *hostVectorNativeGraph) { g.reference.SubjectPrimitiveRawSHA256 = strings.Repeat("d", 64) }, false},
		{"missing_actual_IO_inventory", func(g *hostVectorNativeGraph) { delete(g.io, g.record.Process.NativeHandleInventorySHAs[0]) }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := hostVectorSyntheticNativeGraph(t)
			if c.mutate != nil {
				c.mutate(&g)
			}
			got, e := ResolveHostFactoryNativeObservation(g.reference, hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.record.OriginalOperationDeadline, g.original, g.observer, g.resolveIO, g.first, func(string) ([]byte, error) { return nil, errors.New("unused synthetic getdents") }, g.selectedInventory)
			if c.accepted {
				if e != nil || !reflect.DeepEqual(got, g.record) {
					t.Fatalf("complete declared graph: %v", e)
				}
			} else {
				hostVectorRefused(t, e)
				if got.Process != nil {
					t.Fatal("refusal leaked positive graph")
				}
			}
		})
	}
	t.Run("unknown_FIRST_relation_HOLD", func(t *testing.T) {
		g := hostVectorSyntheticNativeGraph(t)
		_, e := ResolveHostFactoryNativeObservation(g.reference, hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.record.OriginalOperationDeadline, g.original, g.observer, g.resolveIO, func(string, uint32) ([]byte, uint32, error) { return nil, 0, errors.New("unknown relation") }, func(string) ([]byte, error) { return nil, nil }, g.selectedInventory)
		hostVectorRefused(t, e)
	})
	t.Run("unapproved_observer_key_HOLD", func(t *testing.T) {
		g := hostVectorSyntheticNativeGraph(t)
		_, e := ResolveHostFactoryNativeObservation(g.reference, hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.record.OriginalOperationDeadline, g.original, func(string, string, string, string, string, string) (ed25519.PublicKey, error) {
			return nil, ErrHostFactorySourceUnavailable
		}, g.resolveIO, g.first, func(string) ([]byte, error) { return nil, nil }, g.selectedInventory)
		hostVectorRefused(t, e)
	})
}

func hostVectorSyntheticThreadCollection(t *testing.T) (hostVectorNativeGraph, model.HostFactoryNativeObservationCollectionReference) {
	t.Helper()
	g := hostVectorSyntheticNativeGraph(t)
	p := *g.record.Process
	child := hostVectorPositiveIO("thread_children_read", "native_reader_close", "99999999-9999-4999-8999-999999999999", hostVectorTime().Add(25*time.Nanosecond), 0, HostFactoryRawSHA256(nil))
	chunks := []string{}
	for i, op := range []string{child.Operation, "native_reader_close"} {
		ord := uint64(i + 1)
		called, returned := child.OriginalCalledAt, child.OriginalReturnedAt
		f := model.HostFactoryPrimitiveIOReturn{Operation: op, OriginalHandleID: child.OriginalHandleID, OwnerPrimitiveRawSHA256: hostVectorPtr(hostVectorSHA()), OriginalState: "returned", OriginalCalledAt: &called, OriginalReturnedAt: &returned, SubjectOwnerID: hostVectorSubject, OriginalOperationDeadline: g.record.OriginalOperationDeadline, OriginalCallOrdinal: &ord, OriginalCallID: hostVectorPtr(fmt.Sprintf("%s:%d", child.OriginalHandleID, ord)), OriginalHashState: "actual_public_bytes", OriginalReturnClass: "eof", OriginalCount: hostVectorPtr(int64(0)), OriginalSHA256: hostVectorPtr(HostFactoryRawSHA256(nil)), OriginalEOF: hostVectorPtr(true)}
		if i == 1 {
			called, returned = child.OriginalCloseReturnedAt, child.OriginalCloseReturnedAt
			f.OriginalCount = nil
			f.OriginalSHA256 = nil
			f.OriginalEOF = nil
			f.OriginalHashState = "not_byte_operation"
			f.OriginalReturnClass = "success"
			native := hostVectorNativeCall("original_file_close")
			f.OriginalNativeReturn = &native
		}
		c := hostVectorChunk(f)
		c.OriginalHandleID = child.OriginalHandleID
		c.OwnerRole = "host_registrar"
		c.RecordedAt = returned
		raw, e := CanonicalHostFactory(c)
		if e != nil {
			t.Fatal(e)
		}
		sha := HostFactoryRawSHA256(raw)
		g.io[sha] = raw
		chunks = append(chunks, sha)
	}
	vs := []model.HostFactoryCallVectorReference{}
	for i, op := range []string{child.Operation, "native_reader_close"} {
		m := model.HostFactoryCallVectorManifest{Schema: "original_host_factory_call_vector_manifest_v2", Purpose: "original_host_factory_call_vector_manifest_v2", BindingSchema: hostVectorScopeSchema, BindingSHA256: hostVectorSHA(), OwnerRole: "host_registrar", OriginalOwnerID: hostVectorOwner, OwnerPrimitiveRawSHA256: hostVectorSHA(), Operation: op, OriginalHandleID: child.OriginalHandleID, Level: 0, FirstOrdinal: uint64(i + 1), LastOrdinal: uint64(i + 1), OriginalCallCount: 1, ChildBodySHAs: []string{chunks[i]}, CollectionState: "complete_original_calls"}
		raw, e := CanonicalHostFactory(m)
		if e != nil {
			t.Fatal(e)
		}
		sha := HostFactoryRawSHA256(raw)
		g.io[sha] = raw
		r := hostVectorDeclaredRef(op, child.OriginalHandleID, uint64(i+1), uint64(i+1), 1)
		r.ManifestRootSHA256 = &sha
		vs = append(vs, r)
	}
	child.OriginalCallVector = vs[0]
	child.OriginalCloseCallVector = vs[1]
	inv := model.HostFactoryHandleCallInventory{Schema: "original_host_factory_handle_call_inventory_v1", Purpose: "original_host_factory_handle_call_inventory_v1", BindingSchema: hostVectorScopeSchema, BindingSHA256: hostVectorSHA(), OwnerRole: "host_registrar", OriginalOwnerID: hostVectorOwner, OwnerPrimitiveRawSHA256: hostVectorPtr(hostVectorSHA()), OriginalHandleID: child.OriginalHandleID, OriginalAcquisitionState: "original_close_returned", FirstOrdinal: 1, LastOrdinal: 2, OriginalCallCount: 2, OperationVectors: vs, CollectionState: "complete_original_calls", OriginalOperationDeadline: g.record.OriginalOperationDeadline, RecordedAt: hostVectorTime().Add(time.Second)}
	raw, e := CanonicalHostFactory(inv)
	if e != nil {
		t.Fatal(e)
	}
	sha := HostFactoryRawSHA256(raw)
	g.io[sha] = raw
	thread := model.HostFactoryNativeThreadChildRead{PID: p.PID, TID: p.PID, ThreadStartTicks: 1, OwnerNativeReceiptSHA256: hostVectorSHA(), ThreadStatBeforeSHA256: p.NativeReadOperations[1].OriginalSHA256, OriginalChildrenRead: child, ChildPIDs: []int{}, ThreadStatAfterSHA256: p.NativeReadOperations[4].OriginalSHA256, OriginalThreadStatBeforeRead: p.NativeReadOperations[1], OriginalThreadStatAfterRead: p.NativeReadOperations[4], NativeHandleInventorySHAs: append(append([]string(nil), p.NativeHandleInventorySHAs...), sha)}
	g.record.Process = nil
	g.record.ObservationKind = "thread_children"
	g.record.OriginalCensusCollectionID = hostVectorPtr(hostVectorSubject)
	g.record.OriginalCensusOrdinal = hostVectorPtr(uint32(1))
	g.record.ThreadChildren = &thread
	previousRelations := g.relations[g.record.ObservationID]
	selectedRelations := map[string]string{}
	for _, f := range []model.HostFactoryOriginalIOFact{thread.OriginalThreadStatBeforeRead, thread.OriginalChildrenRead, thread.OriginalThreadStatAfterRead} {
		for _, v := range []model.HostFactoryCallVectorReference{f.OriginalCallVector, f.OriginalCloseCallVector} {
			raw, e := CanonicalHostFactory(v)
			if e != nil {
				t.Fatal(e)
			}
			key := HostFactoryRawSHA256(raw)
			selected := previousRelations[key]
			if v.OriginalHandleID == child.OriginalHandleID {
				selected = sha
			}
			if selected == "" {
				t.Fatal("missing synthetic original inventory relation")
			}
			selectedRelations[key] = selected
		}
	}
	g.relations[g.record.ObservationID] = selectedRelations
	raw, e = CanonicalHostFactory(g.record)
	if e != nil {
		t.Fatal(e)
	}
	env, e := SignHostFactoryEnvelope(g.record, "host_registrar", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.key)
	if e != nil {
		t.Fatal(e)
	}
	g.reference.ObservationKind = "thread_children"
	g.reference.OriginalBodySHA256 = HostFactoryRawSHA256(raw)
	g.reference.OriginalEnvelopeSHA256 = HostFactoryRawSHA256(env)
	g.bodies[g.reference.OriginalBodySHA256] = raw
	g.envelopes[g.reference.OriginalEnvelopeSHA256] = env
	m := hostVectorNativeManifest()
	m.Observations[0] = g.reference
	raw, e = CanonicalHostFactory(m)
	if e != nil {
		t.Fatal(e)
	}
	env, e = SignHostFactoryEnvelope(m, "host_registrar", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.key)
	if e != nil {
		t.Fatal(e)
	}
	ref := model.HostFactoryNativeObservationCollectionReference{CollectionID: hostVectorSubject, ObservationKind: "thread_children", BindingSchema: hostVectorScopeSchema, BindingSHA256: hostVectorSHA(), ObserverOwnerID: hostVectorOwner, ObserverPrimitiveRawSHA256: hostVectorSHA(), OriginalObservationCount: 1, ManifestRootBodySHA256: HostFactoryRawSHA256(raw), ManifestRootEnvelopeSHA256: HostFactoryRawSHA256(env)}
	g.bodies[ref.ManifestRootBodySHA256] = raw
	g.envelopes[ref.ManifestRootEnvelopeSHA256] = env
	return g, ref
}
func TestHostOriginalFactoryNativeCollectionWholeGraph(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*testing.T, *hostVectorNativeGraph, *model.HostFactoryNativeObservationCollectionReference)
		accepted bool
	}{
		{"synthetic_single_original_thread_cycle_ONLY", nil, true},
		{"missing_manifest_body", func(t *testing.T, g *hostVectorNativeGraph, r *model.HostFactoryNativeObservationCollectionReference) {
			delete(g.bodies, r.ManifestRootBodySHA256)
		}, false},
		{"missing_manifest_envelope", func(t *testing.T, g *hostVectorNativeGraph, r *model.HostFactoryNativeObservationCollectionReference) {
			delete(g.envelopes, r.ManifestRootEnvelopeSHA256)
		}, false},
		{"foreign_collection_id", func(t *testing.T, g *hostVectorNativeGraph, r *model.HostFactoryNativeObservationCollectionReference) {
			r.CollectionID = hostVectorOwner
		}, false},
		{"foreign_collection_basal", func(t *testing.T, g *hostVectorNativeGraph, r *model.HostFactoryNativeObservationCollectionReference) {
			r.ObserverPrimitiveRawSHA256 = strings.Repeat("d", 64)
		}, false},
		{"wrong_collection_kind", func(t *testing.T, g *hostVectorNativeGraph, r *model.HostFactoryNativeObservationCollectionReference) {
			r.ObservationKind = "process"
		}, false},
		{"omitted_thread_count", func(t *testing.T, g *hostVectorNativeGraph, r *model.HostFactoryNativeObservationCollectionReference) {
			r.OriginalObservationCount = 2
		}, false},
		{"manifest_body_cap_plus_one", func(t *testing.T, g *hostVectorNativeGraph, r *model.HostFactoryNativeObservationCollectionReference) {
			raw := bytes.Repeat([]byte("x"), 65537)
			r.ManifestRootBodySHA256 = HostFactoryRawSHA256(raw)
			g.bodies[r.ManifestRootBodySHA256] = raw
		}, false},
		{"manifest_envelope_cap_plus_one", func(t *testing.T, g *hostVectorNativeGraph, r *model.HostFactoryNativeObservationCollectionReference) {
			raw := bytes.Repeat([]byte("x"), 65537)
			r.ManifestRootEnvelopeSHA256 = HostFactoryRawSHA256(raw)
			g.envelopes[r.ManifestRootEnvelopeSHA256] = raw
		}, false},
		{"signed_thread_record_foreign_root_namespace", func(t *testing.T, g *hostVectorNativeGraph, r *model.HostFactoryNativeObservationCollectionReference) {
			hostVectorRebindSyntheticCollectionRecord(t, g, r, hostVectorRootSchema, hostVectorSHA())
		}, false},
		{"signed_thread_record_foreign_scope_body", func(t *testing.T, g *hostVectorNativeGraph, r *model.HostFactoryNativeObservationCollectionReference) {
			hostVectorRebindSyntheticCollectionRecord(t, g, r, hostVectorScopeSchema, strings.Repeat("d", 64))
		}, false},
		{"signed_collection_observer_differs_from_thread", func(t *testing.T, g *hostVectorNativeGraph, r *model.HostFactoryNativeObservationCollectionReference) {
			var node model.HostFactoryNativeObservationManifest
			if DecodeHostFactory(g.bodies[r.ManifestRootBodySHA256], &node) != nil {
				t.Fatal("synthetic original manifest missing")
			}
			node.ObserverRole = "host_exterior"
			raw, err := CanonicalHostFactory(node)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := SignHostFactoryEnvelope(node, node.ObserverRole, hostVectorOwner, node.BindingSchema, node.BindingSHA256, g.key)
			if err != nil {
				t.Fatal(err)
			}
			r.ManifestRootBodySHA256, r.ManifestRootEnvelopeSHA256 = HostFactoryRawSHA256(raw), HostFactoryRawSHA256(envelope)
			g.bodies[r.ManifestRootBodySHA256], g.envelopes[r.ManifestRootEnvelopeSHA256] = raw, envelope
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g, r := hostVectorSyntheticThreadCollection(t)
			if c.mutate != nil {
				c.mutate(t, &g, &r)
			}
			// Recognize only these finite synthetic crypto tuples so mixed
			// originals reach the collection relation guard. This callback is
			// not a Source-approved observer inventory/native approval.
			fixtureObserver := func(role, key, owner, primitive, binding, sha string) (ed25519.PublicKey, error) {
				roleOK := role == "host_registrar" || role == "host_exterior"
				namespaceOK := binding == hostVectorScopeSchema && (sha == hostVectorSHA() || sha == strings.Repeat("d", 64)) || binding == hostVectorRootSchema && sha == hostVectorSHA()
				if !roleOK || !namespaceOK || key != hostVectorOwner || owner != hostVectorOwner || primitive != hostVectorSHA() {
					return nil, errors.New("unknown synthetic crypto tuple")
				}
				return g.key.Public().(ed25519.PublicKey), nil
			}
			out, e := ResolveHostFactoryNativeCollection(r, hostVectorOwner, g.record.OriginalOperationDeadline, g.original, fixtureObserver, g.resolveIO, g.first, func(string) ([]byte, error) { return nil, errors.New("no synthetic getdents") }, g.selectedInventory)
			if c.accepted {
				if e != nil || len(out) != 1 || !reflect.DeepEqual(out[0], g.record) {
					t.Fatalf("whole synthetic collection: %v", e)
				}
			} else {
				hostVectorRefused(t, e)
				if len(out) != 0 {
					t.Fatal("partial positive returned")
				}
			}
		})
	}
}

// This fixture signs internally consistent synthetic record bytes in another
// namespace while keeping the original collection namespace. It is not a
// Source-approved observer, SQL-FIRST relation or native kernel observation.
func hostVectorRebindSyntheticCollectionRecord(t *testing.T, g *hostVectorNativeGraph, ref *model.HostFactoryNativeObservationCollectionReference, schema, sha string) {
	t.Helper()
	var node model.HostFactoryNativeObservationManifest
	if DecodeHostFactory(g.bodies[ref.ManifestRootBodySHA256], &node) != nil {
		t.Fatal("synthetic original manifest missing")
	}
	g.record.BindingSchema, g.record.BindingSHA256 = schema, sha
	raw, err := CanonicalHostFactory(g.record)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SignHostFactoryEnvelope(g.record, g.record.ObserverRole, hostVectorOwner, schema, sha, g.key)
	if err != nil {
		t.Fatal(err)
	}
	g.reference.OriginalBodySHA256, g.reference.OriginalEnvelopeSHA256 = HostFactoryRawSHA256(raw), HostFactoryRawSHA256(envelope)
	g.bodies[g.reference.OriginalBodySHA256], g.envelopes[g.reference.OriginalEnvelopeSHA256] = raw, envelope
	node.Observations[0] = g.reference
	raw, err = CanonicalHostFactory(node)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err = SignHostFactoryEnvelope(node, node.ObserverRole, hostVectorOwner, node.BindingSchema, node.BindingSHA256, g.key)
	if err != nil {
		t.Fatal(err)
	}
	ref.ManifestRootBodySHA256, ref.ManifestRootEnvelopeSHA256 = HostFactoryRawSHA256(raw), HostFactoryRawSHA256(envelope)
	g.bodies[ref.ManifestRootBodySHA256], g.envelopes[ref.ManifestRootEnvelopeSHA256] = raw, envelope
}

func TestHostOriginalFactoryNativeCandidateCensus(t *testing.T) {
	t.Run("closed_model_63_types_911_fields", func(t *testing.T) {
		fields := 0
		for typ := range hostFactorySchemas {
			fields += typ.NumField()
		}
		if len(hostFactorySchemas) != 63 || fields != 911 {
			t.Fatalf("actual model census %d/%d", len(hostFactorySchemas), fields)
		}
	})
	t.Run("native_permissions_unchanged_141_18", func(t *testing.T) {
		if len(hostFactoryOperations) != 141 || len(hostFactoryEnums["NativeCallKind"]) != 18 {
			t.Fatal("native permission widened")
		}
	})
	t.Run("signed_stage_45_plus_12", func(t *testing.T) {
		if len(hostFactorySignatureStages) != 57 {
			t.Fatalf("actual stage rows %d", len(hostFactorySignatureStages))
		}
	})
	t.Run("default_inventory_still_unavailable", func(t *testing.T) {
		_, e := ApprovedHostFactorySource()
		if !errors.Is(e, ErrHostFactorySourceUnavailable) {
			t.Fatal("representation installed approval")
		}
	})
}

func TestHostOriginalFactoryNativeManifestNestedRules(t *testing.T) {
	leaf := model.HostFactoryNativeObservationManifestReference{OriginalBodySHA256: hostVectorSHA(), OriginalEnvelopeSHA256: strings.Repeat("b", 64), Level: 0, FirstOrdinal: 1, LastOrdinal: 1, OriginalObservationCount: 1}
	cases := []struct {
		name     string
		mutate   func(*model.HostFactoryNativeObservationManifest)
		accepted bool
	}{
		{"bounded_child_reference_shape_ONLY", nil, true},
		{"child_level_must_descend", func(m *model.HostFactoryNativeObservationManifest) { m.Children[0].Level = 1 }, false},
		{"missing_first_reference", func(m *model.HostFactoryNativeObservationManifest) {
			m.Children[0].FirstOrdinal = 2
			m.Children[0].LastOrdinal = 2
		}, false},
		{"reference_gap", func(m *model.HostFactoryNativeObservationManifest) {
			next := m.Children[0]
			next.FirstOrdinal = 3
			next.LastOrdinal = 3
			m.Children = append(m.Children, next)
			m.LastOrdinal = 3
			m.OriginalObservationCount = 3
		}, false},
		{"reference_overlap", func(m *model.HostFactoryNativeObservationManifest) {
			m.Children = append(m.Children, m.Children[0])
			m.LastOrdinal = 2
			m.OriginalObservationCount = 2
		}, false},
		{"leaf_counts_not_partition", func(m *model.HostFactoryNativeObservationManifest) { m.Children[0].OriginalObservationCount = 2 }, false},
		{"more_than_16_children", func(m *model.HostFactoryNativeObservationManifest) {
			m.Children = []model.HostFactoryNativeObservationManifestReference{}
			for i := uint32(1); i <= 17; i++ {
				r := leaf
				r.FirstOrdinal = i
				r.LastOrdinal = i
				m.Children = append(m.Children, r)
			}
			m.LastOrdinal = 17
			m.OriginalObservationCount = 17
		}, false},
		{"null_children_not_complete", func(m *model.HostFactoryNativeObservationManifest) { m.Children = nil }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := hostVectorNativeManifest()
			m.Level = 1
			m.Observations = []model.HostFactoryNativeObservationReference{}
			m.Children = []model.HostFactoryNativeObservationManifestReference{leaf}
			if c.mutate != nil {
				c.mutate(&m)
			}
			hostVectorBothCodecs(t, m, c.accepted)
		})
	}
}
func TestHostOriginalFactoryNativeReferenceCryptoDomains(t *testing.T) {
	cases := []struct {
		name          string
		role, binding string
		mutate        func(*model.HostFactoryNativeObservationRecord)
		accepted      bool
	}{
		{"scoped_original_record_shape_crypto_ONLY", "host_registrar", hostVectorScopeSchema, nil, true},
		{"root_original_record_shape_crypto_ONLY", "host_registrar", hostVectorRootSchema, nil, true},
		{"ordinary_original_record_shape_crypto_ONLY", "host_exterior", hostVectorOrdinarySchema, nil, true},
		{"worker_key_not_independent_observer", "host_worker", hostVectorScopeSchema, nil, false},
		{"issuer_key_not_independent_observer", "host_core_issuer", hostVectorRootSchema, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := hostVectorNativeRecord()
			r.ObserverRole = c.role
			r.BindingSchema = c.binding
			key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{29}, 32))
			raw, e := SignHostFactoryEnvelope(r, c.role, hostVectorOwner, c.binding, hostVectorSHA(), key)
			if !c.accepted {
				hostVectorRefused(t, e)
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			var got model.HostFactoryNativeObservationRecord
			if VerifyHostFactoryEnvelope(raw, &got, c.role, hostVectorOwner, c.binding, hostVectorSHA(), key.Public().(ed25519.PublicKey)) != nil || !reflect.DeepEqual(r, got) {
				t.Fatal("original BODY changed")
			}
		})
	}
	t.Run("legacy_aggregate_body_version_refused", func(t *testing.T) {
		var n model.HostFactoryNativeLeaf
		raw := []byte(`{"schema":"original_host_factory_native_leaf_v4"}`)
		hostVectorRefused(t, DecodeHostFactory(raw, &n))
	})
	t.Run("signed_reference_does_not_approve_registry", func(t *testing.T) {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, 32))
		r := hostVectorNativeRecord()
		if _, e := SignHostFactoryEnvelope(r, r.ObserverRole, hostVectorOwner, r.BindingSchema, r.BindingSHA256, key); e != nil {
			t.Fatal(e)
		}
		a, e := ApprovedHostFactorySource()
		if !errors.Is(e, ErrHostFactorySourceUnavailable) || !reflect.DeepEqual(a, model.HostFactorySourceApproval{}) {
			t.Fatal("crypto became source approval")
		}
	})
}

func hostVectorSyntheticNativeTask(t *testing.T, g *hostVectorNativeGraph) (model.HostFactoryNativeObservationReference, map[string][]byte) {
	return hostVectorSyntheticNativeTaskDescriptor(t, g, 14)
}

func hostVectorSyntheticNativeTaskDescriptor(t *testing.T, g *hostVectorNativeGraph, originalGetdentsFD int) (model.HostFactoryNativeObservationReference, map[string][]byte) {
	t.Helper()
	p := g.record.Process
	if p == nil {
		t.Fatal("synthetic process source missing")
	}
	handle := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	fd := 14
	tm := hostVectorTime().Add(25 * time.Nanosecond)
	buf := hostVectorDirent("17", 1, 4)
	original := map[string][]byte{handle + ":3": append([]byte(nil), buf...), handle + ":4": {}}
	stat := model.HostFactoryNativeStatReturn{Device: 1, Inode: 7, Mode: 0040700, LinkCount: 1, Size: 0}
	refs := []model.HostFactoryCallVectorReference{}
	for _, op := range []string{"native_reader_open", "native_reader_fstat", "task_inventory_getdents", "native_reader_close"} {
		ords := map[string][]uint64{"native_reader_open": {1}, "native_reader_fstat": {2}, "task_inventory_getdents": {3, 4}, "native_reader_close": {5}}[op]
		children := []string{}
		for _, ord := range ords {
			called, returned := tm, tm
			kind := "unix_open"
			if ord == 2 {
				kind = "unix_fstat"
			}
			if ord == 3 || ord == 4 {
				kind = "unix_getdents64"
				returned = tm.Add(time.Nanosecond)
			}
			if ord == 4 {
				called = returned
			}
			if ord == 5 {
				kind = "original_file_close"
				called = tm.Add(2 * time.Nanosecond)
				returned = called
			}
			native := hostVectorNativeCall(kind)
			if native.InputDescriptorNumber != nil {
				native.InputDescriptorNumber = hostVectorPtr(fd)
			}
			if kind == "unix_open" {
				native.OriginalScalar = hostVectorPtr(int64(fd))
				native.ReturnedDescriptors = []model.HostFactoryNativeAcquiredDescriptor{{OriginalHandleID: handle, OriginalDescriptorNumber: fd}}
			}
			if kind == "unix_fstat" {
				native.OriginalStat = &stat
			}
			f := model.HostFactoryPrimitiveIOReturn{Operation: op, OriginalHandleID: handle, OwnerPrimitiveRawSHA256: hostVectorPtr(hostVectorSHA()), OriginalState: "returned", OriginalCalledAt: &called, OriginalReturnedAt: &returned, OriginalReturnClass: "success", SubjectOwnerID: hostVectorSubject, OriginalOperationDeadline: g.record.OriginalOperationDeadline, OriginalHashState: "not_byte_operation", OriginalCallOrdinal: hostVectorPtr(ord), OriginalCallID: hostVectorPtr(fmt.Sprintf("%s:%d", handle, ord)), OriginalNativeReturn: &native}
			if kind == "unix_getdents64" {
				native.InputDescriptorNumber = hostVectorPtr(originalGetdentsFD)
				raw := original[*f.OriginalCallID]
				f.OriginalCount = hostVectorPtr(int64(len(raw)))
				f.OriginalSHA256 = hostVectorPtr(HostFactoryRawSHA256(raw))
				f.OriginalEOF = hostVectorPtr(false)
				f.OriginalHashState = "actual_public_bytes"
				native.OriginalScalar = hostVectorPtr(int64(len(raw)))
				if len(raw) == 0 {
					f.OriginalReturnClass = "native_zero_return"
				}
			}
			c := hostVectorChunk(f)
			c.OriginalHandleID = handle
			c.OwnerRole = "host_registrar"
			c.RecordedAt = returned
			raw, e := CanonicalHostFactory(c)
			if e != nil {
				t.Fatal(e)
			}
			sha := HostFactoryRawSHA256(raw)
			g.io[sha] = raw
			children = append(children, sha)
		}
		m := model.HostFactoryCallVectorManifest{Schema: "original_host_factory_call_vector_manifest_v2", Purpose: "original_host_factory_call_vector_manifest_v2", BindingSchema: hostVectorScopeSchema, BindingSHA256: hostVectorSHA(), OwnerRole: "host_registrar", OriginalOwnerID: hostVectorOwner, OwnerPrimitiveRawSHA256: hostVectorSHA(), Operation: op, OriginalHandleID: handle, Level: 0, FirstOrdinal: ords[0], LastOrdinal: ords[len(ords)-1], OriginalCallCount: uint64(len(ords)), ChildBodySHAs: children, CollectionState: "complete_original_calls"}
		raw, e := CanonicalHostFactory(m)
		if e != nil {
			t.Fatal(e)
		}
		sha := HostFactoryRawSHA256(raw)
		g.io[sha] = raw
		r := hostVectorDeclaredRef(op, handle, m.FirstOrdinal, m.LastOrdinal, m.OriginalCallCount)
		r.ManifestRootSHA256 = &sha
		refs = append(refs, r)
	}
	inv := model.HostFactoryHandleCallInventory{Schema: "original_host_factory_handle_call_inventory_v1", Purpose: "original_host_factory_handle_call_inventory_v1", BindingSchema: hostVectorScopeSchema, BindingSHA256: hostVectorSHA(), OwnerRole: "host_registrar", OriginalOwnerID: hostVectorOwner, OwnerPrimitiveRawSHA256: hostVectorPtr(hostVectorSHA()), OriginalHandleID: handle, OriginalAcquisitionState: "original_close_returned", FirstOrdinal: 1, LastOrdinal: 5, OriginalCallCount: 5, OperationVectors: refs, CollectionState: "complete_original_calls", OriginalOperationDeadline: g.record.OriginalOperationDeadline, RecordedAt: hostVectorTime().Add(time.Second)}
	raw, e := CanonicalHostFactory(inv)
	if e != nil {
		t.Fatal(e)
	}
	invSHA := HostFactoryRawSHA256(raw)
	g.io[invSHA] = raw
	task := model.HostFactoryTaskDirectoryRead{SubjectOwnerID: hostVectorSubject, SubjectBootID: p.HostBootID, SubjectPID: p.PID, SubjectStartTicks: p.StartTicks, OwnerPrimitiveRawSHA256: hostVectorSHA(), OriginalHandleID: handle, OriginalDescriptorNumber: fd, OriginalDirectoryStat: stat, OriginalSubjectStatBeforeRead: p.NativeReadOperations[1], OriginalSubjectStatAfterRead: p.NativeReadOperations[4], OriginalOpenCallVector: refs[0], OriginalFstatCallVector: refs[1], OriginalGetdentsCallVector: refs[2], OriginalCloseCallVector: refs[3], OriginalRawBytes: uint64(len(buf)), OriginalRawSHA256: HostFactoryRawSHA256(buf), OriginalTerminalCallID: handle + ":4", ParsedTIDs: []int{17}, ParserClass: "linux_amd64_dirent64_v1", OriginalCalledAt: tm, OriginalReturnedAt: tm.Add(time.Nanosecond), OriginalCloseReturnedAt: tm.Add(2 * time.Nanosecond), OriginalHandleInventorySHA256: invSHA}
	rec := g.record
	rec.ObservationID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	rec.ObservationKind = "task_directory"
	rec.Process = nil
	rec.TaskDirectory = &task
	g.relations[rec.ObservationID] = map[string]string{}
	for _, v := range append(append([]model.HostFactoryCallVectorReference(nil), refs...), task.OriginalSubjectStatBeforeRead.OriginalCallVector, task.OriginalSubjectStatBeforeRead.OriginalCloseCallVector, task.OriginalSubjectStatAfterRead.OriginalCallVector, task.OriginalSubjectStatAfterRead.OriginalCloseCallVector) {
		raw, e := CanonicalHostFactory(v)
		if e != nil {
			t.Fatal(e)
		}
		key := HostFactoryRawSHA256(raw)
		selected := invSHA
		if v.OriginalHandleID != handle {
			selected = g.relations[g.record.ObservationID][key]
		}
		if selected == "" {
			t.Fatal("missing synthetic original vector relation")
		}
		g.relations[rec.ObservationID][key] = selected
	}
	raw, e = CanonicalHostFactory(rec)
	if e != nil {
		t.Fatal(e)
	}
	env, e := SignHostFactoryEnvelope(rec, "host_registrar", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.key)
	if e != nil {
		t.Fatal(e)
	}
	ref := hostVectorNativeReference()
	ref.ObservationID = rec.ObservationID
	ref.ObservationKind = rec.ObservationKind
	ref.OriginalBodySHA256 = HostFactoryRawSHA256(raw)
	ref.OriginalEnvelopeSHA256 = HostFactoryRawSHA256(env)
	g.bodies[ref.OriginalBodySHA256] = raw
	g.envelopes[ref.OriginalEnvelopeSHA256] = env
	return ref, original
}
func TestHostOriginalFactoryNativeTaskOriginalCustody(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(map[string][]byte)
		accepted bool
	}{
		{"synthetic_actual_buffers_graph_ONLY", nil, true},
		{"unknown_nil_buffer_is_not_empty_native_return", func(b map[string][]byte) { b["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:4"] = nil }, false},
		{"missing_original_buffer", func(b map[string][]byte) { delete(b, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:3") }, false},
		{"same_count_changed_kernel_bytes", func(b map[string][]byte) { b["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:3"][19] = '2' }, false},
		{"rendered_names_not_original_buffer", func(b map[string][]byte) { b["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:3"] = []byte("17") }, false},
		{"raw_buffer_cap_plus_one", func(b map[string][]byte) {
			b["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:3"] = bytes.Repeat([]byte("x"), 65537)
		}, false},
		{"terminal_has_unreported_original_bytes", func(b map[string][]byte) { b["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:4"] = []byte{1} }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := hostVectorSyntheticNativeGraph(t)
			ref, raw := hostVectorSyntheticNativeTask(t, &g)
			if c.mutate != nil {
				c.mutate(raw)
			}
			got, e := ResolveHostFactoryNativeObservation(ref, hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.record.OriginalOperationDeadline, g.original, g.observer, g.resolveIO, g.first, func(id string) ([]byte, error) {
				buf, ok := raw[id]
				if !ok {
					return nil, errors.New("unknown original buffer")
				}
				return buf, nil
			}, g.selectedInventory)
			if c.accepted {
				if e != nil || got.TaskDirectory == nil {
					t.Fatalf("whole byte graph %v", e)
				}
			} else {
				hostVectorRefused(t, e)
				if got.TaskDirectory != nil {
					t.Fatal("partial admitted graph")
				}
			}
		})
	}
}
func TestHostOriginalFactoryNativeLeafResolvedIdentity(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*model.HostFactoryNativeLeaf)
		accepted bool
	}{
		{"synthetic_resolved_leaf_graph_ONLY", nil, true},
		{"leaf_bootstrap_from_other_original", func(l *model.HostFactoryNativeLeaf) { l.BootstrapReturnSHA256 = strings.Repeat("d", 64) }, false},
		{"leaf_observed_before_original_return", func(l *model.HostFactoryNativeLeaf) { l.ObservedAt = hostVectorTime() }, false},
		{"leaf_subject_basal_from_other_original", func(l *model.HostFactoryNativeLeaf) { l.SubjectPrimitiveRawSHA256 = strings.Repeat("d", 64) }, false},
		{"leaf_observer_basal_from_other_original", func(l *model.HostFactoryNativeLeaf) { l.ObserverPrimitiveRawSHA256 = strings.Repeat("d", 64) }, false},
		{"leaf_same_actor_not_independent", func(l *model.HostFactoryNativeLeaf) { l.ObserverRole = l.Role }, false},
		{"leaf_foreign_binding_body", func(l *model.HostFactoryNativeLeaf) { l.BindingSHA256 = strings.Repeat("d", 64) }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := hostVectorSyntheticNativeGraph(t)
			task, raw := hostVectorSyntheticNativeTask(t, &g)
			leaf := model.HostFactoryNativeLeaf{Schema: "original_host_factory_native_leaf_v5", Purpose: "original_host_factory_native_leaf_v5", BindingSchema: hostVectorScopeSchema, BindingSHA256: hostVectorSHA(), Role: "host_worker", Process: g.reference, BootstrapReturnSHA256: g.record.Process.BootstrapReturnSHA256, ObservedAt: hostVectorTime().Add(time.Second), SubjectPrimitiveRawSHA256: g.record.SubjectPrimitiveRawSHA256, ObserverRole: "host_registrar", ObserverPrimitiveRawSHA256: g.record.ObserverPrimitiveRawSHA256, OriginalTaskInventoryRead: task}
			if c.mutate != nil {
				c.mutate(&leaf)
			}
			got, e := ResolveHostFactoryNativeAggregate(leaf, hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.record.OriginalOperationDeadline, g.original, g.observer, g.resolveIO, g.first, func(id string) ([]byte, error) {
				buf, ok := raw[id]
				if !ok {
					return nil, errors.New("unknown buffer")
				}
				return buf, nil
			}, g.selectedInventory)
			if c.accepted {
				if e != nil || len(got) != 2 {
					t.Fatalf("resolved original leaf %v", e)
				}
			} else {
				hostVectorRefused(t, e)
				if len(got) != 0 {
					t.Fatal("partial positive aggregate")
				}
			}
		})
	}
}

func (g hostVectorNativeGraph) selectedInventory(observationID string, ref model.HostFactoryCallVectorReference) ([]byte, error) {
	raw, e := CanonicalHostFactory(ref)
	if e != nil {
		return nil, e
	}
	selected, ok := g.relations[observationID][HostFactoryRawSHA256(raw)]
	if !ok {
		return nil, errors.New("synthetic missing immutable observation/vector relation")
	}
	body, ok := g.io[selected]
	if !ok {
		return nil, errors.New("synthetic missing selected inventory")
	}
	return body, nil
}

func TestHostOriginalFactoryNativeSignedPhaseBound(t *testing.T) {
	// These are signed synthetic BYTE graphs, not observations of a process.
	// A later argument must not make an earlier signed phase a new permission.
	cases := []struct {
		name              string
		change            func(time.Time) time.Time
		accepted          bool
		taskDeadlineDelta time.Duration
	}{
		{"exact_original_signed_phase", func(d time.Time) time.Time { return d }, true, 0},
		{"one_nanosecond_later_is_not_original", func(d time.Time) time.Time { return d.Add(time.Nanosecond) }, false, 0},
		{"one_nanosecond_earlier_is_not_original", func(d time.Time) time.Time { return d.Add(-time.Nanosecond) }, false, 0},
		{"binding_declared600_cannot_replace_phase60", func(d time.Time) time.Time { return d.Add(540 * time.Second) }, false, 0},
		{"unavailable_phase_is_not_clock_sample", func(time.Time) time.Time { return time.Time{} }, false, 0},
		{"nonUTC_argument_is_not_original_projection", func(d time.Time) time.Time { return d.In(time.FixedZone("foreign", 3600)) }, false, 0},
		{"signed_sibling_observation_one_nanosecond_later", func(d time.Time) time.Time { return d }, false, time.Nanosecond},
		{"signed_sibling_observation_one_nanosecond_earlier", func(d time.Time) time.Time { return d }, false, -time.Nanosecond},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := hostVectorSyntheticNativeGraph(t)
			task, buffers := hostVectorSyntheticNativeTask(t, &g)
			if c.taskDeadlineDelta != 0 {
				var record model.HostFactoryNativeObservationRecord
				if DecodeHostFactory(g.bodies[task.OriginalBodySHA256], &record) != nil {
					t.Fatal("synthetic original task record missing")
				}
				record.OriginalOperationDeadline = record.OriginalOperationDeadline.Add(c.taskDeadlineDelta)
				raw, err := CanonicalHostFactory(record)
				if err != nil {
					t.Fatal(err)
				}
				envelope, err := SignHostFactoryEnvelope(record, record.ObserverRole, hostVectorOwner, record.BindingSchema, record.BindingSHA256, g.key)
				if err != nil {
					t.Fatal(err)
				}
				task.OriginalBodySHA256, task.OriginalEnvelopeSHA256 = HostFactoryRawSHA256(raw), HostFactoryRawSHA256(envelope)
				g.bodies[task.OriginalBodySHA256], g.envelopes[task.OriginalEnvelopeSHA256] = raw, envelope
			}
			leaf := model.HostFactoryNativeLeaf{Schema: "original_host_factory_native_leaf_v5", Purpose: "original_host_factory_native_leaf_v5", BindingSchema: hostVectorScopeSchema, BindingSHA256: hostVectorSHA(), Role: "host_worker", Process: g.reference, BootstrapReturnSHA256: g.record.Process.BootstrapReturnSHA256, ObservedAt: hostVectorTime().Add(time.Second), SubjectPrimitiveRawSHA256: g.record.SubjectPrimitiveRawSHA256, ObserverRole: "host_registrar", ObserverPrimitiveRawSHA256: g.record.ObserverPrimitiveRawSHA256, OriginalTaskInventoryRead: task}
			out, err := ResolveHostFactoryNativeAggregate(leaf, hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), c.change(g.record.OriginalOperationDeadline), g.original, g.observer, g.resolveIO, g.first, func(id string) ([]byte, error) {
				b, ok := buffers[id]
				if !ok {
					return nil, errors.New("synthetic original buffer missing")
				}
				return b, nil
			}, g.selectedInventory)
			if c.accepted {
				if err != nil || len(out) != 2 {
					t.Fatalf("exact synthetic phase: %v", err)
				}
			} else {
				hostVectorRefused(t, err)
				if len(out) != 0 {
					t.Fatal("phase refusal returned positive partial graph")
				}
			}
		})
	}
}

func TestHostOriginalFactoryNativeGetdentsDescriptorCustody(t *testing.T) {
	for _, c := range []struct {
		name     string
		fd       int
		accepted bool
	}{
		{"same_original_acquired_directory_descriptor", 14, true},
		{"raw_bytes_from_other_descriptor_do_not_join", 16, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := hostVectorSyntheticNativeGraph(t)
			ref, buffers := hostVectorSyntheticNativeTaskDescriptor(t, &g, c.fd)
			out, err := ResolveHostFactoryNativeObservation(ref, hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.record.OriginalOperationDeadline, g.original, g.observer, g.resolveIO, g.first, func(id string) ([]byte, error) {
				b, ok := buffers[id]
				if !ok {
					return nil, errors.New("synthetic original bytes missing")
				}
				return b, nil
			}, g.selectedInventory)
			if c.accepted {
				if err != nil || out.TaskDirectory == nil {
					t.Fatalf("exact synthetic fd graph: %v", err)
				}
			} else {
				hostVectorRefused(t, err)
				if out.TaskDirectory != nil {
					t.Fatal("foreign descriptor returned partial graph")
				}
			}
		})
	}
}

func TestHostOriginalFactoryNativeGetdentsOperationMapping(t *testing.T) {
	cases := []struct {
		name, operation, kind string
		accepted              bool
	}{
		{"existing_getdents_operation_joins_actual_kind", "task_inventory_getdents", "unix_getdents64", true},
		{"fstat_cannot_replace_original_getdents", "task_inventory_getdents", "unix_fstat", false},
		{"open_cannot_replace_original_getdents", "task_inventory_getdents", "unix_open", false},
		{"regular_read_alias_is_not_directory_syscall", "task_inventory_read", "unix_getdents64", false},
		{"getdents_cannot_replace_subject_pin_poll", "native_subject_alive_poll", "unix_getdents64", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			native := hostVectorNativeCall(c.kind)
			err := hostFactoryNativeOperation(c.operation, native)
			if c.accepted {
				if err != nil {
					t.Fatalf("existing operation/kind mapping: %v", err)
				}
			} else {
				hostVectorRefused(t, err)
			}
		})
	}
}

func TestHostOriginalFactoryNativeSelectedInventoryCustody(t *testing.T) {
	cases := []struct {
		name     string
		mode     string
		accepted bool
	}{
		{"exact_observation_vector_relation", "exact", true},
		{"absent_supplier", "absent", false},
		{"unknown_relation_even_with_samehandle", "unknown", false},
		{"nil_is_not_original_inventory", "nil", false},
		{"empty_is_not_original_inventory", "empty", false},
		{"oversize_before_inventory_decode", "oversize", false},
		{"other_handle_whole_inventory", "other", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := hostVectorSyntheticNativeGraph(t)
			supplier := g.selectedInventory
			switch c.mode {
			case "absent":
				supplier = nil
			case "unknown":
				supplier = func(string, model.HostFactoryCallVectorReference) ([]byte, error) {
					return nil, errors.New("no immutable publication relation")
				}
			case "nil":
				supplier = func(string, model.HostFactoryCallVectorReference) ([]byte, error) { return nil, nil }
			case "empty":
				supplier = func(string, model.HostFactoryCallVectorReference) ([]byte, error) { return []byte{}, nil }
			case "oversize":
				supplier = func(string, model.HostFactoryCallVectorReference) ([]byte, error) {
					return bytes.Repeat([]byte("x"), 65537), nil
				}
			case "other":
				supplier = func(observation string, v model.HostFactoryCallVectorReference) ([]byte, error) {
					for _, sha := range g.record.Process.NativeHandleInventorySHAs {
						var inv model.HostFactoryHandleCallInventory
						if DecodeHostFactory(g.io[sha], &inv) == nil && inv.OriginalHandleID != v.OriginalHandleID {
							return g.io[sha], nil
						}
					}
					return nil, errors.New("synthetic other inventory unavailable")
				}
			}
			out, err := ResolveHostFactoryNativeObservation(g.reference, hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.record.OriginalOperationDeadline, g.original, g.observer, g.resolveIO, g.first, func(string) ([]byte, error) { return nil, errors.New("not a task graph") }, supplier)
			if c.accepted {
				if err != nil || !reflect.DeepEqual(out, g.record) {
					t.Fatalf("exact custody %v", err)
				}
			} else {
				hostVectorRefused(t, err)
				if out.Process != nil {
					t.Fatal("custody refusal returned partial graph")
				}
			}
		})
	}
}

func TestHostOriginalFactoryNativeOriginalNamespaceSupplier(t *testing.T) {
	// The compiler-owned supplier must authenticate the actual original namespace.
	// This deliberately refuses missing lineage; a signature cannot approve it.
	for _, binding := range []string{hostVectorRootSchema, hostVectorOrdinarySchema} {
		t.Run("unapproved_ancestor_"+binding, func(t *testing.T) {
			g := hostVectorSyntheticNativeGraph(t)
			g.record.BindingSchema = binding
			raw, err := CanonicalHostFactory(g.record)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := SignHostFactoryEnvelope(g.record, "host_registrar", hostVectorOwner, binding, hostVectorSHA(), g.key)
			if err != nil {
				t.Fatal(err)
			}
			g.reference.OriginalBodySHA256 = HostFactoryRawSHA256(raw)
			g.reference.OriginalEnvelopeSHA256 = HostFactoryRawSHA256(envelope)
			g.bodies[g.reference.OriginalBodySHA256] = raw
			g.envelopes[g.reference.OriginalEnvelopeSHA256] = envelope
			called := false
			out, err := ResolveHostFactoryNativeObservation(g.reference, hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.record.OriginalOperationDeadline, g.original, func(role, key, owner, basal, actualBinding, actualSHA string) (ed25519.PublicKey, error) {
				called = true
				if actualBinding != binding || actualSHA != hostVectorSHA() {
					t.Fatal("original namespace was rebound before Source supplier")
				}
				return nil, ErrHostFactorySourceUnavailable
			}, g.resolveIO, g.first, func(string) ([]byte, error) { return nil, errors.New("unavailable") }, g.selectedInventory)
			hostVectorRefused(t, err)
			if !called || out.Process != nil {
				t.Fatal("missing ancestry must be checked and HOLD without partial graph")
			}
		})
	}
}

func TestHostOriginalFactoryNativeManifestOriginalChronology(t *testing.T) {
	cases := []struct {
		name     string
		change   func(*model.HostFactoryNativeObservationManifest)
		accepted bool
	}{
		{"original_completed_before_manifest", nil, true},
		{"manifest_recorded_before_original_thread_return", func(m *model.HostFactoryNativeObservationManifest) { m.RecordedAt = hostVectorTime() }, false},
		{"manifest_original_deadline_is_not_phase", func(m *model.HostFactoryNativeObservationManifest) {
			m.OriginalOperationDeadline = m.OriginalOperationDeadline.Add(time.Nanosecond)
		}, false},
		{"manifest_recorded_after_original_deadline", func(m *model.HostFactoryNativeObservationManifest) {
			m.RecordedAt = m.OriginalOperationDeadline.Add(time.Nanosecond)
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g, ref := hostVectorSyntheticThreadCollection(t)
			var node model.HostFactoryNativeObservationManifest
			if DecodeHostFactory(g.bodies[ref.ManifestRootBodySHA256], &node) != nil {
				t.Fatal("synthetic original manifest")
			}
			if c.change != nil {
				c.change(&node)
			}
			// json.Marshal retains the declared late original. The consumer must refuse
			// it; the fixture must not repair the timestamp to make encoding succeed.
			raw, err := json.Marshal(node)
			if err != nil {
				t.Fatal(err)
			}
			if c.name == "manifest_recorded_after_original_deadline" {
				ref.ManifestRootBodySHA256 = HostFactoryRawSHA256(raw)
				g.bodies[ref.ManifestRootBodySHA256] = raw
			} else {
				envelope, err := SignHostFactoryEnvelope(node, "host_registrar", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.key)
				if err != nil {
					t.Fatal(err)
				}
				ref.ManifestRootBodySHA256 = HostFactoryRawSHA256(raw)
				ref.ManifestRootEnvelopeSHA256 = HostFactoryRawSHA256(envelope)
				g.bodies[ref.ManifestRootBodySHA256] = raw
				g.envelopes[ref.ManifestRootEnvelopeSHA256] = envelope
			}
			out, err := ResolveHostFactoryNativeCollection(ref, hostVectorOwner, g.record.OriginalOperationDeadline, g.original, g.observer, g.resolveIO, g.first, func(string) ([]byte, error) { return nil, errors.New("not getdents") }, g.selectedInventory)
			if c.accepted {
				if err != nil || len(out) != 1 {
					t.Fatalf("synthetic chronological graph %v", err)
				}
			} else {
				hostVectorRefused(t, err)
				if len(out) != 0 {
					t.Fatal("late/uncertain graph escaped")
				}
			}
		})
	}
}

func TestHostOriginalFactoryNativeAliveResolvedTimeBound(t *testing.T) {
	// This boundary test supplies synthetic PRE-resolved views only. It tests
	// temporal relationships, not a complete resolver/source/native approval.
	// Whole byte/custody/signature graphs are exercised separately above.
	cases := []struct {
		name     string
		subject  int
		late     bool
		accepted bool
	}{
		{"all_selected_reads_inside_original_phase_interval", -1, false, true},
		{"old_worker_read_cannot_be_current", 0, false, false},
		{"old_exterior_read_cannot_be_current", 1, false, false},
		{"old_registrar_read_cannot_be_current", 2, false, false},
		{"worker_pin_after_original_readclose", 0, true, false},
		{"exterior_pin_after_original_readclose", 1, true, false},
		{"registrar_pin_after_original_readclose", 2, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tm := hostVectorTime()
			ids := []string{hostVectorHandle, "66666666-6666-4666-8666-666666666666", "77777777-7777-4777-8777-777777777777"}
			roles := []string{"host_worker", "host_exterior", "host_registrar"}
			pids := []int{17, 10, 18}
			parents := []int{10, 1, 10}
			graph := hostFactoryNativeGraph{deadline: tm.Add(60 * time.Second), records: map[string]model.HostFactoryNativeObservationRecord{}, refs: map[string]model.HostFactoryNativeObservationReference{}}
			refs := make([]model.HostFactoryNativeObservationReference, 3)
			for i := range ids {
				p := hostVectorNativeDeclaredBytes()
				p.PID = pids[i]
				p.PPID = parents[i]
				p.OriginalNativeReadStartedAt = tm
				p.OriginalSubjectNativePin.OriginalObservedAt = tm.Add(20 * time.Nanosecond)
				if i == c.subject {
					if c.late {
						p.OriginalSubjectNativePin.OriginalObservedAt = tm.Add(21 * time.Nanosecond)
					} else {
						p.OriginalNativeReadStartedAt = tm.Add(-time.Nanosecond)
					}
				}
				ref := hostVectorNativeReference()
				ref.ObservationID = ids[i]
				refs[i] = ref
				record := hostVectorNativeRecord()
				record.ObservationID = ids[i]
				record.SubjectRole = roles[i]
				record.Process = &p
				graph.refs[ids[i]] = ref
				graph.records[ids[i]] = record
			}
			body := model.HostFactoryAliveNativeRead{Worker: refs[0], Exterior: refs[1], Registrar: refs[2], OriginalReadStartedAt: tm, OriginalReadReturnedAt: tm.Add(15 * time.Nanosecond), OriginalReadCloseReturnedAt: tm.Add(20 * time.Nanosecond), ObservedAt: tm.Add(25 * time.Nanosecond)}
			err := graph.aggregate(body)
			if c.accepted {
				if err != nil {
					t.Fatalf("pre-resolved time boundary: %v", err)
				}
			} else {
				hostVectorRefused(t, err)
			}
		})
	}
}

// These are Source-only grammar/crypto/immutable-callback vectors. They provide
// no real syscall, approved source inventory, native epoch or SQL FIRST proof.
// They are authored for CI only and must never run on the owner's machine.
func hostProfileTestKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, ed25519.SeedSize))
}

func hostProfileTestChunk(state string) (model.HostFactoryCallVectorChunk, []HostFactorySourceCallPurpose) {
	fact := hostVectorPrimitive("boot_id_read", 1, state)
	fact.SubjectOwnerID = hostVectorOwner
	chunk := hostVectorChunk(fact)
	return chunk, []HostFactorySourceCallPurpose{{*fact.OriginalCallID, "host_exterior", "worker_start"}}
}

func TestHostFactorySourceProfileManifest(t *testing.T) {
	p := ProposedHostFactorySourceProfileV1()
	raw, err := p.Manifest()
	if err != nil || HostFactoryRawSHA256(raw) != hostFactorySourceProfileSHA {
		t.Fatalf("fixed proposed manifest: %v", err)
	}
	var manifest HostFactorySourceProfileManifest
	if p.Decode(raw, &manifest) != nil || len(manifest.ExactTuples) != 51 {
		t.Fatal("exact tuple roster changed")
	}
	for index, tuple := range manifest.ExactTuples {
		t.Run(fmt.Sprintf("tuple_%02d_%s_%s_%s", index, tuple.Operation, tuple.OwnerRole, tuple.Stage), func(t *testing.T) {
			if p.ValidateOperation(tuple.Operation, tuple.OwnerRole, tuple.SubjectRole, tuple.Stage, tuple.BindingSchema, tuple.EnvelopeType, tuple.NativeKind) != nil {
				t.Fatal("exact proposed tuple refused")
			}
			hostVectorRefused(t, ValidateHostFactoryOperation(tuple.Operation, tuple.OwnerRole, tuple.SubjectRole, tuple.Stage, tuple.BindingSchema, tuple.EnvelopeType))
			hostVectorRefused(t, p.ValidateOperation(tuple.Operation, tuple.OwnerRole, tuple.SubjectRole, tuple.Stage, hostVectorOrdinarySchema, tuple.EnvelopeType, tuple.NativeKind))
			foreignOwner := "host_worker"
			if index >= 41 {
				// Worker-owned cleanup is an EXISTING valid base tuple. A new
				// exterior cleanup declaration cannot remove that old permission.
				foreignOwner = "host_core_issuer"
			}
			hostVectorRefused(t, p.ValidateOperation(tuple.Operation, foreignOwner, tuple.SubjectRole, tuple.Stage, tuple.BindingSchema, tuple.EnvelopeType, tuple.NativeKind))
			hostVectorRefused(t, p.ValidateOperation(tuple.Operation, tuple.OwnerRole, tuple.SubjectRole, "future_start", tuple.BindingSchema, tuple.EnvelopeType, tuple.NativeKind))
			wrong := "unknown_kind"
			hostVectorRefused(t, p.ValidateOperation(tuple.Operation, tuple.OwnerRole, tuple.SubjectRole, tuple.Stage, tuple.BindingSchema, tuple.EnvelopeType, &wrong))
		})
	}
	t.Run("copy_does_not_mutate_manifest", func(t *testing.T) {
		raw[0] = '['
		again, err := p.Manifest()
		if err != nil || again[0] != '{' {
			t.Fatal("manifest shares caller storage")
		}
	})
	t.Run("zero_and_foreign_profile", func(t *testing.T) {
		for _, profile := range []*HostFactorySourceProfile{nil, {}, {identity: hostFactorySourceProfileSHA}} {
			_, err := profile.Identity()
			hostVectorRefused(t, err)
			_, err = profile.Canonical(hostVectorChoice())
			hostVectorRefused(t, err)
		}
	})
	t.Run("default_catalog_still_empty", func(t *testing.T) {
		_, err := ApprovedHostFactorySource()
		if !errors.Is(err, ErrHostFactorySourceUnavailable) {
			t.Fatal("preparation grammar changed approved registry")
		}
	})
	t.Run("default_rejects_new_closed_types", func(t *testing.T) {
		hostVectorRefused(t, DecodeHostFactory([]byte(hostFactorySourceProfileManifestRaw), &manifest))
		_, err := CanonicalHostFactory(manifest)
		hostVectorRefused(t, err)
	})
}

func TestHostFactorySourceProfileClosedPurposeBytes(t *testing.T) {
	p := ProposedHostFactorySourceProfileV1()
	_, entries := hostProfileTestChunk("returned")
	set := HostFactorySourcePurposeSet{hostFactorySourcePurposeSchema, hostVectorSHA(), entries}
	raw, err := p.Canonical(set)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		raw  []byte
	}{
		{"omitted_stage", bytes.Replace(raw, []byte(`,"stage":"worker_start"`), nil, 1)},
		{"null_stage", bytes.Replace(raw, []byte(`"stage":"worker_start"`), []byte(`"stage":null`), 1)},
		{"case_alias", bytes.Replace(raw, []byte(`"stage":`), []byte(`"Stage":`), 1)},
		{"duplicate_stage", bytes.Replace(raw, []byte(`"stage":`), []byte(`"stage":"worker_start","stage":`), 1)},
		{"unknown_field", append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"native_complete":true}`)...)},
		{"unknown_role", bytes.Replace(raw, []byte("host_exterior"), []byte("caller"), 1)},
		{"unknown_stage", bytes.Replace(raw, []byte("worker_start"), []byte("future_start"), 1)},
		{"noncanonical_ordinal", bytes.Replace(raw, []byte(":1\""), []byte(":01\""), 1)},
		{"null_list", []byte(`{"schema":"` + hostFactorySourcePurposeSchema + `","original_body_sha256":"` + hostVectorSHA() + `","original_call_purposes":null}`)},
		{"duplicate_call", hostVectorJSON(t, HostFactorySourcePurposeSet{hostFactorySourcePurposeSchema, hostVectorSHA(), append(entries, entries[0])})},
		{"trailing_newline", append(append([]byte{}, raw...), '\n')},
		{"cap_plus_one", bytes.Repeat([]byte{'x'}, hostFactoryLimit+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var decoded HostFactorySourcePurposeSet
			hostVectorRefused(t, p.Decode(tc.raw, &decoded))
		})
	}
	t.Run("canonical_roundtrip", func(t *testing.T) {
		var decoded HostFactorySourcePurposeSet
		if p.Decode(raw, &decoded) != nil || !reflect.DeepEqual(decoded, set) {
			t.Fatal("exact metadata changed")
		}
	})
}

func TestHostFactorySourceProfileScopedDomains(t *testing.T) {
	p := ProposedHostFactorySourceProfileV1()
	key := hostProfileTestKey()
	public := key.Public().(ed25519.PublicKey)
	body := hostVectorChoice()
	envelope, err := p.SignEnvelope(body, []HostFactorySourceCallPurpose{}, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
	if err != nil {
		t.Fatal(err)
	}
	var decoded model.HostFactoryUnissuedChoiceBody
	t.Run("profile_roundtrip", func(t *testing.T) {
		purposes, err := p.VerifyEnvelope(envelope, &decoded, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), public)
		if err != nil || purposes == nil || len(purposes) != 0 || !reflect.DeepEqual(decoded, body) {
			t.Fatal("profile domain changed exact body")
		}
	})
	t.Run("default_rejects_profile_domain", func(t *testing.T) {
		hostVectorRefused(t, VerifyHostFactoryEnvelope(envelope, &decoded, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), public))
		var old model.HostFactorySignedEnvelope
		hostVectorRefused(t, DecodeHostFactory(envelope, &old))
	})
	t.Run("profile_rejects_old_scope_domain", func(t *testing.T) {
		old, err := SignHostFactoryEnvelope(body, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = p.VerifyEnvelope(old, &decoded, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), public)
		hostVectorRefused(t, err)
	})
	t.Run("profile_hash_tamper", func(t *testing.T) {
		bad := bytes.Replace(envelope, []byte(hostFactorySourceProfileSHA), []byte(strings.Repeat("f", 64)), 1)
		_, err := p.VerifyEnvelope(bad, &decoded, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), public)
		hostVectorRefused(t, err)
	})
	t.Run("wrong_key", func(t *testing.T) {
		wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{18}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
		_, err := p.VerifyEnvelope(envelope, &decoded, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), wrong)
		hostVectorRefused(t, err)
	})
	t.Run("purpose_metadata_tamper", func(t *testing.T) {
		var e HostFactorySourceSignedEnvelope
		if p.Decode(envelope, &e) != nil {
			t.Fatal("source envelope")
		}
		set := HostFactorySourcePurposeSet{hostFactorySourcePurposeSchema, hostVectorSHA(), []HostFactorySourceCallPurpose{}}
		e.OriginalPurposeBase64 = base64.StdEncoding.EncodeToString(hostVectorJSON(t, set))
		_, err := p.VerifyEnvelope(hostVectorJSON(t, e), &decoded, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), public)
		hostVectorRefused(t, err)
	})
	t.Run("legacy_Root_exact_bytes_and_no_metadata", func(t *testing.T) {
		chunk, _ := hostProfileTestChunk("returned")
		chunk.BindingSchema = hostVectorRootSchema
		old, err := SignHostFactoryEnvelope(chunk, "host_exterior", hostVectorOwner, hostVectorRootSchema, hostVectorSHA(), key)
		if err != nil {
			t.Fatal(err)
		}
		throughProfile, err := p.SignEnvelope(chunk, []HostFactorySourceCallPurpose{}, "host_exterior", hostVectorOwner, hostVectorRootSchema, hostVectorSHA(), key)
		if err != nil || !bytes.Equal(old, throughProfile) {
			t.Fatal("legacy ancestor bytes changed")
		}
		_, err = p.SignEnvelope(chunk, nil, "host_exterior", hostVectorOwner, hostVectorRootSchema, hostVectorSHA(), key)
		hostVectorRefused(t, err)
	})
	t.Run("existing_Core_issuer_Scope_roundtrip", func(t *testing.T) {
		reservation := hostVectorReservation()
		env, err := p.SignEnvelope(reservation, []HostFactorySourceCallPurpose{}, "host_core_issuer", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		var out model.HostFactoryUnissuedChoiceReservation
		purposes, verifyErr := p.VerifyEnvelope(env, &out, "host_core_issuer", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), public)
		if err != nil || verifyErr != nil || purposes == nil || len(purposes) != 0 || !reflect.DeepEqual(out, reservation) {
			t.Fatalf("existing issuer role excluded: %v/%v", err, verifyErr)
		}
		hostVectorRefused(t, VerifyHostFactoryEnvelope(env, &out, "host_core_issuer", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), public))
	})
	t.Run("issuer_role_cannot_sign_worker_BODY", func(t *testing.T) {
		_, err := p.SignEnvelope(body, []HostFactorySourceCallPurpose{}, "host_core_issuer", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		hostVectorRefused(t, err)
	})
	t.Run("issuer_role_cannot_sign_IO_chunk", func(t *testing.T) {
		chunk, entries := hostProfileTestChunk("returned")
		_, err := p.SignEnvelope(chunk, entries, "host_core_issuer", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		hostVectorRefused(t, err)
	})
}

func TestHostFactorySourceProfilePerCallPurpose(t *testing.T) {
	p := ProposedHostFactorySourceProfileV1()
	key := hostProfileTestKey()
	chunk, entries := hostProfileTestChunk("returned")
	cases := []struct {
		name    string
		entries []HostFactorySourceCallPurpose
	}{
		{"nil_unknown", nil},
		{"empty_missing_call", []HostFactorySourceCallPurpose{}},
		{"duplicate_orphan", append(append([]HostFactorySourceCallPurpose{}, entries...), entries[0])},
		{"foreign_call_id", []HostFactorySourceCallPurpose{{hostVectorSubject + ":1", "host_exterior", "worker_start"}}},
		{"wrong_stage", []HostFactorySourceCallPurpose{{entries[0].OriginalCallID, "host_exterior", "worker_bootstrap"}}},
		{"wrong_subject_role", []HostFactorySourceCallPurpose{{entries[0].OriginalCallID, "host_worker", "worker_start"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := p.SignEnvelope(chunk, tc.entries, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
			hostVectorRefused(t, err)
		})
	}
	t.Run("pending_returned_purpose_immutable", func(t *testing.T) {
		pending, prior := hostProfileTestChunk("called_pending")
		if p.ValidatePendingSuccessor(pending, chunk, prior, entries) != nil {
			t.Fatal("exact request/purpose successor")
		}
		mutated := append([]HostFactorySourceCallPurpose{}, entries...)
		mutated[0].Stage = "worker_exterior_join"
		hostVectorRefused(t, p.ValidatePendingSuccessor(pending, chunk, prior, mutated))
	})
	t.Run("same_handle_distinct_original_stages", func(t *testing.T) {
		second := hostVectorPrimitive("boot_id_read", 2, "returned")
		second.SubjectOwnerID = hostVectorOwner
		chunk.OriginalCalls = append(chunk.OriginalCalls, second)
		chunk.LastOrdinal = 2
		mixed := append(append([]HostFactorySourceCallPurpose{}, entries...), HostFactorySourceCallPurpose{*second.OriginalCallID, "host_exterior", "worker_exterior_join"})
		env, err := p.SignEnvelope(chunk, mixed, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		var target model.HostFactoryCallVectorChunk
		got, verifyErr := p.VerifyEnvelope(env, &target, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key.Public().(ed25519.PublicKey))
		if err != nil || verifyErr != nil || !reflect.DeepEqual(got, mixed) || !reflect.DeepEqual(target, chunk) {
			t.Fatal("earlier call metadata was rewritten")
		}
	})
	t.Run("same_CallID_pending_returned_metadata_conflict", func(t *testing.T) {
		pending, oldPurposes := hostProfileTestChunk("called_pending")
		oldRaw := hostVectorJSON(t, pending)
		oldEnv, err := p.SignEnvelope(pending, oldPurposes, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		changed := append([]HostFactorySourceCallPurpose{}, entries...)
		changed[0].Stage = "worker_exterior_join"
		newEnv, err2 := p.SignEnvelope(chunk, changed, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		if err != nil || err2 != nil {
			t.Fatal("individually declared synthetic domains")
		}
		r := &hostFactorySourceIOReader{profile: p, cache: map[string]hostFactorySourceOriginalIO{}, callPurpose: map[string]hostFactorySourceCallIdentity{}, originals: HostFactorySourceResolvers{TrustedOwner: func(string, string, string, string, string, string) (ed25519.PublicKey, error) {
			return key.Public().(ed25519.PublicKey), nil
		}}}
		if _, err := r.authenticate(oldRaw, oldEnv, HostFactoryRawSHA256(oldRaw)); err != nil {
			t.Fatal(err)
		}
		newRaw := hostVectorJSON(t, chunk)
		_, err = r.authenticate(newRaw, newEnv, HostFactoryRawSHA256(newRaw))
		hostVectorRefused(t, err)
		if r.callPurpose[entries[0].OriginalCallID].purpose.Stage != "worker_start" {
			t.Fatal("conflict overwrote original purpose")
		}
	})
	t.Run("same_CallID_same_pending_returned_purpose", func(t *testing.T) {
		pending, oldPurposes := hostProfileTestChunk("called_pending")
		oldRaw := hostVectorJSON(t, pending)
		newRaw := hostVectorJSON(t, chunk)
		oldEnv, err := p.SignEnvelope(pending, oldPurposes, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		newEnv, err2 := p.SignEnvelope(chunk, entries, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		if err != nil || err2 != nil {
			t.Fatal("synthetic successor signatures")
		}
		r := &hostFactorySourceIOReader{profile: p, cache: map[string]hostFactorySourceOriginalIO{}, callPurpose: map[string]hostFactorySourceCallIdentity{}, originals: HostFactorySourceResolvers{TrustedOwner: func(string, string, string, string, string, string) (ed25519.PublicKey, error) {
			return key.Public().(ed25519.PublicKey), nil
		}}}
		if _, err := r.authenticate(oldRaw, oldEnv, HostFactoryRawSHA256(oldRaw)); err != nil {
			t.Fatal(err)
		}
		if _, err := r.authenticate(newRaw, newEnv, HostFactoryRawSHA256(newRaw)); err != nil {
			t.Fatal(err)
		}
	})
}

func TestHostFactorySourceProfileOriginalPairs(t *testing.T) {
	p := ProposedHostFactorySourceProfileV1()
	key := hostProfileTestKey()
	public := key.Public().(ed25519.PublicKey)
	chunk, entries := hostProfileTestChunk("returned")
	chunkRaw := hostVectorJSON(t, chunk)
	chunkSHA := HostFactoryRawSHA256(chunkRaw)
	chunkEnv, err := p.SignEnvelope(chunk, entries, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
	if err != nil {
		t.Fatal(err)
	}
	manifest := model.HostFactoryCallVectorManifest{Schema: "original_host_factory_call_vector_manifest_v2", Purpose: "original_host_factory_call_vector_manifest_v2", BindingSchema: hostVectorScopeSchema, BindingSHA256: hostVectorSHA(), OwnerRole: "host_exterior", OriginalOwnerID: hostVectorOwner, OwnerPrimitiveRawSHA256: hostVectorSHA(), Operation: "boot_id_read", OriginalHandleID: hostVectorHandle, Level: 0, FirstOrdinal: 1, LastOrdinal: 1, OriginalCallCount: 1, ChildBodySHAs: []string{chunkSHA}, CollectionState: "complete_original_calls"}
	manifestRaw := hostVectorJSON(t, manifest)
	manifestSHA := HostFactoryRawSHA256(manifestRaw)
	manifestEnv, err := p.SignEnvelope(manifest, []HostFactorySourceCallPurpose{}, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
	if err != nil {
		t.Fatal(err)
	}
	ref := hostVectorReference("boot_id_read")
	ref.SubjectOwnerID = hostVectorOwner
	ref.OwnerPrimitiveRawSHA256 = hostVectorPtr(hostVectorSHA())
	ref.ManifestRootSHA256 = &manifestSHA
	ref.FirstOrdinal, ref.LastOrdinal, ref.OriginalCallCount = 1, 1, 1
	base := HostFactorySourceResolvers{
		IO: func(sha string) ([]byte, []byte, error) {
			if sha == chunkSHA {
				return chunkRaw, chunkEnv, nil
			}
			if sha == manifestSHA {
				return manifestRaw, manifestEnv, nil
			}
			return nil, nil, ErrHostFactorySourceRefused
		},
		TrustedOwner: func(role, keyID, owner, primitive, binding, bindingSHA string) (ed25519.PublicKey, error) {
			if role != "host_exterior" || keyID != hostVectorOwner || owner != hostVectorOwner || primitive != hostVectorSHA() || binding != hostVectorScopeSchema || bindingSHA != hostVectorSHA() {
				return nil, ErrHostFactorySourceRefused
			}
			return public, nil // Explicit synthetic Source grammar key, not approval.
		},
		Predecessor: func(sha string, index uint32) ([]byte, []byte, uint32, error) {
			if sha != chunkSHA || index != 0 {
				return nil, nil, 0, ErrHostFactorySourceRefused
			}
			return nil, nil, 0, nil // Explicit synthetic FIRST, never an SQL proof.
		},
	}
	t.Run("exact_original_pairs", func(t *testing.T) {
		if p.ValidateCallVector(ref, base) != nil {
			t.Fatal("exact Source-only original pairs refused")
		}
	})
	t.Run("body_envelope_mismatch", func(t *testing.T) {
		changed := base
		changed.IO = func(sha string) ([]byte, []byte, error) { return chunkRaw, manifestEnv, nil }
		hostVectorRefused(t, p.ValidateCallVector(ref, changed))
	})
	t.Run("missing_original_envelope", func(t *testing.T) {
		changed := base
		changed.IO = func(sha string) ([]byte, []byte, error) { return manifestRaw, nil, nil }
		hostVectorRefused(t, p.ValidateCallVector(ref, changed))
	})
	t.Run("unapproved_owner_callback", func(t *testing.T) {
		changed := base
		changed.TrustedOwner = func(string, string, string, string, string, string) (ed25519.PublicKey, error) {
			return nil, ErrHostFactorySourceUnavailable
		}
		hostVectorRefused(t, p.ValidateCallVector(ref, changed))
	})
	t.Run("missing_FIRST_relation", func(t *testing.T) {
		changed := base
		changed.Predecessor = func(string, uint32) ([]byte, []byte, uint32, error) { return nil, nil, 0, ErrHostFactorySourceRefused }
		hostVectorRefused(t, p.ValidateCallVector(ref, changed))
	})
	t.Run("unknown_empty_not_FIRST", func(t *testing.T) {
		changed := base
		changed.Predecessor = func(string, uint32) ([]byte, []byte, uint32, error) { return []byte{}, []byte{}, 0, nil }
		hostVectorRefused(t, p.ValidateCallVector(ref, changed))
	})
	t.Run("missing_callback", func(t *testing.T) {
		changed := base
		changed.Predecessor = nil
		hostVectorRefused(t, p.ValidateCallVector(ref, changed))
	})
	t.Run("oversize_original_envelope", func(t *testing.T) {
		changed := base
		changed.IO = func(string) ([]byte, []byte, error) {
			return manifestRaw, bytes.Repeat([]byte{'x'}, hostFactoryLimit+1), nil
		}
		hostVectorRefused(t, p.ValidateCallVector(ref, changed))
	})
	t.Run("actual_model_fields_unchanged", func(t *testing.T) {
		raw, err := json.Marshal(chunk)
		if err != nil || !bytes.Equal(raw, chunkRaw) {
			t.Fatal("original BODY was rewritten")
		}
	})
}

// Adapt the existing synthetic byte graph to declared Source-purpose vectors.
// This is test construction, never an inference of actual producer stages.
func hostProfileSyntheticNativePairs(t *testing.T) (hostVectorNativeGraph, model.HostFactoryNativeObservationReference, HostFactorySourceResolvers) {
	t.Helper()
	p := ProposedHostFactorySourceProfileV1()
	g := hostVectorSyntheticNativeGraph(t)
	task, rawBuffers := hostVectorSyntheticNativeTask(t, &g)
	ioEnvelopes := map[string][]byte{}
	for sha, raw := range g.io {
		var header struct {
			Schema string `json:"schema"`
		}
		if json.Unmarshal(raw, &header) != nil {
			t.Fatal("synthetic IO header")
		}
		var body any
		purposes := []HostFactorySourceCallPurpose{}
		switch header.Schema {
		case "original_host_factory_call_vector_chunk_v2":
			var chunk model.HostFactoryCallVectorChunk
			if DecodeHostFactory(raw, &chunk) != nil {
				t.Fatal("synthetic chunk")
			}
			for _, fact := range chunk.OriginalCalls {
				stage := "native_alive"
				if fact.Operation == "native_subject_pidfd_open" {
					stage = "worker_start" // Declared synthetic acquisition phase.
				}
				purposes = append(purposes, HostFactorySourceCallPurpose{*fact.OriginalCallID, "host_worker", stage})
			}
			body = chunk
		case "original_host_factory_call_vector_manifest_v2":
			var value model.HostFactoryCallVectorManifest
			if DecodeHostFactory(raw, &value) != nil {
				t.Fatal("synthetic manifest")
			}
			body = value
		case "original_host_factory_handle_call_inventory_v1":
			var value model.HostFactoryHandleCallInventory
			if DecodeHostFactory(raw, &value) != nil {
				t.Fatal("synthetic inventory")
			}
			body = value
		default:
			t.Fatalf("unknown synthetic IO schema %s", header.Schema)
		}
		envelope, err := p.SignEnvelope(body, purposes, "host_registrar", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.key)
		if err != nil {
			t.Fatalf("declared synthetic profile IO %s: %v", sha, err)
		}
		ioEnvelopes[sha] = envelope
	}
	for _, ref := range []*model.HostFactoryNativeObservationReference{&g.reference, &task} {
		var record model.HostFactoryNativeObservationRecord
		if DecodeHostFactory(g.bodies[ref.OriginalBodySHA256], &record) != nil {
			t.Fatal("synthetic record")
		}
		envelope, err := p.SignEnvelope(record, []HostFactorySourceCallPurpose{}, "host_registrar", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.key)
		if err != nil {
			t.Fatal(err)
		}
		ref.OriginalEnvelopeSHA256 = HostFactoryRawSHA256(envelope)
		g.envelopes[ref.OriginalEnvelopeSHA256] = envelope
	}
	callbacks := HostFactorySourceResolvers{
		Original: g.original, TrustedOwner: g.observer,
		IO: func(sha string) ([]byte, []byte, error) {
			body, err := g.resolveIO(sha)
			envelope, known := ioEnvelopes[sha]
			if err != nil || !known {
				return nil, nil, ErrHostFactorySourceRefused
			}
			return body, envelope, nil
		},
		Predecessor: func(sha string, index uint32) ([]byte, []byte, uint32, error) {
			body, previousIndex, err := g.first(sha, index)
			if err != nil || body != nil {
				return nil, nil, 0, ErrHostFactorySourceRefused
			}
			return nil, nil, previousIndex, nil // Synthetic explicit FIRST only.
		},
		GetdentsOriginal: func(id string) ([]byte, error) {
			buf, known := rawBuffers[id]
			if !known {
				return nil, ErrHostFactorySourceRefused
			}
			return buf, nil
		},
		Inventory: func(observation string, ref model.HostFactoryCallVectorReference) ([]byte, []byte, error) {
			body, err := g.selectedInventory(observation, ref)
			if err != nil {
				return nil, nil, err
			}
			envelope, known := ioEnvelopes[HostFactoryRawSHA256(body)]
			if !known {
				return nil, nil, ErrHostFactorySourceRefused
			}
			return body, envelope, nil
		},
	}
	return g, task, callbacks
}

func TestHostFactorySourceProfileNativeResolverPropagation(t *testing.T) {
	t.Run("synthetic_whole_observation_profile_only", func(t *testing.T) {
		g, _, callbacks := hostProfileSyntheticNativePairs(t)
		got, err := ProposedHostFactorySourceProfileV1().ResolveNativeObservation(g.reference, hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.record.OriginalOperationDeadline, callbacks)
		if err != nil || !reflect.DeepEqual(got, g.record) {
			t.Fatalf("synthetic complete profile graph %v", err)
		}
	})
	t.Run("default_native_resolver_refuses_profile_envelope", func(t *testing.T) {
		g, _, _ := hostProfileSyntheticNativePairs(t)
		_, err := ResolveHostFactoryNativeObservation(g.reference, hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.record.OriginalOperationDeadline, g.original, g.observer, g.resolveIO, g.first, func(string) ([]byte, error) { return nil, ErrHostFactorySourceRefused }, g.selectedInventory)
		hostVectorRefused(t, err)
	})
	t.Run("missing_inventory_original_envelope", func(t *testing.T) {
		g, _, callbacks := hostProfileSyntheticNativePairs(t)
		original := callbacks.Inventory
		callbacks.Inventory = func(id string, ref model.HostFactoryCallVectorReference) ([]byte, []byte, error) {
			body, _, err := original(id, ref)
			return body, nil, err
		}
		_, err := ProposedHostFactorySourceProfileV1().ResolveNativeObservation(g.reference, hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.record.OriginalOperationDeadline, callbacks)
		hostVectorRefused(t, err)
	})
	t.Run("actual_missing_Source_owner_stays_HOLD", func(t *testing.T) {
		g, _, callbacks := hostProfileSyntheticNativePairs(t)
		callbacks.TrustedOwner = func(string, string, string, string, string, string) (ed25519.PublicKey, error) {
			return nil, ErrHostFactorySourceUnavailable
		}
		_, err := ProposedHostFactorySourceProfileV1().ResolveNativeObservation(g.reference, hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.record.OriginalOperationDeadline, callbacks)
		hostVectorRefused(t, err)
	})
	t.Run("synthetic_leaf_whole_task_and_raw_custody", func(t *testing.T) {
		g, task, callbacks := hostProfileSyntheticNativePairs(t)
		leaf := model.HostFactoryNativeLeaf{Schema: "original_host_factory_native_leaf_v5", Purpose: "original_host_factory_native_leaf_v5", BindingSchema: hostVectorScopeSchema, BindingSHA256: hostVectorSHA(), Role: "host_worker", Process: g.reference, BootstrapReturnSHA256: g.record.Process.BootstrapReturnSHA256, ObservedAt: hostVectorTime().Add(1e9), SubjectPrimitiveRawSHA256: g.record.SubjectPrimitiveRawSHA256, ObserverRole: "host_registrar", ObserverPrimitiveRawSHA256: g.record.ObserverPrimitiveRawSHA256, OriginalTaskInventoryRead: task}
		out, err := ProposedHostFactorySourceProfileV1().ResolveNativeAggregate(leaf, hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.record.OriginalOperationDeadline, callbacks)
		if err != nil || len(out) != 2 {
			t.Fatalf("synthetic paired leaf graph %v", err)
		}
	})
	t.Run("unknown_getdents_nil_is_not_native_zero", func(t *testing.T) {
		g, task, callbacks := hostProfileSyntheticNativePairs(t)
		callbacks.GetdentsOriginal = func(string) ([]byte, error) { return nil, nil }
		_, err := ProposedHostFactorySourceProfileV1().ResolveNativeObservation(task, hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.record.OriginalOperationDeadline, callbacks)
		hostVectorRefused(t, err)
	})
	t.Run("missing_callback_no_graph", func(t *testing.T) {
		g, _, callbacks := hostProfileSyntheticNativePairs(t)
		callbacks.Original = nil
		_, err := ProposedHostFactorySourceProfileV1().ResolveNativeObservation(g.reference, hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), g.record.OriginalOperationDeadline, callbacks)
		hostVectorRefused(t, err)
	})
}

func TestHostFactorySourceProfileSelectedPurposeJoin(t *testing.T) {
	// These explicit synthetic metadata/call vectors exercise Source selection.
	// They do not supply the real recorder, syscall or SQL ownership prerequisite.
	makeDeclared := func() (*hostFactoryNativeGraph, model.HostFactoryNativeObservationRecord, []model.HostFactoryCallVectorReference, map[string]model.HostFactoryPrimitiveIOReturn, map[string]HostFactorySourceCallPurpose) {
		g := &hostFactoryNativeGraph{sourceProfile: ProposedHostFactorySourceProfileV1(), sourceExpectedStage: "native_alive"}
		purposes := map[string]HostFactorySourceCallPurpose{}
		calls := map[string]model.HostFactoryPrimitiveIOReturn{}
		stat := model.HostFactoryNativeStatReturn{Device: 1, Inode: 2, Mode: 0600, LinkCount: 1, Size: 0}
		refs := []model.HostFactoryCallVectorReference{}
		for _, row := range []struct {
			operation          string
			first, last, count uint64
		}{{"native_subject_pidfd_open", 1, 1, 1}, {"native_subject_alive_poll", 2, 7, 4}, {"native_subject_pidfd_fstat", 3, 6, 2}} {
			ref := hostVectorDeclaredRef(row.operation, hostVectorHandle, row.first, row.last, row.count)
			refs = append(refs, ref)
		}
		for ordinal, operation := range map[uint64]string{1: "native_subject_pidfd_open", 2: "native_subject_alive_poll", 3: "native_subject_pidfd_fstat", 4: "native_subject_alive_poll", 5: "native_subject_alive_poll", 6: "native_subject_pidfd_fstat", 7: "native_subject_alive_poll"} {
			id := fmt.Sprintf("%s:%d", hostVectorHandle, ordinal)
			fact := hostVectorPrimitive(operation, ordinal, "returned")
			fact.Operation = operation
			if operation == "native_subject_pidfd_fstat" {
				n := hostVectorNativeCall("unix_fstat")
				n.InputDescriptorNumber = hostVectorPtr(13)
				n.OriginalStat = &stat
				fact.OriginalNativeReturn = &n
			}
			calls[id] = fact
			stage := "native_alive"
			if ordinal <= 4 {
				stage = "worker_start"
			}
			purposes[id] = HostFactorySourceCallPurpose{id, "host_worker", stage}
		}
		pin := model.HostFactoryNativeSubjectPin{OriginalHandleID: hostVectorHandle, OriginalDescriptorNumber: 13, OriginalStat: stat, OriginalOpenCallVector: &refs[0], OriginalAlivePollCallVector: refs[1], OriginalFstatCallVector: refs[2], OriginalBeforePollCallID: hostVectorHandle + ":5", OriginalAfterPollCallID: hostVectorHandle + ":7"}
		record := model.HostFactoryNativeObservationRecord{SubjectRole: "host_worker", Process: &model.HostFactoryNativeProcess{OriginalSubjectNativePin: pin}}
		g.sourceCallPurpose = func(id string) (HostFactorySourceCallPurpose, bool, error) {
			p, known := purposes[id]
			if !known {
				return p, false, ErrHostFactorySourceRefused
			}
			return p, true, nil
		}
		return g, record, refs, calls, purposes
	}
	t.Run("prior_acquisition_Fstat_polls_preserved", func(t *testing.T) {
		g, rec, refs, calls, _ := makeDeclared()
		if g.sourceSelectedPurposes(rec, refs, calls) != nil {
			t.Fatal("genuine declared earlier stages were rewritten")
		}
	})
	t.Run("wrong_subject_role_selected", func(t *testing.T) {
		g, rec, refs, calls, purposes := makeDeclared()
		p := purposes[hostVectorHandle+":6"]
		p.SubjectRole = "host_exterior"
		purposes[p.OriginalCallID] = p
		hostVectorRefused(t, g.sourceSelectedPurposes(rec, refs, calls))
	})
	t.Run("wrong_current_Fstat_stage", func(t *testing.T) {
		g, rec, refs, calls, purposes := makeDeclared()
		p := purposes[hostVectorHandle+":6"]
		p.Stage = "worker_start"
		purposes[p.OriginalCallID] = p
		hostVectorRefused(t, g.sourceSelectedPurposes(rec, refs, calls))
	})
	t.Run("wrong_current_poll_stage", func(t *testing.T) {
		g, rec, refs, calls, purposes := makeDeclared()
		p := purposes[hostVectorHandle+":5"]
		p.Stage = "worker_start"
		purposes[p.OriginalCallID] = p
		hostVectorRefused(t, g.sourceSelectedPurposes(rec, refs, calls))
	})
	t.Run("unexpected_SAMEpin_interleaving", func(t *testing.T) {
		g, rec, refs, calls, purposes := makeDeclared()
		id := hostVectorHandle + ":8"
		calls[id] = calls[hostVectorHandle+":7"]
		purposes[id] = HostFactorySourceCallPurpose{id, "host_worker", "native_alive"}
		rec.Process.OriginalSubjectNativePin.OriginalAfterPollCallID = id
		hostVectorRefused(t, g.sourceSelectedPurposes(rec, refs, calls))
	})
	t.Run("prior_matching_Fstat_not_current_selection", func(t *testing.T) {
		g, rec, refs, calls, _ := makeDeclared()
		delete(calls, hostVectorHandle+":6")
		hostVectorRefused(t, g.sourceSelectedPurposes(rec, refs, calls))
	})
	t.Run("current_Fstat_outside_declared_vector", func(t *testing.T) {
		g, rec, refs, calls, _ := makeDeclared()
		rec.Process.OriginalSubjectNativePin.OriginalFstatCallVector = hostVectorDeclaredRef("native_subject_pidfd_fstat", hostVectorHandle, 3, 3, 1)
		hostVectorRefused(t, g.sourceSelectedPurposes(rec, refs, calls))
	})
	t.Run("unselected_whole_inventory_extras_not_current", func(t *testing.T) {
		g, rec, refs, calls, purposes := makeDeclared()
		f := hostVectorPrimitive("stdout_read", 8, "returned")
		id := *f.OriginalCallID
		calls[id] = f
		purposes[id] = HostFactorySourceCallPurpose{id, "host_exterior", "worker_exterior_join"}
		if g.sourceSelectedPurposes(rec, refs, calls) != nil {
			t.Fatal("unused inventory fact promoted into current selection")
		}
	})
	t.Run("fresh_file_vector_wrong_current_stage", func(t *testing.T) {
		g, rec, refs, calls, purposes := makeDeclared()
		f := hostVectorPrimitive("boot_id_read", 8, "returned")
		id := *f.OriginalCallID
		calls[id] = f
		purposes[id] = HostFactorySourceCallPurpose{id, "host_worker", "worker_start"}
		refs = append(refs, hostVectorDeclaredRef("boot_id_read", hostVectorHandle, 8, 8, 1))
		hostVectorRefused(t, g.sourceSelectedPurposes(rec, refs, calls))
	})
	t.Run("standalone_has_no_invented_aggregate_stage", func(t *testing.T) {
		g, rec, refs, calls, _ := makeDeclared()
		g.sourceExpectedStage = ""
		if g.sourceSelectedPurposes(rec, refs, calls) != nil {
			t.Fatal("unsigned expectedphase synthesized")
		}
	})
	t.Run("legacy_metadata_not_synthesized", func(t *testing.T) {
		g, rec, refs, calls, _ := makeDeclared()
		g.sourceCallPurpose = func(string) (HostFactorySourceCallPurpose, bool, error) {
			return HostFactorySourceCallPurpose{}, false, nil
		}
		if g.sourceSelectedPurposes(rec, refs, calls) != nil {
			t.Fatal("legacy Root purpose synthesized")
		}
	})
	t.Run("all_seven_fixed_aggregate_stage_sources", func(t *testing.T) {
		values := []struct {
			value any
			stage string
		}{{model.HostFactoryOriginalStartReturn{}, "worker_start"}, {model.HostFactoryAliveNativeRead{}, "native_alive"}, {model.HostFactoryExteriorJoin{}, "worker_exterior_join"}, {model.HostFactoryTerminalRead{}, "terminal_read"}, {model.HostFactoryNativeLeaf{}, "native_alive"}, {model.HostFactoryInitialEmptyRealmRead{}, "initial_empty"}, {model.HostFactoryOriginalEmptyRealmRead{}, "poststart_empty"}}
		for _, x := range values {
			if hostFactorySourceAggregateStage(x.value) != x.stage {
				t.Fatal("fixed source stage selection changed")
			}
		}
	})
}

func TestHostFactorySourceProfileLauncherWholeRecipe(t *testing.T) {
	// Full chosen Source tuple inventory only, synthetic crypto/body values.
	// No actual Cmd, Close, native owner, reviewed installation or SQL-FIRST.
	p := ProposedHostFactorySourceProfileV1()
	rows := []HostFactorySourceOperationTuple{
		{"control_pipe_create", "host_exterior", "host_worker", "worker_start", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_os_pipe")},
		{"bootstrap_pipe_create", "host_exterior", "host_worker", "worker_start", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_os_pipe")},
		{"stdout_pipe_create", "host_exterior", "host_worker", "worker_start", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_os_pipe")},
		{"stderr_pipe_create", "host_exterior", "host_worker", "worker_start", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_os_pipe")},
		{"descriptor_fstat", "host_exterior", "host_worker", "worker_start", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_fstat")},
		{"fcntl_getfl", "host_exterior", "host_worker", "worker_start", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("fcntl_getfl")},
		{"fcntl_getfd", "host_exterior", "host_worker", "worker_start", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("fcntl_getfd")},
		{"worker_start", "host_exterior", "host_worker", "worker_start", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_cmd_start")},
		{"worker_pidfd_pin", "host_exterior", "host_worker", "worker_start", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_pidfd_open")},
		{"control_reader_close", "host_exterior", "host_worker", "worker_start", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"bootstrap_reader_close", "host_exterior", "host_worker", "worker_start", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"redundant_stdout_writer_close", "host_exterior", "host_worker", "worker_start", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"redundant_stderr_writer_close", "host_exterior", "host_worker", "worker_start", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"bootstrap_challenge32_write", "host_exterior", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"bootstrap_key64_write", "host_exterior", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"bootstrap_binding_digest32_write", "host_exterior", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"bootstrap_writer_close", "host_exterior", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"control_frame_write", "host_exterior", "host_worker", "prepared_create", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"control_frame_write", "host_exterior", "host_worker", "choice_control", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"control_writer_close", "host_exterior", "host_worker", "choice_write", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"stdout_read", "host_exterior", "host_worker", "worker_exterior_join", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"stderr_read", "host_exterior", "host_worker", "worker_exterior_join", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"stdout_close", "host_exterior", "host_worker", "worker_exterior_join", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"stderr_close", "host_exterior", "host_worker", "worker_exterior_join", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"worker_wait", "host_exterior", "host_worker", "worker_exterior_join", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_cmd_wait")},
		{"worker_pidfd_poll", "host_exterior", "host_worker", "worker_exterior_join", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_poll")},
		{"worker_pidfd_close", "host_exterior", "host_worker", "worker_exterior_join", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"control_reader_close", "host_exterior", "host_worker", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"bootstrap_reader_close", "host_exterior", "host_worker", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"bootstrap_writer_close", "host_exterior", "host_worker", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"control_writer_close", "host_exterior", "host_worker", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"redundant_stdout_writer_close", "host_exterior", "host_worker", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"redundant_stderr_writer_close", "host_exterior", "host_worker", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"stdout_close", "host_exterior", "host_worker", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"stderr_close", "host_exterior", "host_worker", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"worker_pidfd_signal", "host_exterior", "host_worker", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_pidfd_send_signal")},
		{"worker_pidfd_close", "host_exterior", "host_worker", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
	}
	for index, row := range rows {
		t.Run(fmt.Sprintf("launcher_%02d_%s_%s", index, row.Operation, row.Stage), func(t *testing.T) {
			if p.ValidateOperation(row.Operation, row.OwnerRole, row.SubjectRole, row.Stage, row.BindingSchema, row.EnvelopeType, row.NativeKind) != nil {
				t.Fatal("complete chosen Source tuple recipe refused")
			}
		})
	}
	t.Run("control_parent_redundant_close", func(t *testing.T) {
		fact := hostVectorPrimitive("stdout_close", 1, "returned")
		fact.Operation = "control_reader_close"
		fact.SubjectOwnerID = hostVectorSubject
		chunk := hostVectorChunk(fact)
		entries := []HostFactorySourceCallPurpose{{*fact.OriginalCallID, "host_worker", "worker_start"}}
		key := hostProfileTestKey()
		env, err := p.SignEnvelope(chunk, entries, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		var out model.HostFactoryCallVectorChunk
		got, verifyErr := p.VerifyEnvelope(env, &out, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key.Public().(ed25519.PublicKey))
		if err != nil || verifyErr != nil || !reflect.DeepEqual(out, chunk) || !reflect.DeepEqual(got, entries) {
			t.Fatalf("original close metadata/sidecar roundtrip: %v/%v", err, verifyErr)
		}
		hostVectorRefused(t, VerifyHostFactoryEnvelope(env, &out, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key.Public().(ed25519.PublicKey)))
		bad := chunk
		native := *bad.OriginalCalls[0].OriginalNativeReturn
		native.OriginalScalar = hostVectorPtr(int64(0))
		bad.OriginalCalls = append([]model.HostFactoryPrimitiveIOReturn{}, bad.OriginalCalls...)
		bad.OriginalCalls[0].OriginalNativeReturn = &native
		_, err = p.SignEnvelope(bad, entries, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		hostVectorRefused(t, err) // File.Close exposes error only, scalar stays NULL.
	})
	t.Run("bootstrap_parent_redundant_close", func(t *testing.T) {
		fact := hostVectorPrimitive("stdout_close", 1, "returned")
		fact.Operation = "bootstrap_reader_close"
		fact.SubjectOwnerID = hostVectorSubject
		chunk := hostVectorChunk(fact)
		entries := []HostFactorySourceCallPurpose{{*fact.OriginalCallID, "host_worker", "worker_start"}}
		key := hostProfileTestKey()
		env, err := p.SignEnvelope(chunk, entries, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		var out model.HostFactoryCallVectorChunk
		got, verifyErr := p.VerifyEnvelope(env, &out, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key.Public().(ed25519.PublicKey))
		if err != nil || verifyErr != nil || !reflect.DeepEqual(out, chunk) || !reflect.DeepEqual(got, entries) {
			t.Fatalf("original close metadata/sidecar roundtrip: %v/%v", err, verifyErr)
		}
		hostVectorRefused(t, VerifyHostFactoryEnvelope(env, &out, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key.Public().(ed25519.PublicKey)))
		bad := chunk
		native := *bad.OriginalCalls[0].OriginalNativeReturn
		native.OriginalScalar = hostVectorPtr(int64(0))
		bad.OriginalCalls = append([]model.HostFactoryPrimitiveIOReturn{}, bad.OriginalCalls...)
		bad.OriginalCalls[0].OriginalNativeReturn = &native
		_, err = p.SignEnvelope(bad, entries, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		hostVectorRefused(t, err) // File.Close exposes error only, scalar stays NULL.
	})
	t.Run("partial_control_parent_cleanup", func(t *testing.T) {
		fact := hostVectorPrimitive("stdout_close", 1, "returned")
		fact.Operation = "control_reader_close"
		fact.SubjectOwnerID = hostVectorSubject
		chunk := hostVectorChunk(fact)
		entries := []HostFactorySourceCallPurpose{{*fact.OriginalCallID, "host_worker", "cleanup"}}
		key := hostProfileTestKey()
		env, err := p.SignEnvelope(chunk, entries, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		var out model.HostFactoryCallVectorChunk
		got, verifyErr := p.VerifyEnvelope(env, &out, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key.Public().(ed25519.PublicKey))
		if err != nil || verifyErr != nil || !reflect.DeepEqual(out, chunk) || !reflect.DeepEqual(got, entries) {
			t.Fatalf("original close metadata/sidecar roundtrip: %v/%v", err, verifyErr)
		}
		hostVectorRefused(t, VerifyHostFactoryEnvelope(env, &out, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key.Public().(ed25519.PublicKey)))
		bad := chunk
		native := *bad.OriginalCalls[0].OriginalNativeReturn
		native.OriginalScalar = hostVectorPtr(int64(0))
		bad.OriginalCalls = append([]model.HostFactoryPrimitiveIOReturn{}, bad.OriginalCalls...)
		bad.OriginalCalls[0].OriginalNativeReturn = &native
		_, err = p.SignEnvelope(bad, entries, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		hostVectorRefused(t, err) // File.Close exposes error only, scalar stays NULL.
	})
	t.Run("existing_worker_owned_cleanup_base_preserved", func(t *testing.T) {
		kind := "original_file_close"
		if ValidateHostFactoryOperation("control_reader_close", "host_worker", "host_worker", "cleanup", hostVectorScopeSchema, "HostFactorySignedEnvelope") != nil || p.ValidateOperation("control_reader_close", "host_worker", "host_worker", "cleanup", hostVectorScopeSchema, "HostFactorySignedEnvelope", &kind) != nil {
			t.Fatal("Source extension removed old worker cleanup tuple")
		}
	})
	t.Run("prior107d_profile_not_relabelled", func(t *testing.T) {
		body := hostVectorChoice()
		key := hostProfileTestKey()
		env, err := p.SignEnvelope(body, []HostFactorySourceCallPurpose{}, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		if err != nil {
			t.Fatal(err)
		}
		prior := bytes.Replace(env, []byte(hostFactorySourceProfileSHA), []byte("107d1a2cf25fee4d966fa1886dbf5f94c19c866c2eb4cda28405d27c70923ebd"), 1)
		var decoded HostFactorySourceSignedEnvelope
		hostVectorRefused(t, p.Decode(prior, &decoded))
		var out model.HostFactoryChoiceReturn
		_, err = p.VerifyEnvelope(prior, &out, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key.Public().(ed25519.PublicKey))
		hostVectorRefused(t, err)
	})
}

func TestHostFactorySourceProfileTerminalWholeRecipe(t *testing.T) {
	// Complete chosen success/failure-cleanup tuple declarations only. The
	// native methods, signing key and original values below are synthetic
	// Source vectors; no actual descriptor/process/Source approval or SQL-FIRST.
	p := ProposedHostFactorySourceProfileV1()
	rows := []HostFactorySourceOperationTuple{
		{"native_subject_pidfd_open", "host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_pidfd_open")},
		{"native_subject_pidfd_fstat", "host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_fstat")},
		{"native_subject_alive_poll", "host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_poll")},
		{"native_reader_open", "host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_open")},
		{"native_reader_fstat", "host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_fstat")},
		{"native_reader_close", "host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"proc_owner_directory_open", "host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_open")},
		{"proc_owner_directory_fstat", "host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_fstat")},
		{"proc_owner_directory_close", "host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"boot_id_read", "host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"stat_before_read", "host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"stat_after_read", "host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"executable_read", "host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"cmdline_read", "host_registrar", "host_exterior", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"native_subject_pidfd_open", "host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_pidfd_open")},
		{"native_subject_pidfd_fstat", "host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_fstat")},
		{"native_subject_alive_poll", "host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_poll")},
		{"native_reader_open", "host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_open")},
		{"native_reader_fstat", "host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_fstat")},
		{"native_reader_close", "host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"proc_owner_directory_open", "host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_open")},
		{"proc_owner_directory_fstat", "host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_fstat")},
		{"proc_owner_directory_close", "host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"boot_id_read", "host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"stat_before_read", "host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"stat_after_read", "host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"executable_read", "host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"cmdline_read", "host_registrar", "host_registrar", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"gate_directory_duplicate", "host_registrar", "host_worker", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("fcntl_dupfd_cloexec")},
		{"native_reader_open", "host_registrar", "host_worker", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_openat")},
		{"gate_fstat", "host_registrar", "host_worker", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_fstat")},
		{"descriptor_fstat", "host_registrar", "host_worker", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_fstat")},
		{"fcntl_getfl", "host_registrar", "host_worker", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("fcntl_getfl")},
		{"fcntl_getfd", "host_registrar", "host_worker", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("fcntl_getfd")},
		{"gate_read", "host_registrar", "host_worker", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"terminal_gate_close", "host_registrar", "host_worker", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"terminal_directory_close", "host_registrar", "host_worker", "terminal_read", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"worker_pidfd_poll", "host_registrar", "host_worker", "worker_exterior_join", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_poll")},
		{"worker_pidfd_close", "host_registrar", "host_worker", "worker_exterior_join", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"native_reader_close", "host_registrar", "host_exterior", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"proc_owner_directory_close", "host_registrar", "host_exterior", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"native_subject_pidfd_close", "host_registrar", "host_exterior", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"native_reader_close", "host_registrar", "host_registrar", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"proc_owner_directory_close", "host_registrar", "host_registrar", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"native_subject_pidfd_close", "host_registrar", "host_registrar", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
	}
	for index, row := range rows {
		t.Run(fmt.Sprintf("terminal_%02d_%s_%s_%s", index, row.Operation, row.SubjectRole, row.Stage), func(t *testing.T) {
			if p.ValidateOperation(row.Operation, row.OwnerRole, row.SubjectRole, row.Stage, row.BindingSchema, row.EnvelopeType, row.NativeKind) != nil {
				t.Fatal("complete chosen terminal Source tuple refused")
			}
			baseErr := ValidateHostFactoryOperation(row.Operation, row.OwnerRole, row.SubjectRole, row.Stage, row.BindingSchema, row.EnvelopeType)
			newTuple := index == 31 || index == 32 || index == 33 || index == 40 || index == 43
			if (baseErr != nil) != newTuple {
				t.Fatal("default141 outcomes widened or existing original tuple removed")
			}
		})
	}
	t.Run("prior44_manifest_exact_tuple_prefix", func(t *testing.T) {
		raw, err := p.Manifest()
		var current HostFactorySourceProfileManifest
		if err != nil || p.Decode(raw, &current) != nil {
			t.Fatal("fixed Source manifest")
		}
		var prior HostFactorySourceProfileManifest
		if json.Unmarshal([]byte(`{"schema":"source_host_factory_operation_profile_manifest_v1","base_rule_sha256":"ed641019a2b70511914a45ac8e7ece55a2540fd4570f630e6e662dd416ff3ff5","parent_source_decision_sha256":"ce723f6ac59afa4229f65641f69e6daddefb719b3563ad6aa4c7c9dfa58841b8","tuple_key_order":["operation","owner_role","subject_role","stage","binding_schema","envelope_type","native_kind"],"exact_tuples":[{"operation":"native_subject_alive_poll","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_poll"},{"operation":"native_subject_pidfd_fstat","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_open","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"proc_owner_directory_fstat","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_close","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"native_subject_alive_poll","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_poll"},{"operation":"native_subject_pidfd_fstat","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_open","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"proc_owner_directory_fstat","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_close","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"native_subject_alive_poll","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_poll"},{"operation":"native_subject_pidfd_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"native_reader_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"native_reader_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"native_reader_close","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"boot_id_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"stat_before_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"executable_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"cmdline_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"proc_owner_directory_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"proc_owner_directory_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_close","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"stat_after_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"task_inventory_getdents","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_getdents64"},{"operation":"native_subject_alive_poll","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_poll"},{"operation":"native_subject_pidfd_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"native_reader_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"native_reader_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"native_reader_close","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"boot_id_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"stat_before_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"executable_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"cmdline_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"proc_owner_directory_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"proc_owner_directory_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_close","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"stat_after_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"native_subject_pidfd_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_pidfd_open"},{"operation":"native_subject_pidfd_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_pidfd_open"},{"operation":"native_subject_pidfd_open","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_pidfd_open"},{"operation":"native_subject_pidfd_open","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_pidfd_open"},{"operation":"control_reader_close","owner_role":"host_exterior","subject_role":"host_worker","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"bootstrap_reader_close","owner_role":"host_exterior","subject_role":"host_worker","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"control_reader_close","owner_role":"host_exterior","subject_role":"host_worker","stage":"cleanup","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"}]}`), &prior) != nil || len(prior.ExactTuples) != 44 || !reflect.DeepEqual(current.ExactTuples[:44], prior.ExactTuples) {
			t.Fatal("Source44 tuple prefix changed")
		}
	})
	t.Run("prior44_scope_profile_not_relabelled", func(t *testing.T) {
		chunk, entries := hostProfileTestChunk("returned")
		key := hostProfileTestKey()
		env, err := p.SignEnvelope(chunk, entries, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		if err != nil {
			t.Fatal(err)
		}
		bad := bytes.Replace(env, []byte(hostFactorySourceProfileSHA), []byte("b9d558f44df5b7a9a2555b7b0434e9ddcaf727adbfb6d309d63b02e89672b0c8"), 1)
		var decoded model.HostFactoryCallVectorChunk
		_, err = p.VerifyEnvelope(bad, &decoded, "host_exterior", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key.Public().(ed25519.PublicKey))
		hostVectorRefused(t, err)
	})
	t.Run("cleanup_call_not_terminal_current_native_selection", func(t *testing.T) {
		fact := hostVectorPrimitive("stdout_close", 1, "returned")
		fact.Operation = "proc_owner_directory_close"
		ref := hostVectorDeclaredRef(fact.Operation, hostVectorHandle, 1, 1, 1)
		g := &hostFactoryNativeGraph{sourceProfile: p, sourceExpectedStage: "terminal_read", sourceCallPurpose: func(id string) (HostFactorySourceCallPurpose, bool, error) {
			return HostFactorySourceCallPurpose{id, "host_exterior", "cleanup"}, true, nil
		}}
		hostVectorRefused(t, g.sourceSelectedPurposes(model.HostFactoryNativeObservationRecord{SubjectRole: "host_exterior"}, []model.HostFactoryCallVectorReference{ref}, map[string]model.HostFactoryPrimitiveIOReturn{*fact.OriginalCallID: fact}))
	})
	t.Run("RootPreparation_cleanup_stays_unavailable_in_profile", func(t *testing.T) {
		kind := "original_file_close"
		hostVectorRefused(t, p.ValidateOperation("proc_owner_directory_close", "host_registrar", "host_exterior", "cleanup", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", &kind))
	})
}

func TestHostFactorySourceProfileWorkerEarlyLateWholeRecipe(t *testing.T) {
	// Fixed Source-only selected recipes and typed original-call projections.
	// These synthetic values attest no syscall, source approval, inherited FD,
	// native epoch, actual key custody or SQL FIRST relationship.
	p := ProposedHostFactorySourceProfileV1()
	rows := []HostFactorySourceOperationTuple{
		{"inherited_descriptor_fstat", "host_worker", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_fstat")},
		{"descriptor_fstat", "host_worker", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_fstat")},
		{"fcntl_getfl", "host_worker", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("fcntl_getfl")},
		{"fcntl_getfd", "host_worker", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("fcntl_getfd")},
		{"fcntl_setfl", "host_worker", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("fcntl_setfl")},
		{"bootstrap_challenge32_read", "host_worker", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"bootstrap_key64_read", "host_worker", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"bootstrap_binding_digest32_read", "host_worker", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"bootstrap_eof_read", "host_worker", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"bootstrap_reader_close", "host_worker", "host_worker", "worker_bootstrap", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"bootstrap_reader_close", "host_worker", "host_worker", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"control_frame_read", "host_worker", "host_worker", "prepared_create", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"control_frame_read", "host_worker", "host_worker", "choice_control", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"control_frame_write", "host_exterior", "host_worker", "prepared_create", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"control_frame_write", "host_exterior", "host_worker", "choice_control", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil},
		{"control_reader_close", "host_worker", "host_worker", "choice_write", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"control_reader_close", "host_worker", "host_worker", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"gate_fstat", "host_worker", "host_worker", "choice_write", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("unix_fstat")},
		{"gate_directory_close", "host_worker", "host_worker", "choice_write", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"gate_directory_close", "host_worker", "host_worker", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"control_writer_close", "host_exterior", "host_worker", "choice_write", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
		{"control_writer_close", "host_exterior", "host_worker", "cleanup", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", hostVectorPtr("original_file_close")},
	}
	for index, row := range rows {
		t.Run(fmt.Sprintf("earlylate_%02d_%s_%s_%s", index, row.Operation, row.OwnerRole, row.Stage), func(t *testing.T) {
			if p.ValidateOperation(row.Operation, row.OwnerRole, row.SubjectRole, row.Stage, row.BindingSchema, row.EnvelopeType, row.NativeKind) != nil {
				t.Fatal("complete selected early/late Source tuple refused")
			}
			baseErr := ValidateHostFactoryOperation(row.Operation, row.OwnerRole, row.SubjectRole, row.Stage, row.BindingSchema, row.EnvelopeType)
			if (baseErr != nil) != (index == 19) {
				t.Fatal("default141 outcomes widened or existing early/late tuple removed")
			}
		})
	}
	makeClose := func() (model.HostFactoryCallVectorChunk, []HostFactorySourceCallPurpose) {
		fact := hostVectorPrimitive("stdout_close", 1, "returned")
		fact.Operation, fact.SubjectOwnerID = "gate_directory_close", hostVectorOwner
		chunk := hostVectorChunk(fact)
		chunk.OwnerRole = "host_worker"
		return chunk, []HostFactorySourceCallPurpose{{*fact.OriginalCallID, "host_worker", "cleanup"}}
	}
	t.Run("held_FD5_original_Close_roundtrip", func(t *testing.T) {
		chunk, entries := makeClose()
		key := hostProfileTestKey()
		env, err := p.SignEnvelope(chunk, entries, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		var out model.HostFactoryCallVectorChunk
		got, verifyErr := p.VerifyEnvelope(env, &out, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key.Public().(ed25519.PublicKey))
		if err != nil || verifyErr != nil || !reflect.DeepEqual(out, chunk) || !reflect.DeepEqual(got, entries) || out.OriginalCalls[0].OriginalNativeReturn.OriginalScalar != nil {
			t.Fatalf("error-only original File.Close projection: %v/%v", err, verifyErr)
		}
		hostVectorRefused(t, VerifyHostFactoryEnvelope(env, &out, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key.Public().(ed25519.PublicKey)))
	})
	t.Run("failed_Close_original_error_retained_without_scalar", func(t *testing.T) {
		chunk, entries := makeClose()
		chunk.OriginalCalls[0].OriginalReturnClass = "io_refused"
		chunk.OriginalCalls[0].OriginalNativeReturn.OriginalErrorPresent = hostVectorPtr(true)
		chunk.OriginalCalls[0].OriginalNativeReturn.OriginalErrno = hostVectorPtr(uint32(5))
		key := hostProfileTestKey()
		env, err := p.SignEnvelope(chunk, entries, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		var out model.HostFactoryCallVectorChunk
		_, verifyErr := p.VerifyEnvelope(env, &out, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key.Public().(ed25519.PublicKey))
		if err != nil || verifyErr != nil || !reflect.DeepEqual(out, chunk) || !*out.OriginalCalls[0].OriginalNativeReturn.OriginalErrorPresent {
			t.Fatalf("original diagnostic Close error lost: %v/%v", err, verifyErr)
		}
		// This is retained failure grammar only; it provides no successful
		// native closure, immutable SQL relation or permission to create.
	})
	t.Run("Close_scalar_zero_is_not_an_original_return", func(t *testing.T) {
		chunk, entries := makeClose()
		chunk.OriginalCalls[0].OriginalNativeReturn.OriginalScalar = hostVectorPtr(int64(0))
		_, err := p.SignEnvelope(chunk, entries, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), hostProfileTestKey())
		hostVectorRefused(t, err)
	})
	t.Run("Close_does_not_acquire_bytes_EOF_or_descriptor", func(t *testing.T) {
		mutations := []func(*model.HostFactoryPrimitiveIOReturn){
			func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalCount = hostVectorPtr(int64(0)) },
			func(f *model.HostFactoryPrimitiveIOReturn) {
				f.OriginalSHA256 = hostVectorPtr(HostFactoryRawSHA256(nil))
			},
			func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalEOF = hostVectorPtr(true) },
			func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalNativeReturn.InputDescriptorNumber = nil },
			func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalNativeReturn.OriginalErrorPresent = nil },
		}
		for _, mutate := range mutations {
			chunk, entries := makeClose()
			mutate(&chunk.OriginalCalls[0])
			_, err := p.SignEnvelope(chunk, entries, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), hostProfileTestKey())
			hostVectorRefused(t, err)
		}
	})
	t.Run("held_gate_Close_wrong_subject_and_current_stage_refused", func(t *testing.T) {
		for _, entry := range []HostFactorySourceCallPurpose{{hostVectorHandle + ":1", "host_exterior", "cleanup"}, {hostVectorHandle + ":1", "host_worker", "terminal_read"}} {
			chunk, _ := makeClose()
			_, err := p.SignEnvelope(chunk, []HostFactorySourceCallPurpose{entry}, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), hostProfileTestKey())
			hostVectorRefused(t, err)
		}
	})
	t.Run("cleanup_original_purpose_is_required", func(t *testing.T) {
		chunk, _ := makeClose()
		for _, entries := range [][]HostFactorySourceCallPurpose{nil, {}} {
			_, err := p.SignEnvelope(chunk, entries, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), hostProfileTestKey())
			hostVectorRefused(t, err)
		}
	})
	t.Run("bootstrap_private_key_hash_stays_withheld", func(t *testing.T) {
		fact := hostVectorPrimitive("bootstrap_key64_read", 1, "returned")
		fact.SubjectOwnerID = hostVectorOwner
		chunk := hostVectorChunk(fact)
		chunk.OwnerRole = "host_worker"
		entries := []HostFactorySourceCallPurpose{{*fact.OriginalCallID, "host_worker", "worker_bootstrap"}}
		key := hostProfileTestKey()
		env, err := p.SignEnvelope(chunk, entries, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		var out model.HostFactoryCallVectorChunk
		_, verifyErr := p.VerifyEnvelope(env, &out, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key.Public().(ed25519.PublicKey))
		if err != nil || verifyErr != nil || !reflect.DeepEqual(out, chunk) || out.OriginalCalls[0].OriginalSHA256 != nil {
			t.Fatalf("private key metadata custody changed: %v/%v", err, verifyErr)
		}
		chunk.OriginalCalls[0].OriginalSHA256 = hostVectorPtr(hostVectorSHA())
		_, err = p.SignEnvelope(chunk, entries, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		hostVectorRefused(t, err)
	})
	t.Run("prior49_manifest_exact_tuple_prefix", func(t *testing.T) {
		raw, err := p.Manifest()
		var current, prior HostFactorySourceProfileManifest
		if err != nil || p.Decode(raw, &current) != nil || json.Unmarshal([]byte(`{"schema":"source_host_factory_operation_profile_manifest_v1","base_rule_sha256":"ed641019a2b70511914a45ac8e7ece55a2540fd4570f630e6e662dd416ff3ff5","parent_source_decision_sha256":"ce723f6ac59afa4229f65641f69e6daddefb719b3563ad6aa4c7c9dfa58841b8","tuple_key_order":["operation","owner_role","subject_role","stage","binding_schema","envelope_type","native_kind"],"exact_tuples":[{"operation":"native_subject_alive_poll","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_poll"},{"operation":"native_subject_pidfd_fstat","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_open","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"proc_owner_directory_fstat","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_close","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"native_subject_alive_poll","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_poll"},{"operation":"native_subject_pidfd_fstat","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_open","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"proc_owner_directory_fstat","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_close","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"native_subject_alive_poll","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_poll"},{"operation":"native_subject_pidfd_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"native_reader_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"native_reader_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"native_reader_close","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"boot_id_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"stat_before_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"executable_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"cmdline_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"proc_owner_directory_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"proc_owner_directory_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_close","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"stat_after_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"task_inventory_getdents","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_getdents64"},{"operation":"native_subject_alive_poll","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_poll"},{"operation":"native_subject_pidfd_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"native_reader_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"native_reader_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"native_reader_close","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"boot_id_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"stat_before_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"executable_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"cmdline_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"proc_owner_directory_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"proc_owner_directory_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_close","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"stat_after_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"native_subject_pidfd_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_pidfd_open"},{"operation":"native_subject_pidfd_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_pidfd_open"},{"operation":"native_subject_pidfd_open","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_pidfd_open"},{"operation":"native_subject_pidfd_open","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_pidfd_open"},{"operation":"control_reader_close","owner_role":"host_exterior","subject_role":"host_worker","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"bootstrap_reader_close","owner_role":"host_exterior","subject_role":"host_worker","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"control_reader_close","owner_role":"host_exterior","subject_role":"host_worker","stage":"cleanup","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"descriptor_fstat","owner_role":"host_registrar","subject_role":"host_worker","stage":"terminal_read","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"fcntl_getfl","owner_role":"host_registrar","subject_role":"host_worker","stage":"terminal_read","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"fcntl_getfl"},{"operation":"fcntl_getfd","owner_role":"host_registrar","subject_role":"host_worker","stage":"terminal_read","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"fcntl_getfd"},{"operation":"proc_owner_directory_close","owner_role":"host_registrar","subject_role":"host_exterior","stage":"cleanup","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"proc_owner_directory_close","owner_role":"host_registrar","subject_role":"host_registrar","stage":"cleanup","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"}]}`), &prior) != nil || len(prior.ExactTuples) != 49 || len(current.ExactTuples) != 51 || !reflect.DeepEqual(current.ExactTuples[:49], prior.ExactTuples) {
			t.Fatal("Source49 exact tuple prefix changed")
		}
	})
	t.Run("prior49_scope_profile_not_relabelled", func(t *testing.T) {
		chunk, entries := makeClose()
		key := hostProfileTestKey()
		env, err := p.SignEnvelope(chunk, entries, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		if err != nil {
			t.Fatal(err)
		}
		prior := bytes.Replace(env, []byte(hostFactorySourceProfileSHA), []byte("32c01999573a3afe5e250bb3c870f16322b08b2e8de555b52bd9440210d40afe"), 1)
		var out model.HostFactoryCallVectorChunk
		_, err = p.VerifyEnvelope(prior, &out, "host_worker", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key.Public().(ed25519.PublicKey))
		hostVectorRefused(t, err)
	})
	t.Run("no_SET_FD_Root_cleanup_or_new_kind_permission", func(t *testing.T) {
		kind := "original_file_close"
		hostVectorRefused(t, p.ValidateOperation("gate_directory_close", "host_worker", "host_worker", "cleanup", "original_host_factory_root_preparation_v4", "HostFactoryRootSignedEnvelope", &kind))
		wrong := "fcntl_setfd"
		hostVectorRefused(t, p.ValidateOperation("fcntl_setfd", "host_worker", "host_worker", "worker_bootstrap", hostVectorScopeSchema, "HostFactorySignedEnvelope", &wrong))
		hostVectorRefused(t, p.ValidateOperation("gate_directory_close", "host_worker", "host_worker", "cleanup", hostVectorScopeSchema, "HostFactorySignedEnvelope", &wrong))
	})
}

func TestHostFactorySourceProfilePostStartWorkerCleanup(t *testing.T) {
	// Source-only closed grammar and immutable purpose transport, not actual
	// returned proc/syscall/SourceApproval/native closure or SQL FIRST facts.
	p := ProposedHostFactorySourceProfileV1()
	makeClose := func() (model.HostFactoryCallVectorChunk, []HostFactorySourceCallPurpose) {
		fact := hostVectorPrimitive("stdout_close", 1, "returned")
		fact.Operation, fact.SubjectOwnerID = "proc_owner_directory_close", hostVectorSubject
		chunk := hostVectorChunk(fact)
		chunk.OwnerRole = "host_registrar"
		return chunk, []HostFactorySourceCallPurpose{{*fact.OriginalCallID, "host_worker", "cleanup"}}
	}
	t.Run("exact_new_Close_Source_only_default141_still_refuses", func(t *testing.T) {
		kind := "original_file_close"
		if p.ValidateOperation("proc_owner_directory_close", "host_registrar", "host_worker", "cleanup", hostVectorScopeSchema, "HostFactorySignedEnvelope", &kind) != nil {
			t.Fatal("exact new Source cleanup tuple refused")
		}
		hostVectorRefused(t, ValidateHostFactoryOperation("proc_owner_directory_close", "host_registrar", "host_worker", "cleanup", hostVectorScopeSchema, "HostFactorySignedEnvelope"))
	})
	t.Run("original_Close_error_only_scalar_NULL_roundtrip", func(t *testing.T) {
		chunk, purposes := makeClose()
		key := hostProfileTestKey()
		env, err := p.SignEnvelope(chunk, purposes, "host_registrar", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		var out model.HostFactoryCallVectorChunk
		got, verifyErr := p.VerifyEnvelope(env, &out, "host_registrar", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key.Public().(ed25519.PublicKey))
		if err != nil || verifyErr != nil || !reflect.DeepEqual(out, chunk) || !reflect.DeepEqual(got, purposes) || out.OriginalCalls[0].OriginalNativeReturn.OriginalScalar != nil {
			t.Fatalf("literal original Close transport %v/%v", err, verifyErr)
		}
		hostVectorRefused(t, VerifyHostFactoryEnvelope(env, &out, "host_registrar", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key.Public().(ed25519.PublicKey)))
	})
	t.Run("failed_original_Close_retains_error_not_native_complete", func(t *testing.T) {
		chunk, purposes := makeClose()
		key := hostProfileTestKey()
		chunk.OriginalCalls[0].OriginalReturnClass = "io_refused"
		chunk.OriginalCalls[0].OriginalNativeReturn.OriginalErrorPresent = hostVectorPtr(true)
		chunk.OriginalCalls[0].OriginalNativeReturn.OriginalErrno = hostVectorPtr(uint32(5))
		env, err := p.SignEnvelope(chunk, purposes, "host_registrar", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		var out model.HostFactoryCallVectorChunk
		_, verifyErr := p.VerifyEnvelope(env, &out, "host_registrar", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key.Public().(ed25519.PublicKey))
		if err != nil || verifyErr != nil || !reflect.DeepEqual(out, chunk) || !*out.OriginalCalls[0].OriginalNativeReturn.OriginalErrorPresent {
			t.Fatalf("failed diagnostic original Close lost %v/%v", err, verifyErr)
		}
	})
	t.Run("synthetic_scalar_or_wrong_nativekind_refused", func(t *testing.T) {
		for _, mutation := range []func(*model.HostFactoryPrimitiveIOReturn){func(f *model.HostFactoryPrimitiveIOReturn) {
			f.OriginalNativeReturn.OriginalScalar = hostVectorPtr(int64(0))
		}, func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalNativeReturn.Kind = "unix_fstat" }} {
			chunk, purposes := makeClose()
			mutation(&chunk.OriginalCalls[0])
			_, err := p.SignEnvelope(chunk, purposes, "host_registrar", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), hostProfileTestKey())
			hostVectorRefused(t, err)
		}
	})
	t.Run("missing_original_purpose_and_Root_relabel_refused", func(t *testing.T) {
		chunk, _ := makeClose()
		_, err := p.SignEnvelope(chunk, nil, "host_registrar", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), hostProfileTestKey())
		hostVectorRefused(t, err)
		kind := "original_file_close"
		hostVectorRefused(t, p.ValidateOperation("proc_owner_directory_close", "host_registrar", "host_worker", "cleanup", hostVectorRootSchema, "HostFactoryRootSignedEnvelope", &kind))
	})
	t.Run("prior50_scope_signature_never_relabelled", func(t *testing.T) {
		chunk, purposes := makeClose()
		key := hostProfileTestKey()
		env, err := p.SignEnvelope(chunk, purposes, "host_registrar", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key)
		if err != nil {
			t.Fatal(err)
		}
		old := bytes.Replace(env, []byte(hostFactorySourceProfileSHA), []byte("da18f6b330b6fd0a11e52689350871f98124fd614bc8da7917c01a5ddf84e5de"), 1)
		var out model.HostFactoryCallVectorChunk
		_, err = p.VerifyEnvelope(old, &out, "host_registrar", hostVectorOwner, hostVectorScopeSchema, hostVectorSHA(), key.Public().(ed25519.PublicKey))
		hostVectorRefused(t, err)
	})
	t.Run("prior50_manifest_exact_tuple_prefix", func(t *testing.T) {
		var current, prior HostFactorySourceProfileManifest
		raw, err := p.Manifest()
		if err != nil || p.Decode(raw, &current) != nil || json.Unmarshal([]byte(`{"schema":"source_host_factory_operation_profile_manifest_v1","base_rule_sha256":"ed641019a2b70511914a45ac8e7ece55a2540fd4570f630e6e662dd416ff3ff5","parent_source_decision_sha256":"ce723f6ac59afa4229f65641f69e6daddefb719b3563ad6aa4c7c9dfa58841b8","tuple_key_order":["operation","owner_role","subject_role","stage","binding_schema","envelope_type","native_kind"],"exact_tuples":[{"operation":"native_subject_alive_poll","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_poll"},{"operation":"native_subject_pidfd_fstat","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_open","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"proc_owner_directory_fstat","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_close","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"native_subject_alive_poll","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_poll"},{"operation":"native_subject_pidfd_fstat","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_open","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"proc_owner_directory_fstat","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_close","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"native_subject_alive_poll","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_poll"},{"operation":"native_subject_pidfd_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"native_reader_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"native_reader_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"native_reader_close","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"boot_id_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"stat_before_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"executable_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"cmdline_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"proc_owner_directory_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"proc_owner_directory_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_close","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"stat_after_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"task_inventory_getdents","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_getdents64"},{"operation":"native_subject_alive_poll","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_poll"},{"operation":"native_subject_pidfd_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"native_reader_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"native_reader_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"native_reader_close","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"boot_id_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"stat_before_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"executable_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"cmdline_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"proc_owner_directory_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_open"},{"operation":"proc_owner_directory_fstat","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"proc_owner_directory_close","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"stat_after_read","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":null},{"operation":"native_subject_pidfd_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_pidfd_open"},{"operation":"native_subject_pidfd_open","owner_role":"host_exterior","subject_role":"host_exterior","stage":"worker_exterior_join","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_pidfd_open"},{"operation":"native_subject_pidfd_open","owner_role":"host_registrar","subject_role":"host_exterior","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_pidfd_open"},{"operation":"native_subject_pidfd_open","owner_role":"host_registrar","subject_role":"host_registrar","stage":"native_alive","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_pidfd_open"},{"operation":"control_reader_close","owner_role":"host_exterior","subject_role":"host_worker","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"bootstrap_reader_close","owner_role":"host_exterior","subject_role":"host_worker","stage":"worker_start","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"control_reader_close","owner_role":"host_exterior","subject_role":"host_worker","stage":"cleanup","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"descriptor_fstat","owner_role":"host_registrar","subject_role":"host_worker","stage":"terminal_read","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"unix_fstat"},{"operation":"fcntl_getfl","owner_role":"host_registrar","subject_role":"host_worker","stage":"terminal_read","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"fcntl_getfl"},{"operation":"fcntl_getfd","owner_role":"host_registrar","subject_role":"host_worker","stage":"terminal_read","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"fcntl_getfd"},{"operation":"proc_owner_directory_close","owner_role":"host_registrar","subject_role":"host_exterior","stage":"cleanup","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"proc_owner_directory_close","owner_role":"host_registrar","subject_role":"host_registrar","stage":"cleanup","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"},{"operation":"gate_directory_close","owner_role":"host_worker","subject_role":"host_worker","stage":"cleanup","binding_schema":"original_host_factory_pre_authority_scope_v4","envelope_type":"HostFactorySignedEnvelope","native_kind":"original_file_close"}]}`), &prior) != nil || len(prior.ExactTuples) != 50 || len(current.ExactTuples) != 51 || !reflect.DeepEqual(current.ExactTuples[:50], prior.ExactTuples) {
			t.Fatal("Source50 whole exact prefix changed")
		}
	})
}
