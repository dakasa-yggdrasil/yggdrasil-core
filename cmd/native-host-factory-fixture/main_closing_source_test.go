//go:build linux && nativequalification

package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// Source-only caller fence. The real Capture method has no owning state here
// and must refuse BEFORE SQL/Native. No fake Realm or callback supplies a gate.
func TestOriginalMainCaptureRefusalSuppressesAllFinalCompletion(t *testing.T) {
	for _, tc := range []struct {
		name       string
		persistErr error
	}{{"persist-success-capture-refusal", nil}, {"persist-error-remains-separate", errors.New("original Persist refusal")}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
			defer cancel()
			called := time.Now().UTC()
			returned := time.Now().UTC()
			captureErr := (repository.CapacityStore{}).CaptureOriginalHostClosingReturn(ctx, nil, called, returned, tc.persistErr)
			if captureErr == nil {
				t.Fatal("missing owning state became an external-return gate")
			}
			owner := &originalFixtureOwners{cleanup: ctx, preclose: []byte("retained preclose"), ownerID: "source-only-owner", ordinals: map[string]uint64{}}
			index := owner.beginAudit("db_original_query", "source-only-handle", originalSubjectIdentity{SubjectKind: "main_db"}, returned.Add(time.Minute))
			owner.finishAudit(index, tc.persistErr, nil)
			// A nil Realm makes accidental continuation into any finalizer/getter fail;
			// no Source approval, private output or filesystem publication is provided.
			got := owner.finishOriginalCompletion("", errors.Join(tc.persistErr, captureErr))
			if !errors.Is(got, captureErr) || tc.persistErr != nil && !errors.Is(got, tc.persistErr) {
				t.Fatal("actual cleanup causes were normalized/lost")
			}
			if owner.audits[index].Fact.OriginalErrorPresent == nil || *owner.audits[index].Fact.OriginalErrorPresent != (tc.persistErr != nil) {
				t.Fatal("Capture error rewrote the original Persist audit")
			}
		})
	}
}

// Source-only registry/copy discriminants. No file is opened, no Realm approval
// or Native permission is supplied. The consumer corpus separately requires
// complete seven-stream private Read/EOF/Close evidence and the exact union.
func TestOriginalMainPrivateSourceCensus(t *testing.T) {
	makeOwner := func(t *testing.T) (*originalFixtureOwners, *originalMainReturn, []string) {
		t.Helper()
		o := &originalFixtureOwners{ownerID: "source-only-owner", ordinals: map[string]uint64{}}
		refs := []string{}
		for n := 0; n < 7; n++ {
			handle := fmt.Sprintf("10000000-0000-4000-8000-%012d", 1000+n)
			// The same private registration called by originalPrivateFile is
			// made before its first audit/I/O. This test performs no I/O.
			if err := o.registerOriginalMainPrivateSourceHandle(handle); err != nil {
				t.Fatal(err)
			}
			i := o.beginAudit("source_file_open", handle, originalSubjectIdentity{SubjectKind: "source_file"}, time.Time{})
			o.finishAudit(i, nil, nil)
			refs = append(refs, *o.audits[i].Fact.OriginalCallID)
		}
		call := o.beginMainReturn("main_cleanup_return", "source-only", time.Time{})
		return o, call, refs
	}
	t.Run("copy_registered_main_calls_only", func(t *testing.T) {
		o, call, refs := makeOwner(t)
		// A copied Realm stream in the same slice must remain independent.
		i := o.beginAudit("source_file_open", "10000000-0000-4000-8000-000000000520", originalSubjectIdentity{SubjectKind: "source_file"}, time.Time{})
		o.finishAudit(i, nil, nil)
		before := append([]originalAuditProjection(nil), o.audits...)
		if err := o.copyOriginalMainPrivateSourceAuditReferences(call); err != nil || !reflect.DeepEqual(call.SourceAuditCallReferences, refs) || !reflect.DeepEqual(before, o.audits) {
			t.Fatal("registry did not preserve the exact Main/Realm distinction and original facts")
		}
	})
	t.Run("duplicate_handle_refused", func(t *testing.T) {
		o := &originalFixtureOwners{}
		if o.registerOriginalMainPrivateSourceHandle("one-original-handle") != nil || o.registerOriginalMainPrivateSourceHandle("one-original-handle") == nil || len(o.mainPrivateSourceHandles) != 1 {
			t.Fatal("duplicate acquisition overwrote/extended the census")
		}
	})
	t.Run("eighth_handle_refused_before_effect", func(t *testing.T) {
		o, _, _ := makeOwner(t)
		if o.registerOriginalMainPrivateSourceHandle("eighth-original-handle") == nil || len(o.mainPrivateSourceHandles) != 7 {
			t.Fatal("extra acquisition entered the fixed Main census")
		}
	})
	t.Run("late_handle_refused_after_copy", func(t *testing.T) {
		o, call, _ := makeOwner(t)
		if o.copyOriginalMainPrivateSourceAuditReferences(call) != nil || o.registerOriginalMainPrivateSourceHandle("late-original-handle") == nil {
			t.Fatal("cleanup snapshot accepted a later acquisition")
		}
	})
	t.Run("duplicate_copy_preserves_original_selection", func(t *testing.T) {
		o, call, refs := makeOwner(t)
		if o.copyOriginalMainPrivateSourceAuditReferences(call) != nil || o.copyOriginalMainPrivateSourceAuditReferences(call) == nil || !reflect.DeepEqual(call.SourceAuditCallReferences, refs) {
			t.Fatal("duplicate cleanup capture replaced original references")
		}
	})
	t.Run("incomplete_census_refused", func(t *testing.T) {
		o, call, _ := makeOwner(t)
		o.mainPrivateSourceHandles = o.mainPrivateSourceHandles[:6]
		if o.copyOriginalMainPrivateSourceAuditReferences(call) == nil || len(call.SourceAuditCallReferences) != 0 {
			t.Fatal("partial Main inventory became a complete selection")
		}
	})
	t.Run("foreign_subject_on_registered_handle_refused", func(t *testing.T) {
		o, call, _ := makeOwner(t)
		o.audits[0].SubjectIdentity.SubjectKind = "main_db"
		if o.copyOriginalMainPrivateSourceAuditReferences(call) == nil || len(call.SourceAuditCallReferences) != 0 {
			t.Fatal("foreign audit substituted for a Main private stream")
		}
	})
	t.Run("main_record_cap_refuses_without_truncation", func(t *testing.T) {
		o, call, _ := makeOwner(t)
		if o.copyOriginalMainPrivateSourceAuditReferences(call) != nil || !originalMainReturnRecordBounded(call) {
			t.Fatal("ordinary Source-only record does not fit its existing consumer cap")
		}
		call.SourceAuditCallReferences = append(call.SourceAuditCallReferences, strings.Repeat("private-reference-not-bytes", 3000))
		before := append([]string(nil), call.SourceAuditCallReferences...)
		if originalMainReturnRecordBounded(call) || !reflect.DeepEqual(before, call.SourceAuditCallReferences) {
			t.Fatal("over-cap history was clipped or accepted")
		}
	})
}
