package repository

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestNativeReadinessPostgresOriginalCreateAndDeleteKeepSeparateTokenPurposes(t *testing.T) {
	f, a, s := nativeReadinessJournalFixture(t)
	r, keys, err := s.open(t.Context(), a, nativeReadinessGenerateKeys)
	clear(keys)
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.begin(t.Context(), a, r, "candidate_pod", strings.Repeat("4", 64))
	if err != nil {
		t.Fatal(err)
	}
	var first string
	r, first, err = s.redeem(t.Context(), a, r, "candidate_pod")
	if err != nil {
		t.Fatal(err)
	}
	create := model.NativeWorkerProbeResourceReceive{BindingName: "journal-fixture", RunID: r.ID.String(), Slot: "candidate_pod", SettlementToken: first, HTTPStatus: 201, TransportCompleted: true, CompletedAt: time.Now().UTC(), OriginalReturn: []byte(`{"synthetic_low_level_custody":"never_a_qualified_kubernetes_ack"}`)}
	r, err = s.captureOriginal(t.Context(), r, create)
	if err != nil {
		t.Fatal(err)
	}
	// This low-level state helper exists only to exercise purpose/key custody.
	// It grants neither an actual Pod identity nor a producer readiness proof.
	uid := uuid.NewString()
	r, err = s.receive(t.Context(), r, "candidate_pod", uid, strings.Repeat("4", 64), strings.Repeat("5", 64), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.beginDelete(t.Context(), r, "candidate_pod")
	if err != nil {
		t.Fatal(err)
	}
	var second string
	r, second, err = s.redeem(t.Context(), a, r, "candidate_pod")
	if err != nil || first == second {
		t.Fatal("cleanup did not receive a distinct one-shot token", err)
	}
	deleted := model.NativeWorkerProbeResourceReceive{BindingName: create.BindingName, RunID: create.RunID, Slot: create.Slot, SettlementToken: second, HTTPStatus: 202, TransportCompleted: true, CompletedAt: time.Now().UTC(), OriginalReturn: []byte(`{"synthetic_low_level_delete":"not_absence"}`)}
	r, err = s.captureOriginal(t.Context(), r, deleted)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		deleted  bool
		original model.NativeWorkerProbeResourceReceive
	}{{false, create}, {true, deleted}} {
		got, err := s.original(r, "candidate_pod", item.deleted)
		if err != nil {
			t.Fatal("cleanup overwrote the original AEAD token purpose", err)
		}
		want, err := item.original.MarshalPrivateJSON()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("original private response was replaced across cleanup")
		}
		clear(got)
		clear(want)
	}
	altered := r
	altered.Effects = append([]nativeReadinessEffect(nil), r.Effects...)
	i, _ := nativeReadinessEffectIndex(altered, "candidate_pod")
	altered.Effects[i].CreateTokenSHA256 = altered.Effects[i].DeleteTokenSHA256
	if raw, err := s.original(altered, "candidate_pod", false); err == nil || raw != nil {
		t.Fatal("delete settlement token opened create original")
	}
	var row []byte
	if err = f.db.QueryRowContext(t.Context(), `SELECT record FROM public.capacity_native_worker_readiness_runs WHERE attempt_id=$1`, a.ID).Scan(&row); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(row, []byte(first)) || bytes.Contains(row, []byte(second)) || bytes.Contains(row, create.OriginalReturn) || bytes.Contains(row, deleted.OriginalReturn) {
		t.Fatal("SQL projection contains private settlement/original plaintext")
	}
	var actual nativeReadinessRun
	if json.Unmarshal(row, &actual) != nil || actual.ID != r.ID || actual.Revision != r.Revision || actual.Effects[i].State != "delete_received" || actual.Proof != nil {
		t.Fatal("private custody fabricated absent/readiness or lost original identity")
	}
}
