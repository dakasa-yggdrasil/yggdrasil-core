package repository

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func originalDispositionAWSAdjunctFixture(t *testing.T) (model.CapacityOriginalCreateDispositionCandidate, model.CapacityOriginalCreateDispositionObservation, time.Time) {
	t.Helper()
	c, o, now := originalDispositionObservationFixture(t)
	c.Request.OriginalAuxiliaryInventoryComplete = false
	c.Request.OriginalAdapterSourceCommit = originalDispositionAWSOriginalSource
	o.OriginalAdapterSourceCommit = originalDispositionAWSOriginalSource
	c.Request.AuxiliaryResources = []model.CapacityMutationAuxiliaryResource{}
	c.Request.OriginalCreateActionID = "7f07aca4-1901-4cd6-bb42-7cc8a251ab06"
	c.Receipt.ActionID = c.Request.OriginalCreateActionID
	o.InventoryBasis = "aws_original_run_instances_cloudtrail_root_snapshot_absence_v1"
	o.AuxiliaryResources = []model.CapacityVMAuxiliaryObservation{{Kind: "aws_ebs_snapshot_descendants", ID: "snap-0123456789abcdef0", Absent: true, ObservedAt: now.Format(time.RFC3339Nano)}, {Kind: "aws_network_interface", ID: "eni-0123456789abcdef0", Absent: true, ObservedAt: now.Format(time.RFC3339Nano)}}
	o.NativeReads = nil
	rows := []struct {
		operation, kind, id string
		status              int
	}{{"GetCallerIdentity", "aws_account", "123456789012", 200}, {"DescribeInstances", "aws_ec2_instance", o.ResourceID, 200}, {"LookupEvents", "aws_cloudtrail_event", uuid.NewString(), 200}, {"DescribeImages", "aws_ami", "ami-0123456789abcdef0", 200}, {"DescribeVolumes", "aws_ebs_snapshot_descendants", o.AuxiliaryResources[0].ID, 200}, {"DescribeNetworkInterfaces", "aws_network_interface", o.AuxiliaryResources[1].ID, 400}}
	for i, r := range rows {
		raw := []byte("<original-adjunct-read/>")
		called := o.ObservationStartedAt.Add(time.Duration(i) * 100 * time.Millisecond)
		o.NativeReads = append(o.NativeReads, model.CapacityOriginalCreateDispositionNativeRead{Operation: r.operation, ResourceKind: r.kind, ResourceID: r.id, Status: r.status, ResponseSHA256: originalDispositionDigest(raw), ResponseBytes: int64(len(raw)), ResponseBodyBase64: base64.StdEncoding.EncodeToString(raw), ResponseRepresentation: "raw_http_body_v1", CalledAt: called, ReturnedAt: called.Add(50 * time.Millisecond)})
	}
	return c, o, now
}

func TestOriginalDispositionAWSAdjunctCoverage(t *testing.T) {
	c, o, now := originalDispositionAWSAdjunctFixture(t)
	if err := validateOriginalDispositionObservation(c, o, now.Add(-2*time.Second), now, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(c.Request)
	if !strings.Contains(string(raw), `"original_auxiliary_inventory_complete":false`) || !strings.Contains(string(raw), `"auxiliary_resources":[]`) {
		t.Fatal("original unknown inventory rewritten")
	}
	for name, mutate := range map[string]func(*model.CapacityOriginalCreateDispositionObservation){
		"wrong_basis": func(o *model.CapacityOriginalCreateDispositionObservation) {
			o.InventoryBasis = "authenticated_complete_owned_inventory_v1"
		},
		"only_tag_census": func(o *model.CapacityOriginalCreateDispositionObservation) {
			o.NativeReads[4].Operation = "DescribeVolumesByGrantTag"
		},
		"missing_native_row":   func(o *model.CapacityOriginalCreateDispositionObservation) { o.NativeReads = o.NativeReads[:5] },
		"duplicate_native_row": func(o *model.CapacityOriginalCreateDispositionObservation) { o.NativeReads[3] = o.NativeReads[2] },
		"wrong_account_kind": func(o *model.CapacityOriginalCreateDispositionObservation) {
			o.NativeReads[0].ResourceKind = "unscoped"
		},
		"wrong_account_id":      func(o *model.CapacityOriginalCreateDispositionObservation) { o.NativeReads[0].ResourceID = "unknown" },
		"foreign_instance":      func(o *model.CapacityOriginalCreateDispositionObservation) { o.NativeReads[1].ResourceID = "i-other" },
		"wrong_cloudtrail_kind": func(o *model.CapacityOriginalCreateDispositionObservation) { o.NativeReads[2].ResourceKind = "aws_ami" },
		"wrong_event_id": func(o *model.CapacityOriginalCreateDispositionObservation) {
			o.NativeReads[2].ResourceID = "unidentified"
		},
		"wrong_ami_id": func(o *model.CapacityOriginalCreateDispositionObservation) { o.NativeReads[3].ResourceID = "snapshot" },
		"snapshot_filter_not_original": func(o *model.CapacityOriginalCreateDispositionObservation) {
			o.NativeReads[4].ResourceID = "snap-fffffffffffffffff"
		},
		"eni_id_mismatch": func(o *model.CapacityOriginalCreateDispositionObservation) {
			o.NativeReads[5].ResourceID = "eni-fffffffffffffffff"
		},
		"eni_not_found_not_observed": func(o *model.CapacityOriginalCreateDispositionObservation) { o.NativeReads[5].Status = 200 },
		"wrong_auxiliary_order": func(o *model.CapacityOriginalCreateDispositionObservation) {
			o.AuxiliaryResources[0], o.AuxiliaryResources[1] = o.AuxiliaryResources[1], o.AuxiliaryResources[0]
		},
		"snapshot_census_missing": func(o *model.CapacityOriginalCreateDispositionObservation) {
			o.AuxiliaryResources = o.AuxiliaryResources[1:]
		},
		"snapshot_census_unknown": func(o *model.CapacityOriginalCreateDispositionObservation) { o.AuxiliaryResources[0].Absent = false },
		"cross_provider":          func(o *model.CapacityOriginalCreateDispositionObservation) { o.Provider = "hetzner" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := cloneDispositionObservation(o)
			mutate(&bad)
			if validateOriginalDispositionObservation(c, bad, now.Add(-2*time.Second), now, 30*time.Second) == nil {
				t.Fatal("incomplete/misbound adjunct accepted")
			}
		})
	}
	foreign := c
	foreign.Request.OriginalAdapterSourceCommit = strings.Repeat("a", 40)
	foreignObservation := cloneDispositionObservation(o)
	foreignObservation.OriginalAdapterSourceCommit = foreign.Request.OriginalAdapterSourceCommit
	if validateOriginalDispositionObservation(foreign, foreignObservation, now.Add(-2*time.Second), now, 30*time.Second) == nil {
		t.Fatal("foreign original creator source inferred single-root semantics")
	}
	for _, id := range []string{"", strings.ToUpper(c.Request.OriginalCreateActionID), uuid.NewString()} {
		bad := c
		bad.Request.OriginalCreateActionID = id
		if validateOriginalDispositionObservation(bad, o, now.Add(-2*time.Second), now, 30*time.Second) == nil {
			t.Fatal("unjoined owning request action accepted")
		}
	}
}

func TestOriginalDispositionAWSAdjunctPostgres(t *testing.T) {
	db := originalDispositionPG(t)
	f := originalDispositionPGFixture(t, db)
	f.record.Settlement.AuxiliaryInventoryComplete = false
	f.record.Settlement.AuxiliaryResources = nil
	action := uuid.NewString()
	f.record.Settlement.ActionID = action
	f.record.Settlement.OriginalProviderCreateReturn.ActionID = action
	raw, _ := json.Marshal(f.record)
	if _, err := db.Exec(`UPDATE public.capacity_mutation_grants SET grant_record=$2::jsonb WHERE id=$1`, f.pre.OriginalCreateGrantID, string(raw)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := f.store.BeginOriginalCreateDisposition(ctx, f.pre.OriginalCreateGrantID, "isolated-foreign-source-test"); err == nil {
		t.Fatal("foreign original source obtained unknown-inventory candidate")
	}
	f.record.Binding.OriginalProviderSourceCommit = originalDispositionAWSOriginalSource
	f.record.Settlement.OriginalProviderCreateReturn.AdapterSourceCommit = originalDispositionAWSOriginalSource
	raw, _ = json.Marshal(f.record)
	if _, err := db.Exec(`UPDATE public.capacity_mutation_grants SET grant_record=$2::jsonb WHERE id=$1`, f.pre.OriginalCreateGrantID, string(raw)); err != nil {
		t.Fatal(err)
	}
	var original string
	if err := db.QueryRow(`SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, f.pre.OriginalCreateGrantID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	owner, err := f.store.BeginOriginalCreateDisposition(ctx, f.pre.OriginalCreateGrantID, "isolated-adjunct-test")
	if err != nil {
		t.Fatal(err)
	}
	c := owner.Candidate()
	if c.Receipt.AuxiliaryInventoryComplete || c.Request.OriginalAuxiliaryInventoryComplete || len(c.Request.AuxiliaryResources) != 0 || c.Request.OriginalCreateActionID != action {
		t.Fatal("original unknown inventory altered")
	}
	_, o, now := originalDispositionAWSAdjunctFixture(t)
	o.Profile = c.Request.Profile
	o.Slot = c.Request.Slot
	o.GrantID = c.Request.GrantID
	o.AttemptID = c.Request.AttemptID
	o.RequestSHA256 = c.Request.RequestSHA256
	o.ResourceID = c.Request.ExpectedResourceID
	o.ResourceCreatedAt = c.Request.ExpectedResourceCreatedAt
	o.OriginalAdapterSourceCommit = c.Request.OriginalAdapterSourceCommit
	o.NativeReads[1].ResourceID = o.ResourceID
	// Construct a declaration-only fixture within the actual owner interval.
	shift := time.Since(now) + 2*time.Second
	o.ObservationStartedAt = o.ObservationStartedAt.Add(shift)
	o.ObservedAt = o.ObservedAt.Add(shift)
	for i := range o.NativeReads {
		o.NativeReads[i].CalledAt = o.NativeReads[i].CalledAt.Add(shift)
		o.NativeReads[i].ReturnedAt = o.NativeReads[i].ReturnedAt.Add(shift)
	}
	for i := range o.AuxiliaryResources {
		o.AuxiliaryResources[i].ObservedAt = o.ObservedAt.Format(time.RFC3339Nano)
	}
	result, err := f.store.CompleteOriginalCreateDisposition(ctx, owner, o)
	if err != nil {
		t.Fatal(err)
	}
	var after string
	if err := db.QueryRow(`SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, f.pre.OriginalCreateGrantID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if original != after || result.OriginalAuxiliaryInventoryComplete || result.Observation.InventoryBasis != o.InventoryBasis || len(result.Observation.AuxiliaryResources) != 2 {
		t.Fatal("adjunct rewrote original unknown flag or original settlement")
	}
}
