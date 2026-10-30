package repository

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestOriginalDispositionAWS1653AdjunctObservation(t *testing.T) {
	for _, source := range []string{originalDispositionAWSOriginalSource, originalDispositionAWS1653OriginalSource} {
		t.Run(source, func(t *testing.T) {
			c, o, now := originalDispositionAWSAdjunctFixture(t)
			c.Request.OriginalAdapterSourceCommit = source
			o.OriginalAdapterSourceCommit = source
			original, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			if err = validateOriginalDispositionObservation(c, o, now.Add(-2*time.Second), now, 30*time.Second); err != nil {
				t.Fatal(err)
			}
			after, err := json.Marshal(c)
			if err != nil || string(original) != string(after) || c.Request.OriginalAuxiliaryInventoryComplete || len(c.Request.AuxiliaryResources) != 0 {
				t.Fatal("native adjunct altered original unknown inventory")
			}
			cases := []struct {
				name   string
				mutate func(*model.CapacityOriginalCreateDispositionCandidate, *model.CapacityOriginalCreateDispositionObservation)
			}{
				{"foreign_creator", func(c *model.CapacityOriginalCreateDispositionCandidate, o *model.CapacityOriginalCreateDispositionObservation) {
					c.Request.OriginalAdapterSourceCommit = strings.Repeat("a", 40)
					o.OriginalAdapterSourceCommit = c.Request.OriginalAdapterSourceCommit
				}},
				{"uppercase_creator", func(c *model.CapacityOriginalCreateDispositionCandidate, o *model.CapacityOriginalCreateDispositionObservation) {
					c.Request.OriginalAdapterSourceCommit = strings.ToUpper(source)
					o.OriginalAdapterSourceCommit = c.Request.OriginalAdapterSourceCommit
				}},
				{"creator_mismatch", func(c *model.CapacityOriginalCreateDispositionCandidate, o *model.CapacityOriginalCreateDispositionObservation) {
					o.OriginalAdapterSourceCommit = strings.Repeat("b", 40)
				}},
				{"partial_one_auxiliary", func(c *model.CapacityOriginalCreateDispositionCandidate, o *model.CapacityOriginalCreateDispositionObservation) {
					c.Request.AuxiliaryResources = []model.CapacityMutationAuxiliaryResource{{Kind: "aws_ebs_volume", ID: "vol-0123456789abcdef0", RequiresAbsence: true}}
				}},
				{"partial_two_auxiliaries", func(c *model.CapacityOriginalCreateDispositionCandidate, o *model.CapacityOriginalCreateDispositionObservation) {
					c.Request.AuxiliaryResources = []model.CapacityMutationAuxiliaryResource{{Kind: "aws_ebs_volume", ID: "vol-0123456789abcdef0", RequiresAbsence: true}, {Kind: "aws_network_interface", ID: "eni-0123456789abcdef0", RequiresAbsence: true}}
				}},
				{"known_inventory_empty", func(c *model.CapacityOriginalCreateDispositionCandidate, o *model.CapacityOriginalCreateDispositionObservation) {
					c.Request.OriginalAuxiliaryInventoryComplete = true
				}},
				{"running_instance", func(c *model.CapacityOriginalCreateDispositionCandidate, o *model.CapacityOriginalCreateDispositionObservation) {
					o.ResourceState = "running"
				}},
				{"missing_sixth_read", func(c *model.CapacityOriginalCreateDispositionCandidate, o *model.CapacityOriginalCreateDispositionObservation) {
					o.NativeReads = o.NativeReads[:5]
				}},
				{"retained_auxiliary", func(c *model.CapacityOriginalCreateDispositionCandidate, o *model.CapacityOriginalCreateDispositionObservation) {
					o.AuxiliaryResources[0].Absent = false
				}},
				{"unjoined_action", func(c *model.CapacityOriginalCreateDispositionCandidate, o *model.CapacityOriginalCreateDispositionObservation) {
					c.Request.OriginalCreateActionID = uuid.NewString()
				}},
				{"native_mutation", func(c *model.CapacityOriginalCreateDispositionCandidate, o *model.CapacityOriginalCreateDispositionObservation) {
					o.NativeMutations = 1
				}},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					bad := c
					observation := cloneDispositionObservation(o)
					tc.mutate(&bad, &observation)
					if validateOriginalDispositionObservation(bad, observation, now.Add(-2*time.Second), now, 30*time.Second) == nil {
						t.Fatal("invalid adjunct accepted")
					}
				})
			}
		})
	}
}

func TestOriginalDispositionAWS1653AdjunctPostgres(t *testing.T) {
	db := originalDispositionPG(t)
	f := originalDispositionPGFixture(t, db)
	f.record.Binding.OriginalProviderSourceCommit = originalDispositionAWS1653OriginalSource
	f.record.Settlement.OriginalProviderCreateReturn.AdapterSourceCommit = originalDispositionAWS1653OriginalSource
	f.record.Settlement.AuxiliaryInventoryComplete = false
	f.record.Settlement.AuxiliaryResources = nil
	action := uuid.NewString()
	f.record.Settlement.ActionID = action
	f.record.Settlement.OriginalProviderCreateReturn.ActionID = action
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	update := func() {
		t.Helper()
		raw, err := json.Marshal(f.record)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `UPDATE public.capacity_mutation_grants SET grant_record=$2::jsonb WHERE id=$1`, f.pre.OriginalCreateGrantID, string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []int{1, 2} {
		f.record.Settlement.AuxiliaryResources = make([]model.CapacityMutationAuxiliaryResource, n)
		for i := range f.record.Settlement.AuxiliaryResources {
			f.record.Settlement.AuxiliaryResources[i] = model.CapacityMutationAuxiliaryResource{Kind: "aws_ebs_volume", ID: "vol-0123456789abcdef0", RequiresAbsence: true}
		}
		update()
		if _, err := f.store.BeginOriginalCreateDisposition(ctx, f.pre.OriginalCreateGrantID, "isolated-1653-partial-inventory"); err == nil {
			t.Fatal("partial original AUX list accepted as unknown inventory")
		}
	}
	f.record.Settlement.AuxiliaryResources = nil
	f.record.Settlement.AuxiliaryInventoryComplete = true
	update()
	if _, err := f.store.BeginOriginalCreateDisposition(ctx, f.pre.OriginalCreateGrantID, "isolated-1653-known-empty"); err == nil {
		t.Fatal("known empty original inventory accepted")
	}
	f.record.Settlement.AuxiliaryInventoryComplete = false
	update()
	var original string
	if err := db.QueryRowContext(ctx, `SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, f.pre.OriginalCreateGrantID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	owner, err := f.store.BeginOriginalCreateDisposition(ctx, f.pre.OriginalCreateGrantID, "isolated-1653-adjunct")
	if err != nil {
		t.Fatal(err)
	}
	c := owner.Candidate()
	if c.Request.OriginalAdapterSourceCommit != originalDispositionAWS1653OriginalSource || c.Receipt.AuxiliaryInventoryComplete || c.Request.OriginalAuxiliaryInventoryComplete || len(c.Request.AuxiliaryResources) != 0 || c.Request.OriginalCreateActionID != action {
		t.Fatal("candidate rewrote original creator or unknown inventory")
	}
	_, o, now := originalDispositionAWSAdjunctFixture(t)
	o.Profile, o.Slot, o.GrantID, o.AttemptID = c.Request.Profile, c.Request.Slot, c.Request.GrantID, c.Request.AttemptID
	o.RequestSHA256, o.ResourceID, o.ResourceCreatedAt = c.Request.RequestSHA256, c.Request.ExpectedResourceID, c.Request.ExpectedResourceCreatedAt
	o.OriginalAdapterSourceCommit = c.Request.OriginalAdapterSourceCommit
	o.NativeReads[1].ResourceID = o.ResourceID
	shift := time.Since(now) + 2*time.Second
	o.ObservationStartedAt, o.ObservedAt = o.ObservationStartedAt.Add(shift), o.ObservedAt.Add(shift)
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
	if err = db.QueryRowContext(ctx, `SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, f.pre.OriginalCreateGrantID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if original != after || result.OriginalAuxiliaryInventoryComplete || !reflect.DeepEqual(result.Observation.AuxiliaryResources, o.AuxiliaryResources) {
		t.Fatal("disposition altered original settlement or native adjunct")
	}
}
