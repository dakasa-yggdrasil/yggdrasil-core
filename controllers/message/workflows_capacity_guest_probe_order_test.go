//go:build linux && nativequalification

package message

import (
	"errors"
	"reflect"
	"testing"
)

func TestSourceFailedFloorProbeOrder(t *testing.T) {
	for _, tc := range []struct {
		name, nativeCase string
		floor            int
		slots, want      []int
	}{
		{"canonical", "canonical_failed_floor_recovery", 2, []int{1, 2}, []int{2, 1}},
		{"source_live", "source_live_failed_floor_recovery", 2, []int{1, 2}, []int{2, 1}},
		{"other_case", "canonical_compensation_protected_failed_create", 2, []int{1, 2}, []int{1, 2}},
		{"wrong_floor", "canonical_failed_floor_recovery", 1, []int{1, 2}, []int{1, 2}},
		{"missing", "canonical_failed_floor_recovery", 2, []int{1}, []int{1}},
		{"duplicate", "canonical_failed_floor_recovery", 2, []int{1, 1}, []int{1, 1}},
		{"foreign", "canonical_failed_floor_recovery", 2, []int{1, 3}, []int{1, 3}},
		{"already_reversed", "canonical_failed_floor_recovery", 2, []int{2, 1}, []int{2, 1}},
		{"extra", "canonical_failed_floor_recovery", 2, []int{1, 2, 3}, []int{1, 2, 3}},
		{"empty", "canonical_failed_floor_recovery", 2, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := append([]int(nil), tc.slots...)
			got := sourceFailedFloorProbeOrder(tc.nativeCase, tc.floor, tc.slots)
			if !reflect.DeepEqual(got, tc.want) || !reflect.DeepEqual(tc.slots, original) {
				t.Fatalf("order=%v original=%v, want %v and %v", got, tc.slots, tc.want, original)
			}
		})
	}
}

func TestQualificationRequiresEveryOriginalGuestBeforeAdvance(t *testing.T) {
	failed := errors.New("original guest held")
	for _, tc := range []struct {
		name        string
		failSlot    int
		wantCalls   []int
		wantAdvance bool
	}{
		{"first_guest_fails", 2, []int{2}, false},
		{"second_guest_fails", 1, []int{2, 1}, false},
		{"both_guests_complete", 0, []int{2, 1}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := []int{}
			advanced := false
			err := qualifyEveryOriginalGuest([]int{2, 1}, func(slot int) error {
				calls = append(calls, slot)
				if slot == tc.failSlot {
					return failed
				}
				return nil
			}, func() error {
				advanced = true
				return nil
			})
			if !reflect.DeepEqual(calls, tc.wantCalls) || advanced != tc.wantAdvance || (tc.failSlot != 0 && !errors.Is(err, failed)) || (tc.failSlot == 0 && err != nil) {
				t.Fatalf("calls=%v advance=%t err=%v", calls, advanced, err)
			}
		})
	}
}
