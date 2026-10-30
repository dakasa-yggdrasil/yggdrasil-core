package httpapi

import (
	"reflect"
	"testing"
)

func TestMergeStringAnyMapsPreservesOverridesAndInputs(t *testing.T) {
	base := map[string]any{"original": "kept", "shared": "base"}
	extra := map[string]any{"added": "new", "shared": "replacement"}
	got := mergeStringAnyMaps(base, extra)
	want := map[string]any{"original": "kept", "added": "new", "shared": "replacement"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged values differ: got %#v", got)
	}
	got["original"] = "changed"
	if base["original"] != "kept" || extra["shared"] != "replacement" {
		t.Fatal("merge modified its inputs")
	}
	if mergeStringAnyMaps(nil, nil) != nil {
		t.Fatal("empty merge must remain nil")
	}
}
