package externalidentity

import "testing"

func TestMetadataEqual(t *testing.T) {
	cases := []struct {
		name string
		a, b map[string]any
		want bool
	}{
		{"both empty", nil, map[string]any{}, true},
		{"identical", map[string]any{"x": "y"}, map[string]any{"x": "y"}, true},
		{"diff value", map[string]any{"x": "y"}, map[string]any{"x": "z"}, false},
		{"extra key", map[string]any{"x": "y"}, map[string]any{"x": "y", "k": 1}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := metadataEqual(tc.a, tc.b); got != tc.want {
				t.Fatalf("metadataEqual = %v want %v", got, tc.want)
			}
		})
	}
}
