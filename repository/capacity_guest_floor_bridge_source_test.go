//go:build linux && nativequalification

package repository

import "testing"

func TestSourceFloorPolicyExactDelta(t *testing.T) {
	const before = `{"floor":1,"ceiling":2,"profiles":[{"name":"native","min_units":1,"max_units":2}],"other":{"fixed":true}}`
	tests := []struct {
		name, after string
		want        bool
	}{
		{"exact floor and profile minimum", `{"other":{"fixed":true},"profiles":[{"max_units":2,"min_units":2,"name":"native"}],"ceiling":2,"floor":2}`, true},
		{"missing profile adjustment", `{"floor":2,"ceiling":2,"profiles":[{"name":"native","min_units":1,"max_units":2}],"other":{"fixed":true}}`, false},
		{"missing floor adjustment", `{"floor":1,"ceiling":2,"profiles":[{"name":"native","min_units":2,"max_units":2}],"other":{"fixed":true}}`, false},
		{"changed other field", `{"floor":2,"ceiling":2,"profiles":[{"name":"native","min_units":2,"max_units":2}],"other":{"fixed":false}}`, false},
		{"changed profile field", `{"floor":2,"ceiling":2,"profiles":[{"name":"foreign","min_units":2,"max_units":2}],"other":{"fixed":true}}`, false},
		{"additional profile", `{"floor":2,"ceiling":2,"profiles":[{"name":"native","min_units":2,"max_units":2},{"name":"foreign","min_units":2,"max_units":2}],"other":{"fixed":true}}`, false},
		{"missing profile", `{"floor":2,"ceiling":2,"profiles":[],"other":{"fixed":true}}`, false},
		{"wrong type", `{"floor":2,"ceiling":2,"profiles":[{"name":"native","min_units":"2","max_units":2}],"other":{"fixed":true}}`, false},
		{"extra field", `{"floor":2,"ceiling":2,"profiles":[{"name":"native","min_units":2,"max_units":2}],"other":{"fixed":true},"extra":1}`, false},
		{"invalid json", `{`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sourceFloorPolicyExactDelta([]byte(before), []byte(tc.after)); got != tc.want {
				t.Fatalf("sourceFloorPolicyExactDelta = %v, want %v", got, tc.want)
			}
		})
	}
}
