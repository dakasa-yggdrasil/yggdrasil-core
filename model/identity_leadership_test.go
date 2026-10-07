package model

import (
	"encoding/json"
	"testing"
)

func TestTeamLeadershipFieldPresence(t *testing.T) {
	for _, tc := range []struct {
		body                   string
		wantPresent, wantError bool
	}{
		{`{"name":"rename"}`, false, false},
		{`{"owners":[]}`, true, false},
		{`{"owners":null}`, false, true},
	} {
		var r UpdateTeamRequest
		err := json.Unmarshal([]byte(tc.body), &r)
		if (err != nil) != tc.wantError || !tc.wantError && (r.Owners != nil) != tc.wantPresent {
			t.Fatal("owners field presence changed")
		}
	}
}
