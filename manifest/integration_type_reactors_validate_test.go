package manifest

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestValidateReactors(t *testing.T) {
	cases := []struct {
		name string
		spec string
		want error
	}{
		{
			name: "no reactors block — ok",
			spec: `{"action_catalog":[]}`,
			want: nil,
		},
		{
			name: "valid reactor",
			spec: `{"action_catalog":[{"name":"on_collaborator_created"}],
			        "reactors":[{"event_type":"collaborator.created","capability":"on_collaborator_created"}]}`,
			want: nil,
		},
		{
			name: "event_type out of canon",
			spec: `{"action_catalog":[{"name":"on_foo"}],
			        "reactors":[{"event_type":"foo.bar","capability":"on_foo"}]}`,
			want: ErrReactorEventTypeNotCanon,
		},
		{
			name: "capability missing from action_catalog",
			spec: `{"action_catalog":[{"name":"x"}],
			        "reactors":[{"event_type":"collaborator.created","capability":"on_collaborator_created"}]}`,
			want: ErrReactorCapabilityNotInCatalog,
		},
		{
			name: "duplicate event_type",
			spec: `{"action_catalog":[{"name":"a"},{"name":"b"}],
			        "reactors":[
			          {"event_type":"team.created","capability":"a"},
			          {"event_type":"team.created","capability":"b"}
			        ]}`,
			want: ErrReactorDuplicateEventType,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var spec map[string]any
			if err := json.Unmarshal([]byte(tc.spec), &spec); err != nil {
				t.Fatalf("setup: %v", err)
			}
			err := ValidateReactors(spec)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
}
