package manifest

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func originalNotifyResourcePolicyFixture() *model.CapacityNativeNotifyWindowBinding {
	resources := []model.CapacityNativeNotifyResource{}
	for _, actor := range []string{"notify-a", "notify-b"} {
		resources = append(resources, model.CapacityNativeNotifyResource{PodName: actor, Kind: "postgres_retained_session_v1", ResourceName: "notify_primary_pg_session", BindingSHA256: strings.Repeat("a", 64), Database: "notify", DatabaseOID: "42", SystemIdentifier: "77", Role: "notify"})
	}
	return &model.CapacityNativeNotifyWindowBinding{Participants: []model.CapacityNativeNotifyParticipant{{PodName: "notify-a"}, {PodName: "notify-b"}}, RequiredResources: resources}
}

func TestOriginalNotifyResourceRosterPolicy(t *testing.T) {
	if validateNativeNotifyResourceRoster(originalNotifyResourcePolicyFixture()) != nil {
		t.Fatal("complete two-actor sealed resource roster refused")
	}
	for _, kind := range []string{"missing_actor", "foreign_actor", "duplicate", "unordered", "unknown_kind", "noncanonical_oid", "foreign_binding", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			b := originalNotifyResourcePolicyFixture()
			switch kind {
			case "missing_actor":
				b.RequiredResources = b.RequiredResources[:1]
			case "foreign_actor":
				b.RequiredResources[1].PodName = "notify-c"
			case "duplicate":
				b.RequiredResources[1] = b.RequiredResources[0]
			case "unordered":
				b.RequiredResources[0], b.RequiredResources[1] = b.RequiredResources[1], b.RequiredResources[0]
			case "unknown_kind":
				b.RequiredResources[1].Kind = "caller_warm_claim"
			case "noncanonical_oid":
				b.RequiredResources[1].DatabaseOID = "042"
			case "foreign_binding":
				b.RequiredResources[1].BindingSHA256 = "native-facts-unknown"
			case "oversized":
				b.RequiredResources = make([]model.CapacityNativeNotifyResource, 33)
			}
			if validateNativeNotifyResourceRoster(b) == nil {
				t.Fatal("incomplete or ambiguous resource roster accepted")
			}
		})
	}
	t.Run("unsupported_dependency_stays_declared", func(t *testing.T) {
		b := originalNotifyResourcePolicyFixture()
		b.RequiredResources[1] = model.CapacityNativeNotifyResource{PodName: "notify-b", Kind: "redis_retained_connection_v1", ResourceName: "redis", BindingSHA256: strings.Repeat("a", 64)}
		if validateNativeNotifyResourceRoster(b) != nil || len(b.RequiredResources) != 2 {
			t.Fatal("unimplemented dependency erased from the sealed roster")
		}
	})
	t.Run("absence_is_legacy_present_empty_or_null_is_not", func(t *testing.T) {
		b := originalNotifyResourcePolicyFixture()
		b.RequiredResources = nil
		binding, _ := json.Marshal(b)
		var members map[string]json.RawMessage
		if json.Unmarshal(binding, &members) != nil {
			t.Fatal("protocol binding encoding failed")
		}
		encode := func() []byte {
			raw, _ := json.Marshal(map[string]any{"native_notify_window_binding": members})
			return raw
		}
		if validateNativeNotifyWindowJSON(encode()) != nil {
			t.Fatal("absent optional resource roster changed legacy decoding")
		}
		for _, value := range []string{"[]", "null"} {
			members["required_resources"] = json.RawMessage(value)
			if validateNativeNotifyWindowJSON(encode()) == nil {
				t.Fatal("present empty/null roster silently disabled the prerequisite")
			}
		}
	})
}
