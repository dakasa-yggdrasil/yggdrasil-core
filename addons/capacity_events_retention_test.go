package addons

import (
	"testing"
	"time"
)

func TestCapacityRetentionIsExplicitAndBounded(t *testing.T) {
	get := func(values map[string]string) func(string) string {
		return func(key string) string { return values[key] }
	}
	settings, err := capacityRetentionConfig(get(nil))
	if err != nil || settings.enabled {
		t.Fatal("retention enabled by default", settings, err)
	}
	settings, err = capacityRetentionConfig(get(map[string]string{"YGGDRASIL_CAPACITY_EVENT_RETENTION_ENABLED": "false", "YGGDRASIL_CAPACITY_EVENT_RETENTION_DAYS": "invalid"}))
	if err != nil || settings.enabled {
		t.Fatal("disabled maintenance parsed inactive settings", settings, err)
	}
	settings, err = capacityRetentionConfig(get(map[string]string{"YGGDRASIL_CAPACITY_EVENT_RETENTION_ENABLED": "true"}))
	if err != nil || !settings.enabled || settings.days != 90 || settings.batch != 1000 || settings.interval != 15*time.Minute {
		t.Fatal("incorrect explicit defaults", settings, err)
	}
	for key, values := range map[string][]string{
		"YGGDRASIL_CAPACITY_EVENT_RETENTION_ENABLED":          {"1", "TRUE", " true"},
		"YGGDRASIL_CAPACITY_EVENT_RETENTION_DAYS":             {"0", "29", "3651", "broken"},
		"YGGDRASIL_CAPACITY_EVENT_RETENTION_BATCH":            {"0", "1001", "broken"},
		"YGGDRASIL_CAPACITY_EVENT_RETENTION_INTERVAL_SECONDS": {"0", "59", "86401", "broken"},
	} {
		for _, value := range values {
			t.Run(key+"="+value, func(t *testing.T) {
				config := map[string]string{"YGGDRASIL_CAPACITY_EVENT_RETENTION_ENABLED": "true", key: value}
				if _, err := capacityRetentionConfig(get(config)); err == nil {
					t.Fatal("invalid maintenance setting accepted")
				}
			})
		}
	}
}
