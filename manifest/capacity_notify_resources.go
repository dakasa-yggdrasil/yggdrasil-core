package manifest

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func validateNativeNotifyResourceRoster(b *model.CapacityNativeNotifyWindowBinding) error {
	if len(b.RequiredResources) == 0 {
		return nil
	}
	refuse := func() error { return fmt.Errorf("complete sealed original Notify resource roster required") }
	if len(b.RequiredResources) > 32 {
		return refuse()
	}
	name := regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	sha := regexp.MustCompile(`^[0-9a-f]{64}$`)
	actors, covered := map[string]bool{}, map[string]bool{}
	for _, actor := range b.Participants {
		actors[actor.PodName] = true
	}
	last := ""
	decimal := func(s string, bits int) bool {
		n, err := strconv.ParseUint(s, 10, bits)
		return err == nil && n > 0 && strconv.FormatUint(n, 10) == s
	}
	for _, resource := range b.RequiredResources {
		key := resource.PodName + "/" + resource.Kind + "/" + resource.ResourceName
		if !actors[resource.PodName] || !name.MatchString(resource.ResourceName) || !sha.MatchString(resource.BindingSHA256) || key <= last {
			return refuse()
		}
		last = key
		switch resource.Kind {
		case "postgres_retained_session_v1":
			if !name.MatchString(resource.Database) || !name.MatchString(resource.Role) || !decimal(resource.DatabaseOID, 32) || !decimal(resource.SystemIdentifier, 64) {
				return refuse()
			}
		case "redis_retained_connection_v1", "amqp_retained_channel_v1", "resident_model_v1":
			// These declared dependencies do not have a producer in this seam.
			// Retain them in the full roster; never shrink it to the PG session.
			if resource.Database != "" || resource.DatabaseOID != "" || resource.SystemIdentifier != "" || resource.Role != "" {
				return refuse()
			}
		default:
			return refuse()
		}
		covered[resource.PodName] = true
	}
	if len(covered) != len(actors) {
		return refuse()
	}
	return nil
}
