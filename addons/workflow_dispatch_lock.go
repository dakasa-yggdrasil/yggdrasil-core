package addons

import "github.com/dakasa-yggdrasil/yggdrasil-core/internal/workflowdispatchlock"

// workflowDispatchLockPaused keeps startup workers fail-closed when the
// emergency policy is either enforced or invalid.
func workflowDispatchLockPaused() bool {
	policy, err := workflowdispatchlock.LoadFromEnvironment()
	return err != nil || policy.Enforced()
}
