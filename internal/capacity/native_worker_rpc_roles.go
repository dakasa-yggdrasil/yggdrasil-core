package capacity

// These are separate Source-owned principals. A list may narrow a provider
// mutation principal, but cannot combine it with any reader or Kubernetes role.
func nativeWorkerRPCRole(capabilities []string) (map[string]bool, bool) {
	if len(capabilities) < 1 || len(capabilities) > 2 {
		return nil, false
	}
	allowed := make(map[string]bool, len(capabilities))
	role := ""
	for _, capability := range capabilities {
		group := ""
		switch capability {
		case "ensure_native_worker", "destroy_native_worker":
			group = "provider_mutation"
		case "observe_native_worker", "observe_native_worker_cleanup":
			group = "provider_read"
		case "ensure_native_worker_pool":
			group = "kube_writer"
		case "observe_native_worker_pool":
			group = "kube_pool_read"
		case "observe_native_worker_phase":
			group = "kube_phase_read"
		case "observe_native_worker_abort_inventory":
			group = "kube_abort_read"
		case "ensure_native_worker_probe_resource", "destroy_native_worker_probe_resource":
			group = "kube_probe_writer"
		case "observe_native_worker_probe_resource":
			group = "kube_probe_reader"
		default:
			return nil, false
		}
		if allowed[capability] || role != "" && role != group {
			return nil, false
		}
		role = group
		allowed[capability] = true
	}
	return allowed, true
}
