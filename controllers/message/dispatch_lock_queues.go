package message

var dispatchLockPausedQueues = []string{
	queueWorkflowDispatch,
	queueWorkflowRun,
	queueIntegrationExecute,
	queueCatalogDiscover,
	queueManifestCreate,
	queueProductMaterialize,
	queueProductInstallationReconcile,
	queueProductInstallationApply,
	queueProductInstallationObserve,
	queueProductInstallationUninstall,
}

// DispatchLockPausedQueues returns the Core ingress queues that must have no
// consumer while the emergency workflow policy is enforced or invalid.
func DispatchLockPausedQueues() []string {
	return append([]string(nil), dispatchLockPausedQueues...)
}
