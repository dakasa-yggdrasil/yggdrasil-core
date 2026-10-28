//go:build linux && nativequalification

package capacitynativeqemu

// OriginalWorkflowIdentitySQL joins the immutable public-run UUID to the
// manifest selected by namespace/name and to the full terminal result's
// resolved workflow reference. The real public POST writer omits workflow_id
// and can omit a selector version; non-null values must still match exactly.
const OriginalWorkflowIdentitySQL = `SELECT w.status FROM public.workflow_runs w JOIN public.manifests m ON m.id=$2 AND m.kind='workflow' WHERE w.id=$1 AND w.workflow_namespace=m.namespace AND w.workflow_name=m.name AND (w.workflow_version IS NULL OR w.workflow_version=m.version) AND (w.workflow_id IS NULL OR w.workflow_id=m.id) AND w.result #>> '{workflow,id}'=m.id::text AND w.result #>> '{workflow,kind}'='workflow' AND w.result #>> '{workflow,namespace}'=m.namespace AND w.result #>> '{workflow,name}'=m.name AND w.result #>> '{workflow,version}'=m.version::text`
