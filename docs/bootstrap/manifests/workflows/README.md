# Bootstrap Workflows

This directory stores bootstrap `workflow` manifests that the core can import as first-class orchestration definitions.

Current bootstrap workflows:

- `ecosystem-repository-commit.json` (historical, quarantined)
- `github-dispatch.json`

`github-dispatch` is a transitional wrapper around the GitHub integration. It lets edge services call `yggdrasil-core.workflow.run` while the legacy topology model still emits repository/workflow pairs.

`ecosystem-repository-commit` is retained only as a historical bootstrap
template. Its repository, workflow, ref, and environment are caller-selected,
and it has no `spec.authorization`, so hashed machine principals cannot invoke
it. Core ships no automatic emitter for it. Keep it quarantined until it is
replaced by a purpose-bound caller and typed workflow with an exact input
policy.

Real deployment workflows are expected to live in the core as normal `workflow` manifests, typically labeled with:

- `workflow_type=deployment`
- `workflow_build_name=<build-name>`
- `workflow_env_type=<env-type>`
- `workflow_component_id=<component-uuid>`

Those manifests should store stable dispatch values in `spec.defaults` and accept only runtime overrides from callers.
