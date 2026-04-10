# Bootstrap Workflows

This directory stores bootstrap `workflow` manifests that the core can import as first-class orchestration definitions.

Current bootstrap workflows:

- `ecosystem-repository-commit.json`
- `github-dispatch.json`

`github-dispatch` is a transitional wrapper around the GitHub integration. It lets edge services call `yggdrasil-core.workflow.run` while the legacy topology model still emits repository/workflow pairs.

`ecosystem-repository-commit` is the first dog-food deployment template. GitHub
Actions in product, surface, or integration repositories can emit one commit
event into `yggdrasil-core`, and the workflow will dispatch the target
repository `deploy.yml` through the global GitHub integration.

Real deployment workflows are expected to live in the core as normal `workflow` manifests, typically labeled with:

- `workflow_type=deployment`
- `workflow_build_name=<build-name>`
- `workflow_env_type=<env-type>`
- `workflow_component_id=<component-uuid>`

Those manifests should store stable dispatch values in `spec.defaults` and accept only runtime overrides from callers.
