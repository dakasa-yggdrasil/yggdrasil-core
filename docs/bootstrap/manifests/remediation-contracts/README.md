These manifests declare bounded remediation entrypoints for components that
allow Heimdall to do more than generic redeploy recommendations.

Current supported modes:

- `workflow_dispatch`
- `integration_execute`

That means the core does not improvise mutations on its own. It dispatches a
repository workflow that the owning component has explicitly declared as its
remediation contract.

Current production guidance:

- use `repository_binding` to associate the component with its repo
- use `guardian_policy` to decide whether Heimdall may auto-execute the action
- use `remediation_contract` to declare how `rightsize_component` or other
  bounded remediations should be dispatched

The reference contracts here currently cover two patterns:

- official components opting into `rightsize_component` through their existing
  `deploy.yml` entrypoint
- infrastructure-backed hotfixes, like
  `capacity_scheduling_hotfix`, executed through another authorized integration

For `integration_execute` contracts, the input object may be templated from the
Heimdall action payload. That is how bounded hotfixes can target the affected
workload name, namespace, container, and CPU envelope without hardcoding a
single bootstrap patch.
