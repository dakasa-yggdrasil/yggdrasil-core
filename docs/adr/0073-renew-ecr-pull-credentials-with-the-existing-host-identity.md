# 0073 — Renew ECR pull credentials with the existing host identity

## Status

Proposed

## Context

An ECR pull token expires while the cluster and its workloads can remain healthy. A replacement Pod then cannot pull an image. The process that renews this token must start independently of the same private registry credential.

## Decision

Run a small CronJob on the Brain node every thirty minutes, using an immutable public image. Its dedicated ServiceAccount may only get and patch the existing pull Secret. Project the ServiceAccount token and cluster CA; reread the token for every Kubernetes operation.

Use IMDSv2 with the existing instance profile and explicit temporary credentials held in memory. The existing role has permissions for multiple services. The renewer calls only ECR, and only the ECR registry token is written into the Secret. This does not downscope the role. Host networking permits the existing metadata hop limit to remain unchanged. Do not mount an administrative kubeconfig, copy static IAM credentials, use host paths or restart the cluster.

Preserve the Secret UID, unrelated registries and other data keys. Each Job reads fresh state and sends at most one JSON Patch with UID and resource-version tests. Require a valid token with at least two hours remaining immediately before the Patch. Preserve an uncertain original transport result and do not resend that Patch. A later scheduled Job creates a new rotation from fresh reads. If the newly validated authentication already matches, return a successful no-op.

Use `Forbid`, `Never`, zero Job retries and a 120-second Job deadline. Render deployment manifests suspended until the image, admission, Secret identity and effective ServiceAccount permissions have been verified.

## Consequences

Registry credentials renew without a Mac scheduler or dependency on the expired credential. The process uses the existing host's temporary role, so host networking and the role's broader permissions are explicit operational tradeoffs. IAM identity permissions remain separate from the narrow Kubernetes permissions. A live Job and anonymous image pull must be verified before activation; offline tests establish only code behavior.
