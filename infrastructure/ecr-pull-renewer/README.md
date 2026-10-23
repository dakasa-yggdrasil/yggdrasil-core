# ECR pull credential renewal

This component refreshes the existing `dakasa/ecr-pull-fresh` Secret every thirty minutes. It updates only the `153828470928.dkr.ecr.us-east-1.amazonaws.com` registry entry and preserves the Secret UID, other registry entries and other data keys.

Build the supplied Dockerfile with `PYTHON_BASE_IMAGE` set to an official public Python 3.12 image by digest. Dependencies are locked by version and wheel hash. The final image must also be public and referenced by digest so the renewer can start when the credential it renews has expired. No packages are installed during a Job.

The runtime obtains temporary credentials directly through IMDSv2 on the existing Brain host. That instance role has permissions for several services; this program uses its credentials only for ECR and exports only the ECR registry token. It does not reduce the role's IAM permissions. The dedicated ServiceAccount can get and patch only the named Secret. Each Kubernetes operation rereads its projected token.

Each Job reads current state, validates identity and token expiry, and sends at most one JSON Patch with UID and resource-version tests. A transport failure retains an uncertain result. A later Job constructs a fresh rotation from new reads. Identical valid authentication returns a successful no-op. The Job never creates or deletes a Secret.

`render_manifest.py` requires a reviewed admission file and a public image digest, and always renders a suspended CronJob. Its templates contain incomplete admission fields and cannot be applied unchanged. See [ADR 0073](../../docs/adr/0073-renew-ecr-pull-credentials-with-the-existing-host-identity.md) for the operational contract.

Offline checks:

```sh
python3 -m pip install --require-hashes --only-binary=:all: -r requirements.lock
python3 -m unittest discover -s . -p 'test_*.py'
```

The tests use synthetic credentials, fake transports and SDK stubs. They do not renew a production token or establish a successful live Job.

Disable Kubernetes service links so Service environment variables cannot become ambient AWS configuration. The runtime accepts writable permission bits only on the two fixed read-only projected volume roots. Outside ancestors and all internal components retain strict ownership, type and permission checks. The deployment template contains no nested mounts; host and kubelet remain trusted. Projection rotation races fail the Job without retry.
