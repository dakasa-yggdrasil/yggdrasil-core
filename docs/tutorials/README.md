# Tutorials

End-to-end stories that take you from a working Yggdrasil installation to a real adoption outcome. Each tutorial assumes you completed the [quickstart](../quickstart.md) — your control plane is running and the integration-kubernetes adapter is healthy.

| # | Tutorial | What you accomplish | Time |
|---|---|---|---|
| 1 | [Wire your first service to Yggdrasil CD](./01-webhook-cd.md) | A real service repository deploys on every push to `main` via webhook | ~45 min |
| 2 | [Build a custom integration adapter](./02-custom-adapter.md) | Yggdrasil talks to a system it did not previously know about | ~60 min |
| 3 | [Use Yggdrasil as your secret store](./03-secret-store.md) | No more cleartext secrets in your manifests; rotation is one POST | ~30 min |
| 4 | [Spin up ephemeral environments per pull request](./04-ephemeral-envs.md) | One PR → one namespace + TTL + cost projection (v2.2+) | ~30 min |
| 5 | [Multi-tenancy](./05-multi-tenancy.md) | Organise manifests by tenant; opt-in enforcement (v2.3+) | ~30 min |

## Conventions

- Every tutorial starts with the assumed state and ends with the verifiable outcome.
- Commands assume `YGG_URL=http://localhost:9080` from the quickstart port-forward.
- When a step fails, the tutorial includes the error message and the recovery path; troubleshooting lives inline rather than in a separate appendix.
- Tutorials are runnable end-to-end without internet access (other than to the GitHub webhook simulation).
