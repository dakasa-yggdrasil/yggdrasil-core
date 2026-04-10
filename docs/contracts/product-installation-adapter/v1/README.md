# Product Installation Adapter v1

This contract extends the generic adapter protocol for installation-oriented
plugins that generate, reconcile, or observe product-backed resources.

It also covers target-side execution payloads used by substrate executors:

- `declarative_apply`
- `observe_objects`

This is the contract used by installation-style plugins such as substrate-aware
platform integrations.

Important:

- This remains a wire contract.
- Plugins should keep their own local types.
- `yggdrasil-core/model` is not the public SDK.

Primary schema: [schema.json](/Users/dakasa/projects/yggdrasil-core/docs/contracts/product-installation-adapter/v1/schema.json)
