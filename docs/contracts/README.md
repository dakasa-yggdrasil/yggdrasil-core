# Public Contracts

`yggdrasil-core` is the source of truth for the public wire contracts used by
plugins and edge services.

These contracts are versioned as documentation and JSON Schema, not as a
mandatory shared Go package. Plugin repositories should implement local types
that match these contracts instead of importing `yggdrasil-core/model`.

Current contract families:

- `integration-adapter/v1`: generic `describe` and `execute` adapter protocol
- `product-installation-adapter/v1`: installation-oriented adapter protocol

This keeps integrations independent as repositories while still giving the
ecosystem one canonical protocol surface.

`yggdrasil-core` validates adapter request and response payloads against these
schemas at runtime.

For `describe`, the core also compares the live adapter contract with the
persisted `integration_type` manifest before executing integration-backed
operations.
