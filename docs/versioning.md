# Versioning and compatibility policy

Yggdrasil follows [SemVer](https://semver.org/) with concrete
additions tailored to a manifest-driven, long-lived control plane.

## Version numbers

`vMAJOR.MINOR.PATCH` applies to two artifacts in lockstep:

- `yggdrasil-core` container image (`ghcr.io/dakasa-yggdrasil/yggdrasil-core`)
- `yggdrasil` CLI binary

Adapter images (`integration-kubernetes`, `integration-schema-migrations`,
etc.) version independently — each declares its `adapter.version` in
the `integration_type` manifest so the core verifies the contract at
describe-handshake time. The SDK (`yggdrasil-sdk-go`) versions
independently as well, with a compatibility matrix in its release
notes.

Running a CLI one minor ahead or behind the server is supported.
Running two minor versions apart is not. The CLI refuses to talk to
a server whose `api_version` mismatches beyond that window.

## Manifest API version

The `apiVersion` field on every manifest identifies the **schema
contract**, not the server release:

- `yggdrasil.io/v1alpha1` — current. Subject to additive changes at
  any patch release; backward-incompatible changes require a bumped
  apiVersion and a deprecation window.
- `yggdrasil.io/v1beta1` — planned once the shape stabilizes across
  all kinds.
- `yggdrasil.io/v1` — stable. No breaking changes without a new
  apiVersion.

The server accepts multiple apiVersions during a deprecation window.
Old manifests never "rot" silently: you either keep the old
apiVersion (supported for N releases) or migrate when you edit.

## What counts as a breaking change

Breaking in a `MAJOR` bump:

- Removing a manifest kind.
- Removing or renaming a required spec field.
- Changing semantics of an existing field (e.g. truthiness flips).
- Removing an HTTP endpoint.
- Removing a step `kind` or `operation`.

Non-breaking (ok in `MINOR`):

- Adding a new kind, field, endpoint, step kind, or operation.
- Adding optional behavior under a new flag.
- Relaxing a validation rule.

Bug fixes (`PATCH`) preserve all observable behavior.

## Deprecation policy

When a field or endpoint is marked deprecated:

1. The server logs a `deprecated_usage` warning event whenever the
   deprecated path is hit. Consumers get time to notice.
2. Release notes document the replacement and the removal target.
3. Removal lands in the MAJOR bump AFTER at least one MINOR of
   warnings. In practice, ~3 months minimum.

## Upgrading

The [upgrade guide](./upgrade.md) walks through each release. The
short version:

- **PATCH**: pull new image, restart pods. No schema changes.
- **MINOR**: pull new image, run `goose up` as part of the container
  entrypoint (already automatic in Helm + Compose), restart pods.
  Read the release notes for new features.
- **MAJOR**: plan a maintenance window. Schema changes may run for
  minutes on a large `event_log`. Check deprecation warnings in the
  previous MINOR's logs; migrate those before upgrading.

Upgrades NEVER require data loss unless the release notes say so
explicitly (and they won't for `v1+`).

## Downgrades

Downgrades are supported within the same MINOR line. Cross-MINOR
downgrades are NOT supported — a migration may have renamed a column
that the older binary expects. Restore from backup if you must
downgrade across a minor.

## Integration adapters

Each `integration-<type>` repo has its own SemVer, independent of
yggdrasil-core. The server exposes the required **adapter contract
version** via the `integration_family` manifest (`adapter.version`
field). An adapter running a version older than the family demands
is rejected at RPC handshake. This is how we keep the core's
contract stable while adapters iterate freely.

## Release cadence

- MAJOR: annually at most, with at least a full MINOR of deprecation
  notice.
- MINOR: every 4-6 weeks.
- PATCH: as needed; typically weekly during active development.

Release notes live at
[github.com/dakasa-yggdrasil/yggdrasil-core/releases](https://github.com/dakasa-yggdrasil/yggdrasil-core/releases).
