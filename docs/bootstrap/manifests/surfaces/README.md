# Bootstrap surface manifests

These manifests register the reference Yggdrasil surfaces in the core.

They are intentionally catalog entries for replaceable edge runtimes, not
heart-of-product services. The design rule is:

- `yggdrasil-core` is required
- surfaces are optional and replaceable
- integrations stay associated to the core, never to one surface directly

The reference surfaces included in the official runtime today are:

- `yggdrasil-auth-surface`
- `yggdrasil-console`

Organizations can keep, replace, split, or remove those surfaces as long as
their custom runtimes keep talking to the core through supported contracts.

`yggdrasil-auth-surface` is intentionally narrow: it fronts the core auth
endpoints for login/session/logout, while password credentials and sessions are
persisted by `yggdrasil-core`.
