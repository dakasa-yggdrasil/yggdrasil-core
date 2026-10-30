# CodeQL configuration

The Go password-hashing query classifies fields named `PasswordRef` as passwords.
The Postgres control-plane renderer extracts the public Kubernetes Secret object
name from this reference; it does not read the secret value. The local query
models only the return from that specific extraction call in the password-hash
flow. It does not sanitize raw references, other callers of the extractor, or
passwords from other sources. An object name is public metadata and must never
be used as a store for a password.

The configuration retains the default query suite and replaces only
`go/weak-sensitive-data-hashing` with `dakasa/go-secret-reference-hashing`.
The new rule ID has distinct alert history. Preserve a baseline for the default
branch when configuring this query so pull-request comparisons remain meaningful.

The query derives from GitHub CodeQL `WeakSensitiveDataHashing.ql` at
`codeql-cli/v2.27.3`; the accompanying MIT license applies. The only semantic
change is the narrowly scoped barrier described above. When upgrading CodeQL,
compare the upstream query and its library dependency with this copy, update
them together as needed, and verify direct-password, raw-reference,
other-caller and shared-sink positive controls before adoption.

If this repository-specific configuration fails to load, unset the
`github-codeql-config-file` property for this repository to restore the default
suite; do not disable default setup. Verify a new managed main-branch scan and
its open alerts before relying on pull-request comparisons. Keep the organization
property's default unset so other repositories retain their own configuration.
