# Using yggdrasil-core as a Go dependency

`yggdrasil-core` is a **private Go module** hosted at `github.com/dakasa-yggdrasil/yggdrasil-core`. Consumers with read access can import it in their own Go projects.

## Prerequisites

Before you can `go get` this module, you need three things configured on your machine:

1. **Git authentication** to GitHub for the `dakasa-yggdrasil` organization
2. **`GOPRIVATE`** environment variable set, so the Go tool bypasses the public module proxy
3. **(Optional) `GONOSUMDB`** / `GONOSUMCHECK` for private modules

### 1. Configure git authentication

Pick one of the two authentication methods:

**Option A: SSH key (recommended for developers)**

Add your SSH public key to GitHub (Settings → SSH and GPG keys), then tell git to use SSH for GitHub:

```bash
git config --global url."git@github.com:".insteadOf "https://github.com/"
```

Verify:

```bash
ssh -T git@github.com
# Expected: "Hi <username>! You've successfully authenticated..."
```

**Option B: Personal Access Token via netrc (recommended for CI)**

Create a GitHub PAT with `repo` scope (Settings → Developer settings → Personal access tokens).

Add it to `~/.netrc`:

```
machine github.com
  login your-username
  password ghp_YOUR_TOKEN_HERE
```

Ensure `.netrc` permissions are restrictive:

```bash
chmod 600 ~/.netrc
```

### 2. Set `GOPRIVATE`

Add to your shell profile (`.bashrc`, `.zshrc`, or `.envrc`):

```bash
export GOPRIVATE=github.com/dakasa-yggdrasil/*
```

This tells the Go tool: "don't use the public module proxy for modules under `github.com/dakasa-yggdrasil/`; fetch them directly from git."

Verify:

```bash
go env GOPRIVATE
# Expected: github.com/dakasa-yggdrasil/*
```

### 3. (Optional) Disable sumdb check for private modules

If you see errors like `module lookup disabled by GOFLAGS` or `verifying module: invalid GOSUMDB: …`, disable sumdb for private modules:

```bash
export GONOSUMDB=github.com/dakasa-yggdrasil/*
```

Or (simpler) disable sumdb globally:

```bash
export GOSUMDB=off
```

Note: `GOSUMDB=off` disables checksum verification for **all** modules, not just private ones. Prefer `GONOSUMDB` for a scoped approach.

## Installing as a dependency

In your Go project:

```bash
go get github.com/dakasa-yggdrasil/yggdrasil-core@latest
```

Or pin a specific version:

```bash
go get github.com/dakasa-yggdrasil/yggdrasil-core@v0.1.0-alpha.1
```

Or pin a specific commit:

```bash
go get github.com/dakasa-yggdrasil/yggdrasil-core@abc123def
```

## Importing in code

```go
import (
    "github.com/dakasa-yggdrasil/yggdrasil-core/model"
    "github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)
```

## Current stable surface

While `yggdrasil-core` is under active development, the following packages are considered stable enough for external consumers:

- `model/` — All public types (manifest kinds, events, topology, identity, etc.). Contract-first; changes follow semver.
- `repository/` — Data access functions (mutations + reads). Requires `*sql.DB` or `*sql.Tx`.
- `manifest/` — Manifest parsing and validation. Accepts `ManifestDocument`, returns typed specs.
- `docs/contracts/` — JSON Schema contracts for integration adapters, events, and RPC requests. Language-agnostic.

Less stable (may have breaking changes):
- `controllers/` — RPC and HTTP handlers. Usually consumed via the running service, not imported.
- `addons/` — Service runtime wiring. Usually consumed via the running service.
- `internal/` — Internal helpers. **Never import.**

## Troubleshooting

### `go get` hangs or times out

Likely missing git auth. Test with:

```bash
git ls-remote https://github.com/dakasa-yggdrasil/yggdrasil-core.git
```

If that fails, your git credentials aren't set up correctly.

### `410 Gone` or `404 Not Found`

Your account doesn't have read access to the repo. Ask your Yggdrasil admin to add you.

### `verifying module: checksum database disabled`

Set `GOSUMDB=off` (globally) or `GONOSUMDB=github.com/dakasa-yggdrasil/*` (scoped).

### `proxy.golang.org returned 410`

The public proxy doesn't have your private module (correctly). This means `GOPRIVATE` is not set. See step 2 above.

## For the Yggdrasil team

If you're a maintainer, see `CONTRIBUTING.md` (TBD) for the development workflow. Branch protection rules on `main` require PR reviews before merging.
