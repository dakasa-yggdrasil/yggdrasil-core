# Upgrade guide

## General flow

1. Read the [release notes](https://github.com/dakasa-yggdrasil/yggdrasil-core/releases)
   for every intervening version between your current and target.
2. Grep your logs for `deprecated_usage` events since the last
   upgrade. Fix those first.
3. Back up Postgres (`pg_dump` or snapshot).
4. Bump the image tag (see per-deployment instructions below).
5. Restart pods; entrypoint runs `goose up` before starting the
   server.
6. `yggdrasil status` — should return `health: ok`, `ready: ok`.

## Compose

```sh
cd yggdrasil/
docker compose pull
docker compose up -d
docker compose logs yggdrasil-core | grep '\[entrypoint\]\|bootstrap:'
```

Migrations run inside the container via the entrypoint. If migration
fails the pod crashes — inspect logs and restore from backup if the
failure is corrupting state.

## Kubernetes (control_plane manifest)

Bump `spec.image` on the control_plane manifest and re-run the deploy
workflow:

```sh
# edit the image tag in control-plane.yaml
yggdrasil deploy control-plane -f control-plane.yaml
```

The workflow applies the rendered objects with server-side apply, so
the Deployment ends up at the new image; unchanged objects are a
no-op. Migrations run as part of the workflow's `migrate` step
before the new pods come up — a migration failure aborts the run
and leaves the old pods serving.

### Rollback

Edit `spec.image` back to the previous tag and re-run
`yggdrasil deploy control-plane -f control-plane.yaml`. Safe
**within a MINOR line**. Cross-minor rollbacks may fail because
schema migrations are one-way.

## Bare-metal

```sh
systemctl stop yggdrasil-core   # (or your process manager equivalent)
# Replace binary
curl -L -o /usr/local/bin/yggdrasil-core https://...
./goose up
systemctl start yggdrasil-core
```

## Data migrations

`goose up` is additive and idempotent. A bad migration should fail
loud and the pod should not come up — we never silently drop data.

If a release introduces a heavy backfill, the release notes call it
out and the startup time grows. Plan your maintenance window
accordingly.

## When an upgrade breaks

1. Capture logs (`kubectl logs`, `docker compose logs`, or
   journalctl).
2. Roll back: `yggdrasil deploy control-plane` with the previous
   `spec.image`, previous image tag in compose, or restore the
   prior binary.
3. If the DB was touched, restore from the pre-upgrade Postgres
   backup.
4. Open a GitHub issue with the release you upgraded from and to,
   the error, and a description of your deployment topology.

## Integration adapter upgrades

Integration adapters (`integration-*` repos) upgrade independently.
Older adapters stay functional against newer yggdrasil-core as long
as the adapter contract version declared in the corresponding
`integration_family` manifest covers their implementation. Check
`adapter.version` in the family manifest; upgrade adapters when the
family expects a newer minimum.

Run `yggdrasil get integration_family` to see which adapter
contract versions are currently in effect in your environment.
