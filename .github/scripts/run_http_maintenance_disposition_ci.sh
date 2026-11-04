#!/usr/bin/env bash
# CI only: a disposable, Unix-only PostgreSQL owner. No production authority.
set -Eeuo pipefail
umask 077
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
[[ "$EXPECTED_POSTGRES_MAJOR" == 16 || "$EXPECTED_POSTGRES_MAJOR" == 17 ]]
[[ "$(git rev-parse HEAD)" == "$SOURCE_COMMIT" ]]
[[ -z "$(git status --porcelain --untracked-files=all)" ]]
[[ "$HTTP_MAINTENANCE_LOGS" == "$RUNNER_TEMP/http-maintenance-pg$EXPECTED_POSTGRES_MAJOR" ]]
mkdir -m 0700 "$HTTP_MAINTENANCE_LOGS"
export LOGS="$HTTP_MAINTENANCE_LOGS"
printf '%s\n' "$SOURCE_COMMIT" > "$LOGS/source-head.txt"
pg_root="$(mktemp -d "$RUNNER_TEMP/hm91-pg$EXPECTED_POSTGRES_MAJOR-XXXXXX")"
chmod 0700 "$pg_root"
export PGDATA="$pg_root/data" PGHOST="$pg_root/socket" PGUSER=postgres
export PGDATABASE="original_disposition_test_${GITHUB_RUN_ID}_${GITHUB_RUN_ATTEMPT}_pg${EXPECTED_POSTGRES_MAJOR}"
mkdir -m 0700 "$PGDATA" "$PGHOST"
export ORIGINAL_CREATE_DISPOSITION_PG_DSN="host=$PGHOST dbname=$PGDATABASE user=$PGUSER sslmode=disable"
export REQUIRE_ORIGINAL_CREATE_DISPOSITION_PG=true
export DB_HOST="$PGHOST" DB_PORT=5432 DB_NAME="$PGDATABASE" DB_USER="$PGUSER"
export DB_PASSWORD=disposable-ci-only DB_SSLMODE=disable
cid=''
record() {
  local name="$1" rc; shift
  if "$@" > "$LOGS/$name.stdout" 2> "$LOGS/$name.stderr"; then rc=0; else rc=$?; fi
  printf '%s\n' "$rc" > "$LOGS/$name.exit"
  return "$rc"
}
cleanup() {
  local original=$? shutdown=0
  trap - EXIT INT TERM
  if [[ -n "$cid" ]]; then
    record pg-stop timeout 45s docker stop --time 30 "$cid" || shutdown=1
    record pg-wait timeout 10s docker wait "$cid" || shutdown=1
    record pg-state docker inspect --format '{{json .State}}' "$cid" || shutdown=1
    record pg-log docker logs "$cid" || shutdown=1
    record pg-remove docker rm --volumes "$cid" || shutdown=1
  fi
  if record shutdown-check python3 -I -B .github/scripts/verify_http_maintenance_disposition_ci.py shutdown "$original" "$shutdown"; then :; else shutdown=1; fi
  if (( original != 0 || shutdown != 0 )); then exit 1; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
record go-version go version
record pg-pull docker pull "postgres:$EXPECTED_POSTGRES_MAJOR"
# Only this job's private directory is mounted. The official entrypoint's
# arbitrary-UID support is the same Unix-socket pattern used by the old gates.
record pg-create docker create --network none --user "$(id -u):$(id -g)" \
  --cap-drop ALL --security-opt no-new-privileges --memory 512m --cpus 2 \
  --pids-limit 128 --mount "type=bind,src=$pg_root,dst=$pg_root" \
  --mount "type=bind,src=$PGHOST,dst=/var/run/postgresql" \
  -e PGDATA -e PGHOST -e PGUSER -e PGDATABASE \
  -e POSTGRES_USER=postgres -e "POSTGRES_DB=$PGDATABASE" -e POSTGRES_HOST_AUTH_METHOD=trust \
  "postgres:$EXPECTED_POSTGRES_MAJOR" postgres -k "$PGHOST" -c listen_addresses= \
  -c unix_socket_permissions=0700 -c max_connections=30 -c shared_buffers=32MB \
  -c max_worker_processes=0 -c max_parallel_workers=0
cid="$(cat "$LOGS/pg-create.stdout")"
[[ "$cid" =~ ^[0-9a-f]{64}$ ]]
record pg-start docker start "$cid"
ready=0
for n in $(seq 1 60); do
  if record "pg-ready-$n" docker exec "$cid" /bin/sh -ec 'test "$(cat /proc/1/comm)" = postgres; exec pg_isready -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE"'; then ready=1; break; fi
  sleep 1
done
[[ "$ready" == 1 ]]
# Initialization chmods its default socket alias; restore before any test.
record pg-socket-mode chmod 00700 "$PGHOST"
record pg-directory-modes stat -c '%u %a' "$PGDATA" "$PGHOST"
record pg-image docker inspect --format '{{json .Image}}' "$cid"
record pg-identity docker exec "$cid" psql -XAt -v ON_ERROR_STOP=1 -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" \
  -c "SELECT json_build_object('database',current_database(),'unix_socket',inet_server_addr() IS NULL,'major',current_setting('server_version_num')::int/10000,'listen_addresses',current_setting('listen_addresses'));"
record identity-check python3 -I -B .github/scripts/verify_http_maintenance_disposition_ci.py identity
record derived-sql python3 -I -B .github/scripts/render_http_maintenance_pre91.py --check
record migrations go run ./scripts/goose up
record database-before docker exec "$cid" psql -XAt -v ON_ERROR_STOP=1 -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" \
  -c "SELECT json_build_object('schema_version',(SELECT max(version_id) FROM public.goose_db_version WHERE is_applied),'history',(SELECT array_to_json(array_agg(row_to_json(v) ORDER BY v.id)) FROM public.goose_db_version v));"
record source-before python3 -I -B .github/scripts/verify_http_maintenance_disposition_ci.py prepare
run_go() {
  local name="$1" package="$2" pattern="$3" duration="$4"
  set +e
  go test -buildvcs=true -p=1 -race -count=1 -timeout="$duration" -json "$package" -run "$pattern" \
    2> "$LOGS/$name.stderr" | tee "$LOGS/$name.stdout" 2> "$LOGS/$name.tee.stderr"
  local returns=("${PIPESTATUS[@]}")
  set -e
  printf '%s\n' "${returns[0]}" > "$LOGS/$name.exit"
  printf '%s\n' "${returns[1]}" > "$LOGS/$name.tee.exit"
  [[ "${returns[0]}" == 0 && "${returns[1]}" == 0 ]]
}
failed=0
run_go repository ./repository '^TestHTTPMaintenance(Disposition|Dispatch)' 8m || failed=1
run_go http ./controllers/httpapi '^TestHTTPMaintenanceDispatchDisposition' 3m || failed=1
# Keep the original Go and tee exits even if either package failed. The
# verifier still writes a refusal census from the complete original streams.
record database-after docker exec "$cid" psql -XAt -v ON_ERROR_STOP=1 -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" \
  -c "SELECT json_build_object('schema_version',(SELECT max(version_id) FROM public.goose_db_version WHERE is_applied),'history',(SELECT array_to_json(array_agg(row_to_json(v) ORDER BY v.id)) FROM public.goose_db_version v));"
record census python3 -I -B .github/scripts/verify_http_maintenance_disposition_ci.py census || failed=1
[[ "$failed" == 0 ]]
