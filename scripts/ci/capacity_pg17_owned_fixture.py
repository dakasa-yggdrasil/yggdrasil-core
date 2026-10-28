#!/usr/bin/env python3
"""Create and destroy an owned, Unix-socket-only PG17 test cluster.

This prepares and validates schema and server isolation. With --run-grants it
also exercises a synthetic source-only grant fixture; it does not establish
production or native Guest qualification.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tempfile
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
PG = Path(os.environ["CAPACITY_TEST_PG_BIN"]).resolve(strict=True)
GO = Path(os.environ["CAPACITY_TEST_GO"]).resolve(strict=True)
DATABASE = "ci_capacity_original_grant"
ENV_KEYS = ("PATH", "HOME", "TMPDIR", "GOCACHE", "GOMODCACHE", "GOPATH", "GOTOOLCHAIN", "GOPROXY", "GOSUMDB", "CGO_ENABLED", "CC", "CXX", "SDKROOT")
active_child = None
pending_signal = None
cleanup_uncertain = False


def safe_environment():
    """Do not pass caller credentials or PostgreSQL connection overrides."""
    env = {key: os.environ[key] for key in ENV_KEYS if key in os.environ}
    env["LC_ALL"] = "C"
    return env


def interrupted(signum, _frame):
    global pending_signal
    pending_signal = signum
    # Popen's context manager can wait for a slow child before our cleanup.
    # Kill the owned process group first so wait/communicate can finish.
    if active_child is not None:
        try:
            os.killpg(active_child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def check_interrupted():
    if pending_signal is not None:
        raise InterruptedError(f"received signal {pending_signal}")


def run(args, *, env=None, timeout=90, input_text=None):
    global active_child, cleanup_uncertain
    check_interrupted()
    argv = [str(x) for x in args]
    process = subprocess.Popen(argv, cwd=ROOT, env=env if env is not None else safe_environment(), stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    active_child = process
    try:
        # A signal received during Popen is recorded even before the child can
        # be assigned. The exception path below kills and joins that child.
        check_interrupted()
        stdout, stderr = process.communicate(input=input_text, timeout=timeout)
        check_interrupted()
    except BaseException:
        # The leader can already have exited while descendants still own its
        # pipes. The process group remains addressable in that case.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            # A descendant may have escaped the group. Do not wait forever
            # on its inherited pipes, and retain the cluster directory because
            # we cannot establish that the descendant stopped using it.
            cleanup_uncertain = True
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe is not None:
                    pipe.close()
            process.wait(timeout=5)
        raise
    finally:
        active_child = None
    result = subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
    result.check_returncode()
    return result


def remove_owner_if_safe(owner):
    if cleanup_uncertain:
        raise RuntimeError(f"subprocess cleanup uncertain; retain directory {owner}")
    shutil.rmtree(owner)


def owner_parent():
    """Accept only a fresh private direct child of the system temp root."""
    value = os.environ.get("CAPACITY_TEST_PARENT_DIR")
    if not value:
        return Path(os.path.realpath("/tmp")), False
    parent = Path(value)
    st = parent.lstat()
    tmp = Path(os.path.realpath("/tmp"))
    registry_value = os.environ.get("CAPACITY_TEST_OWNER_ROOT")
    if registry_value:
        registry = Path(registry_value)
        registry_stat = registry.lstat()
        if registry.resolve(strict=True) != registry or registry.parent != tmp or not registry.name.startswith("dk-reg-") or not stat.S_ISDIR(registry_stat.st_mode) or stat.S_IMODE(registry_stat.st_mode) != 0o700 or registry_stat.st_uid != os.geteuid():
            raise RuntimeError("private fixture owner registry required")
        expected_parent = registry
    else:
        expected_parent = tmp
    if not parent.is_absolute() or parent.resolve(strict=True) != parent or parent.parent != expected_parent or not parent.name.startswith("dk-own-") or not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700 or st.st_uid != os.geteuid():
        raise RuntimeError("private fixture owner parent required")
    return parent, True


def write_cleanup_receipt(parent):
    path = parent / "cleanup-receipt"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write("owner-cleaned-v1\n")
        out.flush()
        os.fsync(out.fileno())


def write_linux_owner_identity(parent):
    """Record only local process identity; no source or credential values."""
    stat_text = Path("/proc/self/stat").read_text()
    tail = stat_text[stat_text.rfind(")") + 2:].split()
    if len(tail) < 20 or not tail[19].isdigit():
        raise RuntimeError("Linux owner identity unavailable")
    record = {"schema": "capacity_fixture_owner_identity_v1", "pid": os.getpid(), "start_ticks": int(tail[19]), "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}
    fd = os.open(parent / "owner-identity.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(record, out, sort_keys=True)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())


def main():
    global pending_signal, cleanup_uncertain
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--run-grants", action="store_true", help="run synthetic source-only concurrency and HTTP after reviewed clean commit")
    mode.add_argument("--run-repository", action="store_true", help="run source-only repository scenarios with four baseline members")
    args = parser.parse_args()
    if not PG.is_dir() or not GO.is_file():
        raise RuntimeError("PostgreSQL and Go executables required")
    cleanup_uncertain = False
    parent, publish_cleanup = owner_parent()
    owner = Path(tempfile.mkdtemp(prefix="dk-pg-", dir=parent))
    data, sock = owner / "data", owner / "socket"
    sock.mkdir(mode=0o700)
    started = False
    start_attempted = False
    signals = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    previous = {sig: signal.signal(sig, interrupted) for sig in signals}
    try:
        if publish_cleanup and os.environ.get("CAPACITY_TEST_OWNER_ROOT"):
            write_linux_owner_identity(parent)
        run([PG / "initdb", "-D", data, "--username=postgres", "--auth-local=trust", "--auth-host=reject", "--encoding=UTF8", "--no-locale"])
        start_attempted = True
        run([PG / "pg_ctl", "-D", data, "-l", owner / "postgres.log", "-o", f"-k {sock} -h '' -p 54383 -c unix_socket_permissions=0700 -c max_connections=32 -c shared_buffers=32MB", "-w", "-t", "20", "start"])
        started = True
        ctl = run([PG / "pg_controldata", data]).stdout
        ids = re.findall(r"^Database system identifier:\s*(\d+)\s*$", ctl, re.M)
        if len(ids) != 1:
            raise RuntimeError("cannot establish owned system identifier")
        sql = "SELECT current_setting('data_directory'), current_setting('listen_addresses'), inet_server_addr() IS NULL, system_identifier::text FROM pg_control_system()"
        actual = run([PG / "psql", "-h", sock, "-p", "54383", "-U", "postgres", "-d", "postgres", "-At", "-F", "|", "-c", sql]).stdout.strip()
        if actual != f"{data}||t|{ids[0]}":
            raise RuntimeError("owned cluster identity mismatch")
        run([PG / "createdb", "-h", sock, "-p", "54383", "-U", "postgres", DATABASE])
        dsn = f"postgres://postgres@/{DATABASE}?host={quote(str(sock), safe='')}&port=54383&sslmode=disable"
        env = dict(safe_environment(), CAPACITY_TEST_ALLOW="isolated-postgresql-only", CAPACITY_TEST_SOCKET_DIR=str(sock), CAPACITY_TEST_PGDATA=str(data), CAPACITY_TEST_PG_BIN=str(PG), CAPACITY_TEST_PG_SYSTEM_ID=ids[0], CAPACITY_TEST_OWNED_DSN=dsn, DB_URL=dsn, REQUIRE_CAPACITY_OWNED_POSTGRES="true")
        run([GO, "test", "-tags", "capacitytest", "-count=1", "./cmd/capacity-original-grant-fixture", "-run", "TestOwnedPostgres"], env=env, timeout=120)
        # Standalone migrator executes only after the test binary validates PID,
        # socket, data directory, server control identity and no TCP listener.
        migrator = owner / "migrate.go"
        migrator.write_text('''package main
import("context";"database/sql";"os";"time";_ "github.com/lib/pq";"github.com/pressly/goose/v3")
func main(){ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second);defer cancel();db,e:=sql.Open("postgres",os.Getenv("CAPACITY_TEST_OWNED_DSN"));if e!=nil{panic(e)};defer db.Close();var name,dir,id,listen string;var sock bool;var version int;e=db.QueryRowContext(ctx,"SELECT current_database(),current_setting('data_directory'),system_identifier::text,current_setting('listen_addresses'),inet_server_addr() IS NULL,current_setting('server_version_num')::int FROM pg_control_system()").Scan(&name,&dir,&id,&listen,&sock,&version);if e!=nil||name!="ci_capacity_original_grant"||dir!=os.Getenv("CAPACITY_TEST_PGDATA")||id!=os.Getenv("CAPACITY_TEST_PG_SYSTEM_ID")||listen!=""||!sock||version/10000!=17{panic("unowned PostgreSQL refused")};if e=goose.SetDialect("postgres");e!=nil{panic(e)};if e=goose.UpToContext(ctx,db,"db/migrations",82);e!=nil{panic(e)};v,e:=goose.GetDBVersionContext(ctx,db);if e!=nil||v!=82{panic("schema 82 required")}}
''')
        run([GO, "run", "-mod=readonly", migrator], env=env, timeout=120)
        if args.run_grants or args.run_repository:
            binary = owner / "grant-fixture"
            run([GO, "build", "-race", "-tags", "capacitytest nativequalification", "-o", binary, "./cmd/capacity-original-grant-fixture"], env=env, timeout=120)
            try:
                fixture_mode = "--synthetic-repository-run" if args.run_repository else "--synthetic-seed-run"
                process = run([binary, fixture_mode], env=env, input_text=json.dumps({"source_root": str(ROOT)}), timeout=120)
            except subprocess.CalledProcessError as exc:
                raise RuntimeError("synthetic grant runner failed: " + exc.stderr.strip()[:1000]) from exc
            result = json.loads(process.stdout)
            if result.get("provider") != "native-qemu" or result.get("native_or_production_qualified") is not False or result.get("provider_send_attempted") is not False:
                raise RuntimeError("unexpected synthetic result scope")
            print(json.dumps(result, sort_keys=True))
        else:
            print(json.dumps({"schema": "owned_pg17_fixture_preflight_v1", "schema_version": 82, "unix_socket_only": True, "owned_identity_verified": True, "grant_test_run": False, "production_used": False}))
    finally:
        # Finish bounded shutdown even if another ordinary termination signal
        # arrives. Never remove the cluster on uncertain shutdown.
        for sig in signals:
            signal.signal(sig, signal.SIG_IGN)
        pending_signal = None
        try:
            if start_attempted and not started:
                if (data / "postmaster.pid").exists():
                    run([PG / "pg_ctl", "-D", data, "-m", "fast", "-w", "-t", "20", "stop"], timeout=30)
                raise RuntimeError(f"PostgreSQL startup outcome uncertain; retain directory {owner}")
            if started or (data / "postmaster.pid").exists():
                run([PG / "pg_ctl", "-D", data, "-m", "fast", "-w", "-t", "20", "stop"], timeout=30)
            if (data / "postmaster.pid").exists():
                raise RuntimeError("owned PostgreSQL still running; retain directory")
            remove_owner_if_safe(owner)
            if publish_cleanup:
                write_cleanup_receipt(parent)
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)


if __name__ == "__main__":
    main()
