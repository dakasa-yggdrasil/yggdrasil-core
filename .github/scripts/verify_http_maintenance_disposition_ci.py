#!/usr/bin/env python3
"""Verify retained CI originals only; never grants native or production authority."""
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
ROSTER = ROOT / ".github/scripts/http_maintenance_disposition_expected.json"


def need(condition, message):
    if not condition:
        raise ValueError(message)


def closed_object(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def loads(raw):
    def nonfinite(_):
        raise ValueError("nonfinite JSON")
    return json.loads(raw, object_pairs_hook=closed_object, parse_constant=nonfinite)


def read_json(path):
    return loads(path.read_text())


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def current_head():
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    need(re.fullmatch("[0-9a-f]{40}", head) and head == os.environ["SOURCE_COMMIT"], "exact Source head differs")
    need(not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT), "Source checkout is dirty")
    return head


def identity(logs):
    value = read_json(logs / "pg-identity.stdout")
    expected = {"database": os.environ["PGDATABASE"], "unix_socket": True,
                "major": int(os.environ["EXPECTED_POSTGRES_MAJOR"]), "listen_addresses": ""}
    need(value == expected and expected["major"] in (16, 17), "actual isolated PostgreSQL identity differs")
    for name in ("PGDATA", "PGHOST"):
        st = Path(os.environ[name]).stat()
        need(st.st_uid == os.getuid() and st.st_mode & 0o7777 == 0o700, "PostgreSQL directory mode/owner differs")
    need(loads((logs / "pg-image.stdout").read_text()).startswith("sha256:"), "actual Docker image identity missing")
    return value


def database(logs, phase):
    value = read_json(logs / ("database-" + phase + ".stdout"))
    versions = [int(path.name.split("_", 1)[0]) for path in (ROOT / "db/migrations").glob("*.sql")]
    need(sorted(versions) == list(range(1, 40)) + list(range(41, 93)), "Source migration roster differs")
    history = value["history"]
    need(value["schema_version"] == 92 and isinstance(history, list), "actual schema92 absent")
    need([row["version_id"] for row in history] == [0] + sorted(versions), "actual complete Goose history differs")
    need(all(row["is_applied"] is True for row in history), "unapplied Goose row retained")
    return value


def prepare(logs):
    current_head()
    identity(logs)
    database(logs, "before")
    paths = [
        ".github/workflows/http-maintenance-disposition.yml",
        ".github/scripts/run_http_maintenance_disposition_ci.sh",
        ".github/scripts/verify_http_maintenance_disposition_ci.py",
        ".github/scripts/http_maintenance_disposition_expected.json",
        ".github/scripts/render_http_maintenance_pre91.py",
        "repository/capacity_dispatch_http_maintenance_disposition.go",
        "repository/capacity_dispatch_http_maintenance_disposition_test.go",
        "repository/capacity_dispatch_http_maintenance_disposition_postgres_test.go",
        "controllers/httpapi/ops_http_maintenance_dispatch_disposition.go",
        "controllers/httpapi/ops_http_maintenance_dispatch_disposition_test.go",
        "controllers/httpapi/server.go",
        "repository/capacity_dispatch_unknown_maintenance_disposition.go",
        "controllers/httpapi/ops_unknown_maintenance_dispatch_disposition.go",
        "ops/http-maintenance/http_maintenance_pre91.sql",
    ] + sorted(str(path.relative_to(ROOT)) for path in (ROOT / "db/migrations").glob("*.sql"))
    pins = {}
    for name in paths:
        raw = (ROOT / name).read_bytes()
        pins[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    write_json(logs / "SOURCE-PINS.PUBLIC.json", {"source_commit": current_head(), "files": pins})


def census(logs):
    result = {"schema": "http_maintenance_dispatch_exact_Source_CI_v1",
              "source_commit": os.environ["SOURCE_COMMIT"], "run_id": os.environ["GITHUB_RUN_ID"],
              "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
              "postgres_major": int(os.environ["EXPECTED_POSTGRES_MAJOR"]), "schema_version": 92,
              "race": True, "count": 1, "summary": {}, "passed": False,
              "declared_storage_and_transport_fixtures_only": True,
              "native_provider_or_Guest_qualification": False, "production_authority": False}
    failure = None
    try:
        expected = read_json(ROSTER)
        need(expected["schema"] == "http_maintenance_dispatch_expected_Source_tests_v1", "roster schema differs")
        for name, spec in expected["packages"].items():
            package = "github.com/dakasa-yggdrasil/yggdrasil-core/" + spec["package"]
            want = [parent for parent in spec["cases"]]
            want += [parent + "/" + child for parent, children in spec["cases"].items() for child in children]
            need(len(set(want)) == len(want), "duplicate expected test node")
            raw = (logs / (name + ".stdout")).read_bytes()
            need(0 < len(raw) <= 32 * 1024 * 1024, "Go JSON stream absent or oversized")
            events = [loads(line) for line in raw.decode("utf-8").splitlines()]
            need(events and all(event.get("Package") == package for event in events), "foreign or absent owning package")
            need(all(event.get("Action") in ("start", "run", "pause", "cont", "output", "pass") for event in events), "failure, skip or unknown Go action")
            for action in ("run", "pass"):
                actual = collections.Counter(event["Test"] for event in events if event["Action"] == action and event.get("Test"))
                need(actual == collections.Counter(want), name + " exact " + action + " census differs")
            for action in ("start", "pass"):
                need(sum(event["Action"] == action and not event.get("Test") for event in events) == 1, "owning package completion differs")
            for suffix in (".exit", ".tee.exit"):
                need((logs / (name + suffix)).read_text() == "0\n", "original Go or tee exit differs")
            need("WARNING: DATA RACE" not in (logs / (name + ".stderr")).read_text(), "race warning retained")
            need(not any("WARNING: DATA RACE" in event.get("Output", "") for event in events), "Go JSON race warning retained")
            result["summary"][name] = {"package": package, "roots": len(spec["cases"]),
                                       "nodes": len(want), "executed": sorted(want), "skips": 0, "failures": 0,
                                       "go_exit": 0, "tee_exit": 0}
        before = database(logs, "before")
        need(database(logs, "after") == before, "Goose history changed during tests")
        need((logs / "migrations.exit").read_text() == "0\n", "original migration exit differs")
        need((logs / "derived-sql.exit").read_text() == "0\n", "Source-derived pre91 SQL byte check failed")
        current_head()
        result["total_roots"] = sum(value["roots"] for value in result["summary"].values())
        result["total_nodes"] = sum(value["nodes"] for value in result["summary"].values())
        result["passed"] = True
    except Exception as error:
        result["failure_class"] = type(error).__name__
        result["failure"] = str(error)
        failure = error
    write_json(logs / "CENSUS.PUBLIC.json", result)
    print(json.dumps(result, sort_keys=True))
    if failure is not None:
        raise failure


def shutdown(logs, original, command_failure):
    value = {"schema": "http_maintenance_dispatch_owned_PostgreSQL_shutdown_v1",
             "original_step_exit": original, "cleanup_command_failure": command_failure,
             "postgres_closed_zero": False, "production_authority": False}
    failure = None
    try:
        names = ("pg-stop", "pg-wait", "pg-state", "pg-log", "pg-remove")
        value["original_cleanup_exits"] = {name: int((logs / (name + ".exit")).read_text()) for name in names}
        state = read_json(logs / "pg-state.stdout")
        closed = all(code == 0 for code in value["original_cleanup_exits"].values())
        closed = closed and (logs / "pg-wait.stdout").read_text() == "0\n"
        closed = closed and state["ExitCode"] == 0 and state["Running"] is False and state["OOMKilled"] is False
        value["postgres_closed_zero"] = closed
        need(closed and command_failure == 0, "owned PostgreSQL shutdown not closed zero")
        need(original == 0, "original CI step failed")
    except Exception as error:
        value["failure_class"] = type(error).__name__
        value["failure"] = str(error)
        failure = error
    write_json(logs / "SHUTDOWN.PUBLIC.json", value)
    print(json.dumps(value, sort_keys=True))
    if failure is not None:
        raise failure


def main():
    logs = Path(os.environ["LOGS"])
    need(logs.is_dir(), "original evidence directory missing")
    action = sys.argv[1]
    if action == "identity":
        identity(logs)
    elif action == "prepare":
        prepare(logs)
    elif action == "census":
        census(logs)
    elif action == "shutdown" and len(sys.argv) == 4:
        shutdown(logs, int(sys.argv[2]), int(sys.argv[3]))
    else:
        raise ValueError("closed CI verifier action required")


if __name__ == "__main__":
    main()
