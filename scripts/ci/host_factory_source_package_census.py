#!/usr/bin/env python3
"""Remote CI only. Exact Source test census; never execute this on the owner laptop."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import sys


SCHEMA = "host_factory_source_package_census_v2"
MAX_RAW_BYTES = 32 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_EVENTS = 262144


def closed_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def decode(raw):
    def refuse_constant(_):
        raise ValueError("non-JSON numeric constant")
    return json.loads(raw, object_pairs_hook=closed_object, parse_constant=refuse_constant)


def write_json(path, value, exclusive=False):
    with path.open("x" if exclusive else "w", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")


def selected(expected, phase):
    if expected.get("schema") != "host_factory_source_package_expected_v2":
        raise ValueError("unknown expected manifest schema")
    phases = expected.get("phases")
    if not isinstance(phases, dict) or set(phases) != {"profile", "persistence", "package", "main"} or phase not in phases:
        raise ValueError("unknown Source phase")
    total_children = 0
    total_roots = 0
    for phase_value in phases.values():
        phase_roots = phase_value.get("roots")
        if phase_value.get("complete") is not True or not isinstance(phase_roots, list):
            raise ValueError("whole Source phase roster remains incomplete")
        if phase_value.get("root_count") != len(phase_roots):
            raise ValueError("declared root census differs from exact roster")
        total_roots += len(phase_roots)
        for row in phase_roots:
            if row.get("children_complete") is not True or not isinstance(row.get("children"), list):
                raise ValueError("UNRESOLVED child census; no positive execution/census permitted")
            if row.get("child_count") != len(row["children"]):
                raise ValueError("declared child census differs from exact roster")
            total_children += len(row["children"])
    if expected.get("whole_child_count") != total_children:
        raise ValueError("whole descendant census unknown/different")
    if expected.get("root_count") != total_roots:
        raise ValueError("whole root census differs from exact rosters")
    value = phases[phase]
    roots = value.get("roots")
    if not isinstance(roots, list) or not roots:
        raise ValueError("missing exact root roster")
    names = [row.get("name") for row in roots]
    if any(not isinstance(name, str) or not re.fullmatch(r"Test[A-Za-z0-9_]+", name) for name in names):
        raise ValueError("invalid root name")
    if len(names) != len(set(names)):
        raise ValueError("duplicate expected root")
    for row in roots:
        children = row.get("children")
        if row.get("children_complete") is not True or not isinstance(children, list):
            raise ValueError("UNRESOLVED child census; no positive execution/census permitted")
        if any(not isinstance(name, str) or not name or name.startswith("/") for name in children):
            raise ValueError("invalid expected descendant")
        if len(children) != len(set(children)):
            raise ValueError("duplicate expected descendant")
    if expected.get("complete") is not True or value.get("complete") is not True:
        raise ValueError("whole Source census/provenance remains incomplete")
    return value, names


def preflight(args):
    audit = Path(args.audit)
    if not audit.is_dir() or any(audit.iterdir()):
        raise ValueError("audit directory must be newly created and empty")
    status = {"schema": SCHEMA, "state": "INCOMPLETE", "phase": args.phase,
              "go_exit": None, "tee_exit": None, "census_exit": None}
    write_json(audit / "status.json", status, exclusive=True)
    raw = Path(args.expected).read_bytes()
    (audit / "expected.json").write_bytes(raw)
    (audit / "expected.sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n")
    try:
        expected = decode(raw)
        value, names = selected(expected, args.phase)
        observed = []
        for source in value["source_files"]:
            path = Path(args.repository) / source["path"]
            body = path.read_bytes()
            row = {"path": source["path"], "bytes": len(body),
                   "sha256": hashlib.sha256(body).hexdigest()}
            observed.append(row)
            if row["bytes"] != source["bytes"] or row["sha256"] != source["sha256"]:
                raise ValueError("selected Source file differs from frozen expected roster")
        write_json(audit / "source-files.json", observed, exclusive=True)
        (audit / "root-regex.txt").write_text("^(" + "|".join(sorted(names)) + ")$\n")
        status["state"] = "PREPARED_NOT_EXECUTED"
        write_json(audit / "status.json", status)
        return 0
    except Exception as error:
        status.update(state="BLOCKED_BEFORE_GO", reason=str(error), census_exit=1)
        write_json(audit / "status.json", status)
        return 1


def census(args):
    audit = Path(args.audit)
    status = decode((audit / "status.json").read_bytes())
    original_state = status.get("state")
    status.update(state="INCOMPLETE", go_exit=args.go_exit, tee_exit=args.tee_exit,
                  census_exit=None)
    write_json(audit / "status.json", status)
    failures = []
    result = {"schema": SCHEMA, "phase": args.phase,
              "state": "INCOMPLETE", "failures": failures,
              "go_exit": args.go_exit, "tee_exit": args.tee_exit,
              "expected_names": None, "observed_names": None}
    try:
        if original_state != "PREPARED_NOT_EXECUTED":
            raise ValueError("missing original preflight or repeated census attempt")
        expected_raw = (audit / "expected.json").read_bytes()
        if hashlib.sha256(expected_raw).hexdigest() + "\n" != (audit / "expected.sha256").read_text():
            raise ValueError("expected manifest changed after original preflight")
        expected = decode(expected_raw)
        value, roots = selected(expected, args.phase)
        if status.get("phase") != args.phase:
            raise ValueError("foreign original phase status")
        raw_path = audit / "raw.jsonl"
        if raw_path.stat().st_size > MAX_RAW_BYTES:
            raise ValueError("original GoJSON exceeds 32MiB; original file retained without trimming")
        if not (audit / "stderr.log").is_file() or not (audit / "tee.stderr.log").is_file():
            raise ValueError("missing original stderr artifact")
        expected_names = set(roots)
        for row in value["roots"]:
            expected_names.update(row["name"] + "/" + name for name in row["children"])
        starts = collections.Counter()
        terminals = collections.Counter()
        package_starts = 0
        package_passes = 0
        events = 0
        with raw_path.open("rb") as source:
            while True:
                line = source.readline(MAX_LINE_BYTES + 1)
                if not line:
                    break
                events += 1
                if events > MAX_EVENTS or len(line) > MAX_LINE_BYTES:
                    raise ValueError("original event/line bound exceeded; no truncation/recovery")
                if not line.endswith(b"\n"):
                    raise ValueError("partial final GoJSON line")
                event = decode(line)
                if not isinstance(event, dict) or event.get("Package") != value["go_json_package"]:
                    raise ValueError("unknown/missing original package")
                action = event.get("Action")
                if action not in {"start", "run", "pause", "cont", "pass", "fail", "skip", "output"}:
                    raise ValueError("unknown original event action")
                name = event.get("Test")
                if name is not None and (not isinstance(name, str) or name not in expected_names):
                    raise ValueError("unexpected original test/descendant name")
                if action in {"fail", "skip"}:
                    failures.append("original fail/skip event: " + str(name))
                if name is None:
                    if action == "start":
                        package_starts += 1
                    elif action == "pass":
                        package_passes += 1
                    elif action not in {"output", "fail", "skip"}:
                        raise ValueError("test event missing original test identity")
                    continue
                if action == "run":
                    starts[name] += 1
                    if starts[name] != 1 or terminals[name]:
                        raise ValueError("duplicate/out-of-order original run")
                elif action in {"pass", "fail", "skip"}:
                    terminals[name] += 1
                    if starts[name] != 1 or terminals[name] != 1:
                        raise ValueError("missing/duplicate original terminal")
                elif action in {"pause", "cont"} and (starts[name] != 1 or terminals[name]):
                    raise ValueError("pause/continue outside original running interval")
        if package_starts != 1 or package_passes != 1:
            failures.append("expected exactly one package start and package pass")
        if set(starts) != expected_names or set(terminals) != expected_names:
            failures.append("missing exact original root/descendant run/pass census")
        if args.go_exit != 0 or args.tee_exit != 0:
            failures.append("original Go or tee command failed")
        result.update(expected_names=len(expected_names), observed_names=len(starts),
                      events=events, raw_sha256=hashlib.sha256(raw_path.read_bytes()).hexdigest(),
                      raw_bytes=raw_path.stat().st_size)
    except Exception as error:
        failures.append(str(error))
    code = 1 if failures else 0
    result["state"] = "REFUSED" if code else "SOURCE_CASES_COMPLETE_NOT_NATIVE"
    write_json(audit / "census.json", result)
    status.update(state=result["state"], census_exit=code)
    write_json(audit / "status.json", status)
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["preflight", "census"])
    parser.add_argument("--expected")
    parser.add_argument("--phase", required=True, choices=["profile", "persistence", "package", "main"])
    parser.add_argument("--audit", required=True)
    parser.add_argument("--repository", default=".")
    parser.add_argument("--go-exit", type=int)
    parser.add_argument("--tee-exit", type=int)
    args = parser.parse_args()
    if args.mode == "preflight":
        if not args.expected:
            parser.error("preflight requires --expected")
        return preflight(args)
    if args.go_exit is None or args.tee_exit is None:
        parser.error("census requires both actual original command returns")
    return census(args)


if __name__ == "__main__":
    sys.exit(main())
