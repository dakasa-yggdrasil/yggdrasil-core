"""Select and account for authored readiness cases; tests run only in CI."""

import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re


PREFIX = "github.com/dakasa-yggdrasil/yggdrasil-core/"
PATTERNS = {
    "repository": "capacity_native_worker_readiness*_test.go",
    "internal/capacity": "native_worker_readiness*_test.go",
    "model": "capacity_native_worker_readiness*_test.go",
    "addons": "native_worker_readiness*_test.go",
    "controllers/httpapi": "native_worker_probe_resources_test.go",
    "controllers/message": "native_worker_readiness_resources_test.go",
}


def select(group, directory):
    rows = []
    for package, pattern in PATTERNS.items():
        for path in sorted(Path(package).glob(pattern)):
            text = path.read_text()
            tag = re.search(r"^//go:build ([^\n]+)", text, re.M)
            kind = "ownership" if tag and "native_readiness_ownership" in tag.group(1) else (
                "postgres" if path.name.endswith("_postgres_test.go") else "unit"
            )
            if kind != group:
                continue
            names = re.findall(r"^func (Test\w+)\(t \*testing\.T\)", text, re.M)
            if not names:
                raise SystemExit("No authored cases found: " + str(path))
            rows.extend({"package": PREFIX + package, "name": name, "path": str(path)} for name in names)
    identities = [(r["package"], r["name"]) for r in rows]
    if not rows or len(identities) != len(set(identities)):
        raise SystemExit("Empty or duplicate readiness case set")
    rows.sort(key=lambda r: (r["package"], r["name"]))
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "expected.json").write_text(json.dumps(rows, indent=2) + "\n")
    (directory / "selector.txt").write_text("^(" + "|".join(sorted({r["name"] for r in rows})) + ")$\n")
    (directory / "packages.txt").write_text("\n".join(sorted({"./" + r["package"][len(PREFIX):] for r in rows})) + "\n")


def verify(group, directory):
    expected = json.loads((directory / "expected.json").read_text())
    wanted = collections.Counter((r["package"], r["name"]) for r in expected)
    events = [json.loads(line) for line in (directory / "original.jsonl").read_text().splitlines() if line.strip()]
    if any(e.get("Action") in ("fail", "skip") for e in events):
        raise SystemExit("A readiness case failed or skipped")
    for action in ("run", "pass"):
        actual = collections.Counter(
            (e.get("Package"), e["Test"]) for e in events
            if e.get("Action") == action and e.get("Test") and "/" not in e["Test"]
        )
        if actual != wanted:
            raise SystemExit("Missing, repeated or unexpected readiness roots: " + action)
    package_passes = collections.Counter(
        e.get("Package") for e in events if e.get("Action") == "pass" and not e.get("Test")
    )
    if package_passes != collections.Counter({r["package"]: 1 for r in expected}):
        raise SystemExit("A readiness package did not finish exactly once")
    source = os.environ["SOURCE_COMMIT"]
    if re.fullmatch(r"[a-f0-9]{40}", source) is None:
        raise SystemExit("Missing exact checkout Source")
    evidence = {
        p.name: {"bytes": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
        for p in sorted(directory.iterdir()) if p.is_file() and p.name != "qualified.json"
    }
    receipt = {
        "schema": "native_readiness_controller_ci_v1", "group": group,
        "head": source, "event_sha": os.environ["GITHUB_SHA"],
        "roots": expected, "race": True, "count": 1, "skips": 0,
        "evidence": evidence, "live_or_provider_qualification": False,
    }
    if group == "postgres":
        version = (directory / "postgres-version.txt").read_text().strip()
        major = int(os.environ["EXPECTED_POSTGRES_MAJOR"])
        if not version.isdigit() or int(version) // 10000 != major:
            raise SystemExit("Wrong actual PostgreSQL major")
        receipt["postgres_major"] = major
    (directory / "qualified.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("select", "verify"))
    parser.add_argument("group", choices=("unit", "postgres", "ownership"))
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    {"select": select, "verify": verify}[args.mode](args.group, args.directory)
