#!/usr/bin/env python3
"""Independently check owned Linux fixture shutdown after a test exits.

Uncertain directories are left untouched. This reports local cleanup only,
never provider, Guest, or production qualification.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import time


def private_dir(path):
    info = path.lstat()
    if path.resolve(strict=True) != path or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.geteuid():
        raise RuntimeError("private owner directory required")


def live(identity, boot_id):
    if identity.get("schema") != "capacity_fixture_owner_identity_v1" or identity.get("boot_id") != boot_id or type(identity.get("pid")) is not int or identity["pid"] < 2 or type(identity.get("start_ticks")) is not int:
        raise RuntimeError("invalid owner identity")
    try:
        value = Path("/proc", str(identity["pid"]), "stat").read_text()
    except FileNotFoundError:
        return False
    close = value.rfind(")")
    tail = value[close + 2:].split()
    if close < 1 or len(tail) < 20 or not tail[19].isdigit():
        raise RuntimeError("owner process state unavailable")
    # A reused PID is not the recorded owner. A zombie no longer executes.
    return int(tail[19]) == identity["start_ticks"] and tail[0] != "Z"


def verify(registry, wait_seconds=45):
    registry = Path(registry)
    tmp = Path(os.path.realpath("/tmp"))
    if not registry.is_absolute() or registry.parent != tmp or not registry.name.startswith("dk-reg-"):
        raise RuntimeError("invalid fixture registry path")
    private_dir(registry)
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if not re.fullmatch(r"[0-9a-f-]{36}", boot_id):
        raise RuntimeError("boot identity unavailable")
    deadline = time.monotonic() + wait_seconds
    owners = list(registry.iterdir())
    for owner in owners:
        if not owner.name.startswith("dk-own-"):
            raise RuntimeError("unexpected owner registry entry")
        private_dir(owner)
        identity_file = owner / "owner-identity.json"
        if identity_file.is_symlink() or not identity_file.is_file():
            raise RuntimeError("owner identity unavailable")
        identity = json.loads(identity_file.read_text())
        while live(identity, boot_id) and time.monotonic() < deadline:
            time.sleep(0.05)
        if live(identity, boot_id):
            raise RuntimeError("owner still running")
        receipt = owner / "cleanup-receipt"
        if receipt.is_symlink() or not receipt.is_file() or receipt.read_text() != "owner-cleaned-v1\n":
            raise RuntimeError("owner cleanup receipt unavailable")
        if list(owner.glob("dk-pg-*")):
            raise RuntimeError("owned PostgreSQL directory remains")
    return {"schema": "capacity_fixture_registry_check_v1", "local_cleanup_confirmed": True, "remaining_owner_directories": len(owners), "native_qualified": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", required=True)
    args = parser.parse_args()
    try:
        result = verify(args.registry)
    except (OSError, ValueError, RuntimeError) as exc:
        print(json.dumps({"schema": "capacity_fixture_registry_check_v1", "local_cleanup_confirmed": False, "reason": str(exc), "registry_preserved": args.registry, "native_qualified": False}))
        raise SystemExit(1)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
