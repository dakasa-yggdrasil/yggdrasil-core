#!/usr/bin/env python3
"""Compare local Go compiler inputs of an original and a clean checkout.

This establishes source-input equality for one Go test invocation only; it
does not establish binary, runtime, native-provider or production equivalence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


SOURCE_FIELDS = (
    "GoFiles", "CgoFiles", "CFiles", "CXXFiles", "MFiles", "HFiles", "FFiles",
    "SFiles", "SwigFiles", "SwigCXXFiles", "SysoFiles", "EmbedFiles",
    "TestGoFiles", "XTestGoFiles", "TestEmbedFiles", "XTestEmbedFiles",
)


def packages(raw):
    decoder = json.JSONDecoder()
    pos = 0
    while pos < len(raw):
        while pos < len(raw) and raw[pos].isspace():
            pos += 1
        if pos == len(raw):
            break
        item, pos = decoder.raw_decode(raw, pos)
        yield item


def inventory(root, go_binary, package):
    root = Path(root).resolve(strict=True)
    env = dict(os.environ, GOWORK="off")
    raw = subprocess.check_output([str(go_binary), "list", "-deps", "-test", "-race", "-json", package], cwd=root, env=env, text=True, timeout=120)
    found = {}
    for item in packages(raw):
        # Go generates the test main in its build cache from the listed test
        # inputs. Its absolute cache path is not a source input of either tree.
        if item.get("ImportPath", "").endswith(".test") and item.get("Name") == "main":
            continue
        replacement = item.get("Module", {}).get("Replace", {}) if item.get("Module") else {}
        if replacement and not replacement.get("Version"):
            raise RuntimeError("local module replacement is outside the qualification scope")
        directory = Path(item.get("Dir", "/nonexistent"))
        try:
            relative = directory.relative_to(root)
        except ValueError:
            continue  # Standard library and module-cache dependencies are shared.
        for field in SOURCE_FIELDS:
            for name in item.get(field, []):
                path = directory / name
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(root) or not resolved.is_file():
                    raise RuntimeError("local input escapes the checkout or is not a file")
                key = str(relative / name)
                digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
                if key in found and found[key] != digest:
                    raise RuntimeError("ambiguous local source input")
                found[key] = digest
    if not found:
        raise RuntimeError("no local source inputs found")
    for name in ("go.mod", "go.sum"):
        path = root / name
        if path.exists():
            found[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return found


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--clone", required=True)
    parser.add_argument("--go", required=True)
    parser.add_argument("--package", required=True)
    args = parser.parse_args()
    if os.environ.get("GOWORK", "off") != "off":
        raise RuntimeError("GOWORK=off required for the qualification test")
    before = inventory(args.source, args.go, args.package)
    after = inventory(args.clone, args.go, args.package)
    if before != after:
        raise SystemExit("compiled local inputs differ from the clean checkout")
    print(json.dumps({"schema": "capacity_go_test_source_inputs_v1", "inputs": len(before), "equivalent": True, "native_qualified": False}))


if __name__ == "__main__":
    main()
