"""Focused offline tests for the fixed read-only projection-root exception.

All projection paths, resolutions, owners, modes, devices and mount flags below
are synthetic. No real /etc, /run, /var/run or credential file is inspected.
"""

import builtins
import contextlib
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import refresh_once as runtime


LISTED = (
    "/etc/dakasa-ecr/admission.json",
    "/var/run/secrets/dakasa-ecr/token",
    "/var/run/secrets/dakasa-ecr/ca.crt",
)


class SyntheticProjection:
    def __init__(self, requested, root_mode=0o777):
        self.requested = requested
        logical_root = runtime.PROJECTED_FILES[requested]
        self.root = Path(runtime.PROJECTED_CANONICAL_ROOTS[logical_root])
        self.inner = self.root / "..synthetic-projection-epoch"
        self.actual = self.inner / Path(requested).name
        self.metadata = {}
        self.readonly = {}
        for path in self.root.parents:
            self.set_metadata(path, stat.S_IFDIR | 0o755, device=1)
        self.set_metadata(self.root, stat.S_IFDIR | root_mode)
        self.set_metadata(self.inner, stat.S_IFDIR | 0o755)
        self.set_metadata(self.actual, stat.S_IFREG | (0o600 if self.actual.name == "token" else 0o400))
        self.resolutions = {
            logical_root: self.root,
            str(self.root): self.root,
            requested: self.actual,
            str(self.actual): self.actual,
        }

    def set_metadata(self, path, mode, owner=0, device=42, readonly=True):
        name = str(path)
        self.metadata[name] = SimpleNamespace(st_mode=mode, st_uid=owner, st_gid=0,
                                              st_dev=device, st_nlink=1)
        self.readonly[name] = readonly

    def change(self, path, *, mode=None, owner=None, device=None, readonly=None):
        name = str(path)
        previous = self.metadata[name]
        self.set_metadata(name, previous.st_mode if mode is None else mode,
                          owner=previous.st_uid if owner is None else owner,
                          device=previous.st_dev if device is None else device,
                          readonly=self.readonly[name] if readonly is None else readonly)

    def lstat(self, path):
        name = str(path)
        if name not in self.metadata:
            raise AssertionError("unexpected synthetic metadata path")
        return self.metadata[name]

    def resolve(self, path, strict=False):
        name = str(path)
        if name in self.resolutions:
            return self.resolutions[name]
        if name in self.metadata:
            return Path(name)
        raise AssertionError("unexpected synthetic resolve path")

    def statvfs(self, path):
        name = str(path)
        if name not in self.readonly:
            raise AssertionError("unexpected synthetic mount metadata path")
        return SimpleNamespace(f_flag=os.ST_RDONLY if self.readonly[name] else 0)

    @contextlib.contextmanager
    def mounted(self):
        fixture = self

        def fake_lstat(path):
            return fixture.lstat(path)

        def fake_stat(path, *args, **kwargs):
            return fixture.lstat(path)

        def fake_resolve(path, strict=False):
            return fixture.resolve(path, strict)

        with mock.patch.object(Path, "lstat", new=fake_lstat):
            with mock.patch.object(Path, "stat", new=fake_stat):
                with mock.patch.object(Path, "resolve", new=fake_resolve):
                    with mock.patch.object(runtime.os, "statvfs", side_effect=self.statvfs):
                        yield


class ReadonlyProjectionRootTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(mock.patch.stopall)
        mock.patch("socket.socket.connect", side_effect=AssertionError("network forbidden")).start()
        mock.patch.object(runtime, "exchange", side_effect=AssertionError("HTTP forbidden")).start()
        mock.patch.object(runtime, "private_read", side_effect=AssertionError("file contents forbidden")).start()
        mock.patch.object(runtime, "KubeSecret", side_effect=AssertionError("Kubernetes client forbidden")).start()
        mock.patch.object(runtime, "HostECR", side_effect=AssertionError("AWS client forbidden")).start()
        original_import = builtins.__import__

        def no_sdk(name, *args, **kwargs):
            if name == "boto3" or name.startswith("boto3.") or name == "botocore" or name.startswith("botocore."):
                raise AssertionError("AWS SDK import forbidden")
            return original_import(name, *args, **kwargs)

        mock.patch("builtins.__import__", side_effect=no_sdk).start()

    def test_all_three_listed_files_accept_only_fixed_readonly_writable_mode_roots(self):
        for requested in LISTED:
            for mode in (0o777, 0o1777):
                with self.subTest(requested=requested, root_mode=oct(mode)):
                    fs = SyntheticProjection(requested, mode)
                    with fs.mounted():
                        self.assertEqual(runtime.input_path(requested), fs.actual)

    def test_projection_root_without_readonly_mount_flag_is_rejected(self):
        for mode in (0o755, 0o777, 0o1777):
            with self.subTest(root_mode=oct(mode)):
                fs = SyntheticProjection(LISTED[0], mode)
                fs.change(fs.root, readonly=False)
                with fs.mounted(), self.assertRaises(runtime.Hold):
                    runtime.input_path(fs.requested)

    def test_readonly_root_does_not_relax_inner_file_or_directory_guards(self):
        for point in ("actual", "inner"):
            for defect in ("writable", "not_readonly"):
                with self.subTest(point=point, defect=defect):
                    fs = SyntheticProjection(LISTED[1], 0o1777)
                    path = getattr(fs, point)
                    if defect == "writable":
                        mode = fs.metadata[str(path)].st_mode | 0o022
                        fs.change(path, mode=mode)
                    else:
                        fs.change(path, readonly=False)
                    with fs.mounted(), self.assertRaises(runtime.Hold):
                        runtime.input_path(fs.requested)

    def test_readonly_projection_never_exempts_writable_external_ancestors(self):
        for requested, external in ((LISTED[0], "/etc"), (LISTED[1], "/run/secrets")):
            with self.subTest(requested=requested, external=external):
                fs = SyntheticProjection(requested, 0o1777)
                fs.change(external, mode=stat.S_IFDIR | 0o777, readonly=True)
                with fs.mounted(), self.assertRaises(runtime.Hold):
                    runtime.input_path(requested)

    def test_escape_wrong_canonical_root_device_owner_symlink_and_type_are_rejected(self):
        for defect in ("escape", "wrong_canonical_root", "file_cross_device", "dir_cross_device",
                       "root_owner", "file_owner", "dir_owner", "root_symlink", "root_not_directory", "inner_symlink",
                       "actual_not_regular", "inner_not_directory"):
            with self.subTest(defect=defect):
                fs = SyntheticProjection(LISTED[2], 0o1777)
                if defect == "escape":
                    fs.resolutions[fs.requested] = Path("/run/secrets/unrelated/ca.crt")
                elif defect == "wrong_canonical_root":
                    fs.resolutions[runtime.PROJECTED_FILES[fs.requested]] = Path("/run/not-the-projection")
                elif defect == "file_cross_device":
                    fs.change(fs.actual, device=99)
                elif defect == "dir_cross_device":
                    fs.change(fs.inner, device=99)
                elif defect == "root_owner":
                    fs.change(fs.root, owner=987654)
                elif defect == "file_owner":
                    fs.change(fs.actual, owner=987654)
                elif defect == "dir_owner":
                    fs.change(fs.inner, owner=987654)
                elif defect == "root_symlink":
                    fs.change(fs.root, mode=stat.S_IFLNK | 0o777)
                elif defect == "root_not_directory":
                    fs.change(fs.root, mode=stat.S_IFREG | 0o777)
                elif defect == "inner_symlink":
                    fs.change(fs.inner, mode=stat.S_IFLNK | 0o755)
                elif defect == "actual_not_regular":
                    fs.change(fs.actual, mode=stat.S_IFDIR | 0o400)
                elif defect == "inner_not_directory":
                    fs.change(fs.inner, mode=stat.S_IFREG | 0o755)
                with fs.mounted(), self.assertRaises(runtime.Hold):
                    runtime.input_path(fs.requested)

    def test_global_trusted_path_and_unlisted_paths_keep_their_strict_rules(self):
        fs = SyntheticProjection(LISTED[0], 0o777)
        normal = Path("/safe/normal.json")
        fs.set_metadata(normal.parent, stat.S_IFDIR | 0o755, device=1)
        fs.set_metadata(normal, stat.S_IFREG | 0o600, device=1)
        unlisted = fs.root / "not-listed.json"
        fs.set_metadata(unlisted, stat.S_IFREG | 0o400)
        with fs.mounted():
            self.assertEqual(runtime.input_path(str(normal)), normal)
            with self.assertRaises(runtime.Hold):
                runtime.trusted_path(fs.root)
            with self.assertRaises(runtime.Hold):
                runtime.input_path(str(unlisted))
            fs.change(normal.parent, mode=stat.S_IFDIR | 0o777, readonly=True)
            with self.assertRaises(runtime.Hold):
                runtime.input_path(str(normal))


if __name__ == "__main__":
    unittest.main()
