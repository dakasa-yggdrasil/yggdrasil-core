#!/usr/bin/env python3
import errno
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("owner_registry", Path(__file__).with_name("capacity_fixture_owner_registry.py"))
registry_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(registry_module)


class RegistryCheck(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="dk-reg-", dir=os.path.realpath("/tmp")))
        self.owner = Path(tempfile.mkdtemp(prefix="dk-own-", dir=self.root))
        (self.owner / "owner-identity.json").write_text(json.dumps({"schema": "capacity_fixture_owner_identity_v1", "pid": 12345, "start_ticks": 1, "boot_id": "00000000-0000-0000-0000-000000000000"}))
        (self.owner / "cleanup-receipt").write_text("owner-cleaned-v1\n")
        self.original_read = Path.read_text

    def tearDown(self):
        shutil.rmtree(self.root)

    def verify(self, alive=False):
        original = self.original_read
        def read(path, *args, **kwargs):
            if str(path) == "/proc/sys/kernel/random/boot_id":
                return "00000000-0000-0000-0000-000000000000\n"
            return original(path, *args, **kwargs)
        with mock.patch.object(Path, "read_text", read), mock.patch.object(registry_module, "live", return_value=alive):
            return registry_module.verify(self.root, wait_seconds=0)

    def test_closed_owner_and_receipt_pass(self):
        self.assertTrue(self.verify()["local_cleanup_confirmed"])

    def test_live_owner_refuses_even_with_receipt(self):
        with self.assertRaisesRegex(RuntimeError, "still running"):
            self.verify(alive=True)
        self.assertTrue(self.owner.exists())

    def test_missing_receipt_or_remaining_pg_preserves_evidence(self):
        (self.owner / "cleanup-receipt").unlink()
        with self.assertRaisesRegex(RuntimeError, "receipt unavailable"):
            self.verify()
        self.assertTrue(self.owner.exists())
        (self.owner / "cleanup-receipt").write_text("owner-cleaned-v1\n")
        (self.owner / "dk-pg-remains").mkdir()
        with self.assertRaisesRegex(RuntimeError, "PostgreSQL directory remains"):
            self.verify()
        self.assertTrue(self.owner.exists())

    def proc_reader(self, result):
        original = self.original_read

        def read(path, *args, **kwargs):
            if str(path) == "/proc/sys/kernel/random/boot_id":
                return "00000000-0000-0000-0000-000000000000\n"
            if str(path) == "/proc/12345/stat":
                if isinstance(result, BaseException):
                    raise result
                return result
            return original(path, *args, **kwargs)
        return read

    def test_proc_disappearance_still_requires_receipt_and_no_remaining_pg(self):
        identity_path = self.owner / "owner-identity.json"
        original_identity = identity_path.read_bytes()
        identity = json.loads(original_identity)
        boot = identity["boot_id"]
        receipt = self.owner / "cleanup-receipt"
        remains = self.owner / "dk-pg-remains"
        for error in (FileNotFoundError(errno.ENOENT, "process no longer exists"),
                      ProcessLookupError(errno.ESRCH, "process exited during proc read")):
            with self.subTest(errno=error.errno), mock.patch.object(Path, "read_text", self.proc_reader(error)):
                self.assertFalse(registry_module.live(identity, boot))
                result = registry_module.verify(self.root, wait_seconds=0)
                self.assertTrue(result["local_cleanup_confirmed"])
                self.assertFalse(result["native_qualified"])
                receipt.unlink()
                with self.assertRaisesRegex(RuntimeError, "receipt unavailable"):
                    registry_module.verify(self.root, wait_seconds=0)
                self.assertTrue(self.owner.is_dir())
                self.assertEqual(identity_path.read_bytes(), original_identity)
                receipt.write_text("owner-cleaned-v1\n")
                remains.mkdir()
                with self.assertRaisesRegex(RuntimeError, "PostgreSQL directory remains"):
                    registry_module.verify(self.root, wait_seconds=0)
                self.assertTrue(remains.is_dir())
                self.assertEqual(receipt.read_text(), "owner-cleaned-v1\n")
                remains.rmdir()

    def test_proc_uncertainty_and_live_or_invalid_identity_preserve_evidence(self):
        identity_path = self.owner / "owner-identity.json"
        original_identity = identity_path.read_bytes()
        identity = json.loads(original_identity)
        boot = identity["boot_id"]
        for error in (PermissionError(errno.EACCES, "process read permission denied"),
                      OSError(errno.EIO, "process read uncertain")):
            with self.subTest(errno=error.errno), mock.patch.object(Path, "read_text", self.proc_reader(error)):
                for operation in (lambda: registry_module.live(identity, boot),
                                  lambda: registry_module.verify(self.root, wait_seconds=0)):
                    with self.assertRaises(OSError) as raised:
                        operation()
                    self.assertEqual(raised.exception.errno, error.errno)
                self.assertTrue(self.owner.is_dir())
                self.assertEqual(identity_path.read_bytes(), original_identity)
                self.assertEqual((self.owner / "cleanup-receipt").read_text(), "owner-cleaned-v1\n")

        def process_stat(state, ticks):
            return "12345 (declared CI process) " + " ".join([state] + ["0"] * 18 + [str(ticks)])

        with mock.patch.object(Path, "read_text", self.proc_reader(process_stat("R", 1))):
            self.assertTrue(registry_module.live(identity, boot))
            with self.assertRaisesRegex(RuntimeError, "still running"):
                registry_module.verify(self.root, wait_seconds=0)
            with self.assertRaisesRegex(RuntimeError, "invalid owner identity"):
                registry_module.live({**identity, "boot_id": "11111111-1111-1111-1111-111111111111"}, boot)
        for state, ticks in (("Z", 1), ("R", 2)):
            with self.subTest(state=state, ticks=ticks), mock.patch.object(Path, "read_text", self.proc_reader(process_stat(state, ticks))):
                self.assertFalse(registry_module.live(identity, boot))
                self.assertTrue(registry_module.verify(self.root, wait_seconds=0)["local_cleanup_confirmed"])
        with mock.patch.object(Path, "read_text", self.proc_reader("malformed proc stat")):
            with self.assertRaisesRegex(RuntimeError, "process state unavailable"):
                registry_module.verify(self.root, wait_seconds=0)
        self.assertTrue(self.owner.is_dir())
        self.assertEqual(identity_path.read_bytes(), original_identity)
        self.assertEqual((self.owner / "cleanup-receipt").read_text(), "owner-cleaned-v1\n")


if __name__ == "__main__":
    unittest.main()
