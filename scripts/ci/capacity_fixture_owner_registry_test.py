#!/usr/bin/env python3
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


if __name__ == "__main__":
    unittest.main()
