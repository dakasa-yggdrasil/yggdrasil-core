#!/usr/bin/env python3
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest


here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("capacity_source_equivalence", here / "capacity_fixture_source_equivalence.py")
equivalence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(equivalence)
go = os.environ.get("CAPACITY_TEST_GO") or shutil.which("go")


@unittest.skipUnless(go, "Go toolchain required")
class CompilerInputEquivalence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.source = Path(self.tmp.name) / "source"
        self.clone = Path(self.tmp.name) / "clone"
        self.source.mkdir()
        (self.source / "go.mod").write_text("module example.invalid/test\n\ngo 1.22\n")
        (self.source / "a.go").write_text('package example\nimport _ "embed"\n//go:embed input.txt\nvar input string\n')
        (self.source / "a_test.go").write_text('package example\nimport "testing"\nfunc TestA(t *testing.T) {}\n')
        (self.source / "input.txt").write_text("original\n")
        (self.source / ".gitignore").write_text("ignored_test.go\n")
        shutil.copytree(self.source, self.clone)

    def tearDown(self):
        self.tmp.cleanup()

    def contents(self):
        return (equivalence.inventory(self.source, go, "./..."), equivalence.inventory(self.clone, go, "./..."))

    def test_equal_checkout(self):
        left, right = self.contents()
        self.assertEqual(left, right)

    def test_untracked_ignored_test_is_detected(self):
        (self.source / "ignored_test.go").write_text('package example\nimport "testing"\nfunc TestExtra(t *testing.T) {}\n')
        left, right = self.contents()
        self.assertNotEqual(left, right)
        self.assertIn("ignored_test.go", left)

    def test_embedded_file_change_is_detected(self):
        (self.source / "input.txt").write_text("changed\n")
        left, right = self.contents()
        self.assertNotEqual(left, right)
        self.assertIn("input.txt", left)


if __name__ == "__main__":
    unittest.main()
