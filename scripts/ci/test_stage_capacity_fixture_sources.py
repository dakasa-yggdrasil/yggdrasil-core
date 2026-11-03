import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("stage_capacity_fixture_sources.sh").resolve()
NAMES = (".ci-native-hetzner", ".ci-bound-prometheus", ".ci-bound-kubernetes", ".ci-original-notify")


class FixtureSourceStageTest(unittest.TestCase):
    def run_stage(self, extra=False, symlink=False, inside=False, dirty=False):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            workspace = base / "source"
            workspace.mkdir()
            runner = workspace / "runner" if inside else base / "runner"
            runner.mkdir()
            subprocess.run(["git", "init", "-q", str(workspace)], check=True)
            subprocess.run(["git", "-C", str(workspace), "config", "user.name", "Giomaster"], check=True)
            subprocess.run(["git", "-C", str(workspace), "config", "user.email", "giovanni.martins@dakasa.me"], check=True)
            (workspace / "tracked").write_text("source\n")
            subprocess.run(["git", "-C", str(workspace), "add", "tracked"], check=True)
            subprocess.run(["git", "-C", str(workspace), "commit", "-q", "-m", "fixture"], check=True)
            for name in NAMES:
                if symlink and name == NAMES[0]:
                    (workspace / name).symlink_to(runner, target_is_directory=True)
                else:
                    (workspace / name).mkdir()
                    (workspace / name / "source").write_text(name)
            if extra:
                (workspace / "unexpected").write_text("not hidden")
            if dirty:
                (workspace / "tracked").write_text("modified")
            envfile = base / "env"
            envfile.touch()
            env = dict(os.environ, GITHUB_WORKSPACE=str(workspace), RUNNER_TEMP=str(runner), GITHUB_ENV=str(envfile))
            result = subprocess.run(["bash", str(SCRIPT)], cwd=workspace, env=env, capture_output=True)
            if extra or symlink or inside or dirty:
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(envfile.read_text(), "")
                if symlink or inside:
                    self.assertTrue((workspace / NAMES[-1]).is_dir())
                return
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            line = envfile.read_text().strip()
            self.assertTrue(line.startswith("CAPACITY_NOTIFY_FIXTURE_SOURCE_DIR="))
            notify = Path(line.split("=", 1)[1])
            self.assertEqual(notify.parent.parent, runner.resolve())
            self.assertEqual((notify / "source").read_text(), NAMES[-1])
            self.assertEqual(subprocess.check_output(["git", "status", "--porcelain"], cwd=workspace), b"")
            self.assertTrue(all((notify.parent / name / "source").read_text() == name for name in NAMES))

    def test_stages_exact_sources_outside_clean_core(self):
        self.run_stage()

    def test_refuses_untracked_and_symlink(self):
        self.run_stage(extra=True)
        self.run_stage(symlink=True)
        self.run_stage(inside=True)
        self.run_stage(dirty=True)


if __name__ == "__main__":
    unittest.main()
