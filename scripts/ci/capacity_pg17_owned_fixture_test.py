#!/usr/bin/env python3
"""Process-isolation regressions for the owned PostgreSQL test runner."""
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

with mock.patch.dict(os.environ, {"CAPACITY_TEST_PG_BIN": "/", "CAPACITY_TEST_GO": sys.executable}):
    spec = importlib.util.spec_from_file_location("owned_fixture", Path(__file__).with_name("capacity_pg17_owned_fixture.py"))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)


class RunnerIsolationTest(unittest.TestCase):
    def tearDown(self):
        fixture.pending_signal = None
        fixture.active_child = None
        fixture.cleanup_uncertain = False

    def test_explicit_postgres_major_matches_binary(self):
        self.assertTrue(fixture.valid_binary_major("postgres (PostgreSQL) 16.15 (Homebrew)", "16"))
        self.assertTrue(fixture.valid_binary_major("postgres (PostgreSQL) 17.6", "17"))
        self.assertFalse(fixture.valid_binary_major("postgres (PostgreSQL) 17.6", "16"))
        self.assertFalse(fixture.valid_binary_major("postgres (PostgreSQL) 16.15", "17"))
        self.assertFalse(fixture.valid_binary_major("postgres (PostgreSQL) 18.1", "18"))
        self.assertFalse(fixture.valid_binary_major("postgres (PostgreSQL) 16.15 extra\n17", "16"))

    def test_child_does_not_inherit_credentials_or_postgres_overrides(self):
        with mock.patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "sentinel", "PGHOST": "not-the-fixture"}):
            child = fixture.run([sys.executable, "-c", "import os; print('AWS_SECRET_ACCESS_KEY' in os.environ, 'PGHOST' in os.environ)"])
        self.assertEqual(child.stdout.strip(), "False False")

    def test_signal_during_spawn_kills_and_joins_the_new_child(self):
        child = mock.Mock(pid=12345)
        child.poll.return_value = None

        def spawn(*_args, **_kwargs):
            fixture.interrupted(signal.SIGTERM, None)
            return child

        with mock.patch.object(fixture.subprocess, "Popen", side_effect=spawn), mock.patch.object(fixture.os, "killpg") as killpg:
            with self.assertRaises(InterruptedError):
                fixture.run(["unused"])
        killpg.assert_called_once_with(12345, signal.SIGKILL)
        child.communicate.assert_called_once()

    def test_exited_leader_with_child_holding_pipes_times_out(self):
        code = "import subprocess,sys; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])"
        start = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            fixture.run([sys.executable, "-c", code], timeout=0.5)
        self.assertLess(time.monotonic() - start, 8)

    def test_uncertain_descendant_preserves_owner_directory(self):
        child = mock.Mock(pid=12345)
        child.communicate.side_effect = [
            subprocess.TimeoutExpired("fixture", 1),
            subprocess.TimeoutExpired("fixture", 5),
        ]
        with mock.patch.object(fixture.subprocess, "Popen", return_value=child), mock.patch.object(fixture.os, "killpg"):
            with self.assertRaises(subprocess.TimeoutExpired):
                fixture.run(["unused"], timeout=1)
        self.assertTrue(fixture.cleanup_uncertain)
        child.wait.assert_called_once_with(timeout=5)
        for pipe in (child.stdin, child.stdout, child.stderr):
            pipe.close.assert_called_once()
        with tempfile.TemporaryDirectory() as temp:
            owner = Path(temp) / "owner"
            owner.mkdir()
            with self.assertRaisesRegex(RuntimeError, "cleanup uncertain"):
                fixture.remove_owner_if_safe(owner)
            self.assertTrue(owner.is_dir())

    @unittest.skipUnless(os.environ.get("CAPACITY_TEST_PG_BIN"), "owned PostgreSQL tools not configured")
    def test_real_sigterm_stops_owned_postgres_and_writes_cleanup_receipt(self):
        parent = Path(tempfile.mkdtemp(prefix="dk-own-", dir=os.path.realpath("/tmp")))
        marker = parent / "slow-child-ready"
        fake_go = parent / "slow-go"
        fake_go.write_text("#!/usr/bin/env python3\nimport pathlib,time\npathlib.Path(" + repr(str(marker)) + ").write_text('ready')\ntime.sleep(90)\n")
        fake_go.chmod(0o700)
        env = {key: os.environ[key] for key in fixture.ENV_KEYS if key in os.environ}
        env.update(CAPACITY_TEST_PG_BIN=os.environ["CAPACITY_TEST_PG_BIN"], CAPACITY_TEST_GO=str(fake_go), CAPACITY_TEST_PARENT_DIR=str(parent))
        proc = subprocess.Popen([sys.executable, str(Path(__file__).with_name("capacity_pg17_owned_fixture.py"))], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        clean = False
        try:
            deadline = time.monotonic() + 30
            while not marker.exists() and proc.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(marker.exists(), f"owned PG did not reach slow child; preserve {parent}")
            proc.send_signal(signal.SIGTERM)
            proc.communicate(timeout=45)
            self.assertNotEqual(proc.returncode, 0)
            self.assertEqual((parent / "cleanup-receipt").read_text(), "owner-cleaned-v1\n")
            self.assertEqual(list(parent.glob("dk-pg-*")), [])
            clean = True
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            if clean:
                import shutil
                shutil.rmtree(parent)

    @unittest.skipUnless(os.environ.get("CAPACITY_TEST_PG_BIN"), "owned PostgreSQL tools not configured")
    def test_nested_registry_socket_path_accepts_real_postgres(self):
        # Exercise the same registry depth used by CI, not just the shorter
        # standalone owner path. Keep socket paths portable to Darwin/Linux.
        import shutil
        pg = Path(os.environ["CAPACITY_TEST_PG_BIN"]).resolve(strict=True)
        registry = Path(tempfile.mkdtemp(prefix="dk-reg-", dir=os.path.realpath("/tmp")))
        parent = Path(tempfile.mkdtemp(prefix="dk-own-", dir=registry))
        owner = Path(tempfile.mkdtemp(prefix="dk-pg-", dir=parent))
        data, sock = owner / "data", owner / "socket"
        sock.mkdir(mode=0o700)
        clean = False
        try:
            self.assertLessEqual(len(os.fsencode(str(sock / ".s.PGSQL.54383"))), 103)
            fixture.run([pg / "initdb", "-D", data, "--username=postgres", "--auth-local=trust", "--auth-host=reject", "--encoding=UTF8", "--no-locale"])
            fixture.run([pg / "pg_ctl", "-D", data, "-l", owner / "postgres.log", "-o", f"-k {sock} -h '' -p 54383", "-w", "-t", "20", "start"])
            fixture.run([pg / "pg_ctl", "-D", data, "-m", "fast", "-w", "-t", "20", "stop"])
            self.assertFalse((data / "postmaster.pid").exists())
            clean = True
        finally:
            if (data / "postmaster.pid").exists():
                try:
                    fixture.run([pg / "pg_ctl", "-D", data, "-m", "fast", "-w", "-t", "20", "stop"])
                except Exception:
                    raise RuntimeError(f"owned PostgreSQL shutdown uncertain; retain {registry}")
            if clean and not (data / "postmaster.pid").exists():
                shutil.rmtree(registry)

    @unittest.skipUnless(sys.platform.startswith("linux") and os.environ.get("CAPACITY_TEST_PG_BIN") and os.environ.get("CAPACITY_TEST_GO"), "Linux, Go and owned PostgreSQL tools required")
    def test_parent_death_stops_real_owned_postgres_and_external_registry_confirms(self):
        registry = Path(tempfile.mkdtemp(prefix="dk-reg-", dir=os.path.realpath("/tmp")))
        parent = Path(tempfile.mkdtemp(prefix="dk-own-", dir=registry))
        marker = parent / "slow-child-ready"
        fake_go = parent / "slow-go"
        fake_go.write_text("#!/usr/bin/env python3\nimport pathlib,time\npathlib.Path(" + repr(str(marker)) + ").write_text('ready')\ntime.sleep(90)\n")
        fake_go.chmod(0o700)
        source = parent / "test-parent.go"
        source.write_text('''package main
import("os";"os/exec";"syscall")
func main(){c:=exec.Command(os.Args[1],os.Args[2]);c.Stdout=os.Stdout;c.Stderr=os.Stderr;c.SysProcAttr=&syscall.SysProcAttr{Pdeathsig:syscall.SIGTERM};if c.Start()!=nil{os.Exit(2)};if c.Wait()!=nil{os.Exit(3)}}
''')
        binary = parent / "test-parent"
        subprocess.run([os.environ["CAPACITY_TEST_GO"], "build", "-o", str(binary), str(source)], check=True, timeout=90, capture_output=True)
        env = {key: os.environ[key] for key in fixture.ENV_KEYS if key in os.environ}
        env.update(CAPACITY_TEST_PG_BIN=os.environ["CAPACITY_TEST_PG_BIN"], CAPACITY_TEST_GO=str(fake_go), CAPACITY_TEST_PARENT_DIR=str(parent), CAPACITY_TEST_OWNER_ROOT=str(registry))
        proc = subprocess.Popen([str(binary), sys.executable, str(Path(__file__).with_name("capacity_pg17_owned_fixture.py"))], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        clean = False
        try:
            deadline = time.monotonic() + 30
            while not marker.exists() and proc.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(marker.exists(), f"owned PG did not reach slow child; preserve {registry}")
            proc.kill()
            proc.wait(timeout=5)
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("capacity_fixture_owner_registry.py")), "--registry", str(registry)], capture_output=True, text=True, timeout=55)
            self.assertEqual(result.returncode, 0, f"external cleanup verification failed; preserve {registry}: {result.stdout}")
            self.assertEqual((parent / "cleanup-receipt").read_text(), "owner-cleaned-v1\n")
            self.assertEqual(list(parent.glob("dk-pg-*")), [])
            clean = True
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            if clean:
                import shutil
                shutil.rmtree(registry)


if __name__ == "__main__":
    unittest.main()
