#!/usr/bin/env python3
"""Exercise the workflow's real exit-accounting shell with controlled returns."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/capacity-postgres.yml"


class ExitCustody(unittest.TestCase):
    def run_case(self, go_exit, cleanup_exit, expected_exit):
        lines = WORKFLOW.read_text().splitlines()
        start = next(i for i, line in enumerate(lines) if line.strip().startswith('python3 "$capacity_source_dir/clean/scripts/ci/capacity_fixture_owner_registry.py" --registry '))
        end = next(i for i in range(start, len(lines)) if lines[i].strip().startswith("python3 - <<'PY'"))
        begin_finish = next(i for i, line in enumerate(lines) if line.strip().startswith('"$RUNNER_TEMP/capacity-source-corpus-go-owner/status-owner" finish "capacity" '))
        end_finish = next(i for i in range(begin_finish, len(lines)) if lines[i].strip() == 'fi') + 1
        cleanup = '\n'.join(line.removeprefix('          ') for line in lines[start:end])
        finish = '\n'.join(line.removeprefix('          ') for line in lines[begin_finish:end_finish])
        with tempfile.TemporaryDirectory(prefix='capacity-exit-custody-') as directory:
            root = Path(directory)
            owner = root / 'capacity-source-corpus-go-owner'
            owner.mkdir()
            status = owner / 'status-owner'
            status.write_text('#!/bin/bash\nprintf "%s\\n" "$@" > "$CAPTURE"\n')
            status.chmod(0o700)
            (root / 'case').mkdir()
            (root / 'registry').mkdir()
            env = dict(os.environ, RUNNER_TEMP=str(root), CAPTURE=str(root / 'capture'),
                       capacity_source_dir=str(root), core_pg_case_dir=str(root / 'case'),
                       capacity_owner_registry=str(root / 'registry'))
            script = f'''set +e
core_pg_go_exit={go_exit}
core_pg_tee_exit=0
core_pg_census_exit=0
python3() {{ printf '{{"simulated_cleanup":true}}\\n'; return {cleanup_exit}; }}
{cleanup}
{finish}
'''
            result = subprocess.run(['/bin/bash', '-c', script], env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, expected_exit, result.stderr)
            self.assertEqual((root / 'capture').read_text().splitlines(), ['finish', 'capacity', str(go_exit), '0', '0'])
            self.assertEqual((root / 'case' / 'fixture-cleanup-exit.txt').read_text().strip(), str(cleanup_exit))
            self.assertEqual((root / 'registry').exists(), cleanup_exit != 0)

    def test_cleanup_failure_preserves_successful_go_return_and_fails_gate(self):
        self.run_case(0, 7, 1)

    def test_go_failure_is_retained_with_successful_cleanup(self):
        self.run_case(4, 0, 1)

    def test_both_successes_pass(self):
        self.run_case(0, 0, 0)


if __name__ == '__main__':
    unittest.main()
