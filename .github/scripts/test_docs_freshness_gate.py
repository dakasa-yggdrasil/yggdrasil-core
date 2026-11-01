"""Exercise the workflow's real gate with large and ordinary PR file lists."""
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / 'workflows' / 'docs-freshness.yml'

class GateDecision(unittest.TestCase):
    def decide(self, files):
        workflow = WORKFLOW.read_text()
        start = workflow.index('          # Economy path 1:')
        end = workflow.index('      - name: Reconcile docs with the code (AI) and commit to the PR', start)
        gate = textwrap.dedent(workflow[start:end])
        with tempfile.TemporaryDirectory() as tmp:
            changed = Path(tmp) / 'changed'
            output = Path(tmp) / 'output'
            changed.write_text('\n'.join(files) + '\n')
            env = dict(os.environ, GITHUB_OUTPUT=str(output))
            result = subprocess.run(['bash', '-c', 'set -euo pipefail\nchanged=$(cat "$1")\n' + gate, '_', str(changed)], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return output.read_text().strip()

    def test_large_diff_with_stamp_is_recognized(self):
        files = ['controllers/' + str(n).zfill(6) + '.go' for n in range(10000)]
        files.insert(50, 'docs/AI_DOCS_FRESHNESS.md')
        self.assertEqual(self.decide(files), 'run_ai=false')

    def test_similar_nonstamp_path_does_not_skip(self):
        self.assertEqual(self.decide(['docs/AI_DOCS_FRESHNESSXmd', 'controller.go']), 'run_ai=true')

    def test_code_without_stamp_requests_review(self):
        self.assertEqual(self.decide(['docs/readme.md', 'controller.go']), 'run_ai=true')

    def test_only_docs_skip_review(self):
        self.assertEqual(self.decide(['docs/readme.md', 'README.md']), 'run_ai=false')

if __name__ == '__main__':
    unittest.main(verbosity=2)
