"""Run the preserved historical/G9 and additive R6 rosters; no host claim."""
import collections
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


HERE = Path(__file__).resolve().parent
OUT = Path(os.environ['GUARDIAN_CI_EVIDENCE'])


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


class Outcomes(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.runs, self.passes = [], []

    def startTest(self, test):
        self.runs.append(test.id())
        super().startTest(test)

    def addSuccess(self, test):
        self.passes.append(test.id())
        super().addSuccess(test)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    actual_commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    if actual_commit != os.environ['SOURCE_COMMIT'] or subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all']):
        raise RuntimeError('exact clean published source required before importing operational definitions')
    historical = json.loads((HERE / 'EXPECTED-TESTS.json').read_bytes())
    current = json.loads((HERE / 'EXPECTED-TESTS-G9.json').read_bytes())
    r6 = json.loads((HERE / 'EXPECTED-TESTS-R6.json').read_bytes())
    if (type(historical) is not list or len(historical) != 106 or len(set(historical)) != 106
            or type(current) is not list or len(current) != 47 or len(set(current)) != 47
            or type(r6) is not list or len(r6) != 12 or len(set(r6)) != 12
            or set(historical) & set(current) or (set(historical) | set(current)) & set(r6)):
        raise RuntimeError('preserved original106/G9-47 and closed additive R6-12 rosters required')
    expected = historical + current + r6
    suite = unittest.defaultTestLoader.discover(str(HERE), pattern='test_*.py')
    actual = [test.id() for test in flatten(suite)]
    if collections.Counter(actual) != collections.Counter(expected):
        discovery_errors = list(unittest.defaultTestLoader.errors)
        (OUT / 'CENSUS-REFUSAL.PUBLIC.json').write_text(json.dumps({
            'expected': expected, 'actual': actual, 'success': False,
            'discovery_errors': discovery_errors}, indent=2) + '\n')
        for error in discovery_errors:
            print(error, file=sys.stderr, flush=True)
        raise RuntimeError('discovered tests differ from reviewed exact G6+G7+G8+G9+R6 roster')
    result = unittest.TextTestRunner(verbosity=2, resultclass=Outcomes).run(suite)
    success = (result.wasSuccessful() and not result.skipped and not result.expectedFailures
               and not result.unexpectedSuccesses and result.testsRun == len(expected)
               and collections.Counter(result.runs) == collections.Counter(expected)
               and collections.Counter(result.passes) == collections.Counter(expected))
    clean_source = (subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == actual_commit
                    and not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all']))
    success = success and clean_source
    value = {'schema': 'owned_network_guardian_g6_g7_g8_g9_r6_exact_CI_census_v1',
             'source_commit': os.environ['SOURCE_COMMIT'], 'success': success,
             'expected': expected, 'historical_expected': historical, 'g9_expected': current, 'r6_expected': r6,
             'historical_count': len(historical), 'g9_count': len(current), 'r6_count': len(r6),
             'executed': result.runs, 'passed': result.passes,
             'failures': [test.id() for test, _ in result.failures],
             'errors': [test.id() for test, _ in result.errors],
             'skipped': [test.id() for test, _ in result.skipped],
             'tests_run': result.testsRun, 'native_current_health': False,
             'exact_clean_source_before_and_after': clean_source,
             'production_authority': False, 'actual_host_cutover': False}
    (OUT / 'CENSUS.PUBLIC.json').write_text(json.dumps(value, indent=2) + '\n')
    print(json.dumps({key: value[key] for key in ('source_commit', 'success', 'tests_run',
                                               'native_current_health', 'production_authority')}))
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
