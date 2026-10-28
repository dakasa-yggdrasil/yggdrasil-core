#!/usr/bin/env python3
"""Run and require each Linux fixture-safety test; never treat a skip as pass."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
PYTHON_REQUIRED = {
    'capacity_pg17_owned_fixture_test.RunnerIsolationTest.' + name for name in (
        'test_explicit_postgres_major_matches_binary',
        'test_child_does_not_inherit_credentials_or_postgres_overrides',
        'test_signal_during_spawn_kills_and_joins_the_new_child',
        'test_exited_leader_with_child_holding_pipes_times_out',
        'test_uncertain_descendant_preserves_owner_directory',
        'test_real_sigterm_stops_owned_postgres_and_writes_cleanup_receipt',
        'test_nested_registry_socket_path_accepts_real_postgres',
        'test_parent_death_stops_real_owned_postgres_and_external_registry_confirms',
    )
} | {
    'capacity_fixture_owner_registry_test.RegistryCheck.' + name for name in (
        'test_closed_owner_and_receipt_pass',
        'test_live_owner_refuses_even_with_receipt',
        'test_missing_receipt_or_remaining_pg_preserves_evidence',
    )
} | {
    'capacity_fixture_source_equivalence_test.CompilerInputEquivalence.' + name for name in (
        'test_equal_checkout', 'test_untracked_ignored_test_is_detected',
        'test_embedded_file_change_is_detected',
    )
}
GO_REQUIRED = {
    'TestOwnerChild', 'TestTimeoutTerminatesAndJoinsOwner',
    'TestTimeoutPreservesUncertainOwner', 'TestExitWithoutCleanupReceiptIsUncertain',
    'TestParentDeathHelper', 'TestOwnerReceivesSignalOnParentDeath',
}


def require_events(events, required):
    for name in required:
        actions = [e['action'] for e in events if e.get('name') == name and e.get('action') in {'run', 'pass', 'skip', 'fail'}]
        if actions != ['run', 'pass']:
            raise ValueError('mandatory fixture safety test missing, duplicate, skipped or failed: ' + name)
    if any(e.get('action') in {'skip', 'fail'} for e in events):
        raise ValueError('fixture safety suite had a skip or failure')


class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.events = []

    def startTest(self, test):
        self.events.append({'name': test.id(), 'action': 'run'})
        super().startTest(test)

    def addSuccess(self, test):
        self.events.append({'name': test.id(), 'action': 'pass'})
        super().addSuccess(test)

    def addSkip(self, test, reason):
        self.events.append({'name': test.id(), 'action': 'skip'})
        super().addSkip(test, reason)

    def addFailure(self, test, err):
        self.events.append({'name': test.id(), 'action': 'fail'})
        super().addFailure(test, err)

    def addError(self, test, err):
        self.events.append({'name': test.id(), 'action': 'fail'})
        super().addError(test, err)


def run_python():
    suite = unittest.TestSuite()
    for name in ('capacity_pg17_owned_fixture_test', 'capacity_fixture_owner_registry_test', 'capacity_fixture_source_equivalence_test'):
        spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
    result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
    if not result.wasSuccessful():
        raise ValueError('Python fixture safety tests failed')
    require_events(result.events, PYTHON_REQUIRED)
    print(json.dumps({'schema': 'capacity_fixture_python_safety_census_v1', 'required': len(PYTHON_REQUIRED), 'status': 'pass'}))


def check_go(path):
    events = [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
    expected_package = 'github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacityfixturetest'
    if any(event.get('Package') != expected_package for event in events if event.get('Package')):
        raise ValueError('unexpected Go package in fixture safety events')
    require_events([{'name': e.get('Test'), 'action': e.get('Action')} for e in events], GO_REQUIRED)
    if sum(e.get('Action') == 'pass' and not e.get('Test') for e in events) != 1:
        raise ValueError('fixture safety package pass absent or duplicate')
    print(json.dumps({'schema': 'capacity_fixture_go_safety_census_v1', 'required': len(GO_REQUIRED), 'status': 'pass'}))


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--python', action='store_true')
    group.add_argument('--go-events')
    args = parser.parse_args()
    try:
        if args.python:
            run_python()
        else:
            check_go(args.go_events)
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        print('fixture safety census failed: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
