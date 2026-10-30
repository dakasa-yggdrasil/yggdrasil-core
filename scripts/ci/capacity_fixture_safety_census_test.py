import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('census', Path(__file__).with_name('capacity_fixture_safety_census.py'))
census = importlib.util.module_from_spec(spec)
spec.loader.exec_module(census)


class CensusTests(unittest.TestCase):
    def test_required_events_reject_missing_skip_duplicate_and_failure(self):
        required = {'one', 'two'}
        good = [{'name': n, 'action': a} for n in sorted(required) for a in ('run', 'pass')]
        census.require_events(good, required)
        for bad in (good[:-2], good + [{'name': 'one', 'action': 'skip'}], good + good[:2], good + [{'name': 'other', 'action': 'fail'}]):
            with self.subTest(events=bad):
                with self.assertRaises(ValueError):
                    census.require_events(bad, required)

    def test_go_census_requires_package_pass_and_parent_death_test(self):
        package = 'github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacityfixturetest'
        events = [{'Package': package, 'Test': n, 'Action': a} for n in sorted(census.GO_REQUIRED) for a in ('run', 'pass')]
        events.append({'Package': package, 'Action': 'pass'})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.jsonl'
            def check(rows):
                path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
                census.check_go(path)
            check(events)
            for bad in (events[:-1], [e for e in events if e.get('Test') != 'TestOwnerReceivesSignalOnParentDeath'], events + [{'Package': package, 'Test': 'TestOwnerReceivesSignalOnParentDeath', 'Action': 'skip'}]):
                with self.assertRaises(ValueError):
                    check(bad)


if __name__ == '__main__':
    unittest.main()
