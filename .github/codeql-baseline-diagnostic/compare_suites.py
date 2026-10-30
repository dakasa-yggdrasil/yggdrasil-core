import json, pathlib, sys


def load(path):
    doc = json.loads(pathlib.Path(path).read_text())
    rules, findings = set(), set()
    for run in doc['runs']:
        for tool in [run['tool']['driver'], *run['tool'].get('extensions', [])]:
            rules.update(rule['id'] for rule in tool.get('rules', []))
        for result in run.get('results', []):
            location = result['locations'][0]['physicalLocation']
            findings.add((result['ruleId'], location['artifactLocation']['uri'], location['region']['startLine']))
    return rules, findings

base_rules, base_findings = load(sys.argv[1])
new_rules, new_findings = load(sys.argv[2])
base_id = 'go/weak-sensitive-data-hashing'
new_id = 'dakasa/go-secret-reference-hashing'
assert base_id in base_rules, ('missing_baseline_hash_query', base_rules)
assert new_id in new_rules, ('missing_configured_hash_query', new_rules)
assert base_id not in new_rules, 'old hash query unexpectedly remains in candidate'
missing = (base_rules - {base_id}) - new_rules
unexpected = (new_rules - {new_id}) - base_rules
assert not missing and not unexpected, ('query_set_difference', sorted(missing), sorted(unexpected))
assert {x for x in base_findings if x[0] != base_id} == {x for x in new_findings if x[0] != new_id}, 'non-hash findings changed'
print(f'PASS {len(base_rules)} baseline rules, {len(new_rules)} configured rules: one precise replacement; non-hash findings unchanged')
