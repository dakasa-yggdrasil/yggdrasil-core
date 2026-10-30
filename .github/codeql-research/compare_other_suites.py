import json, pathlib, sys

def load(path):
    doc = json.loads(pathlib.Path(path).read_text())
    rules, findings = set(), set()
    for run in doc['runs']:
        for tool in [run['tool']['driver'], *run['tool'].get('extensions', [])]:
            rules.update(rule['id'] for rule in tool.get('rules', []))
        for result in run.get('results', []):
            loc = result['locations'][0]['physicalLocation']
            findings.add((result['ruleId'], loc['artifactLocation']['uri'], loc['region']['startLine']))
    return rules, findings

base_rules, base_findings = load(sys.argv[1])
new_rules, new_findings = load(sys.argv[2])
assert base_rules, 'baseline returned no rules'
assert base_rules == new_rules, ('different_rules', sorted(base_rules-new_rules), sorted(new_rules-base_rules))
assert base_findings == new_findings, ('different_findings', sorted(base_findings-new_findings), sorted(new_findings-base_findings))
assert all(not rule.startswith(('go/', 'dakasa-research/')) for rule in new_rules), 'unexpected Go rule'
print(f'PASS non-Go rules equal: {len(base_rules)}; findings equal: {len(base_findings)}')
