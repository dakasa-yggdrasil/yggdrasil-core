import json, pathlib, sys

def findings(path):
    doc = json.loads(pathlib.Path(path).read_text())
    out = set()
    for run in doc['runs']:
        for r in run.get('results', []):
            loc = r['locations'][0]['physicalLocation']
            out.add((r['ruleId'], loc['artifactLocation']['uri'], loc['region']['startLine']))
    return out

published, local = map(findings, sys.argv[1:])
assert published == local, ('main_go_findings_differ', sorted(published-local), sorted(local-published))
print(f'PASS all {len(published)} existing published main Go findings match local baseline')
