import json, pathlib, sys

fixture = pathlib.Path('internal/controlplane/codeql_sandbox_probe.go')
markers = {line.split('// ',1)[1]: i for i,line in enumerate(fixture.read_text().splitlines(),1) if '// PROBE_' in line}

def findings(path):
    doc=json.loads(pathlib.Path(path).read_text())
    found={}
    for run in doc['runs']:
        for result in run.get('results',[]):
            loc=result['locations'][0]['physicalLocation']
            if loc['artifactLocation']['uri'].endswith('codeql_sandbox_probe.go'):
                line=loc['region']['startLine']
                found.setdefault(line, []).extend(result.get('codeFlows', []))
    return found

original, narrow=map(findings,sys.argv[1:])
for name in ('PROBE_DIRECT_PASSWORD','PROBE_RAW_REFERENCE','PROBE_SHARED'):
    assert markers[name] in original, ('baseline_missing',name,original.keys())
    assert markers[name] in narrow, ('narrow_missing',name,narrow.keys())
assert markers['PROBE_REFERENCE_NAME'] in original, ('baseline_missing_reference_name',original.keys())
assert markers['PROBE_REFERENCE_NAME'] not in narrow, ('narrow_still_reports_reference_name',narrow.keys())
print('PASS synthetic direct password, raw reference, shared sink retained; reference-name path removed')
