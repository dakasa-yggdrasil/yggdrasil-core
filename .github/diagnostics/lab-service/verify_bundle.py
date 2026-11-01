"""CI-only validation of generated identity and sealed source boundaries."""
import importlib.util,json,os,sys
from pathlib import Path
root=Path(sys.argv[1]).resolve();spec=importlib.util.spec_from_file_location('lab_entry_test',root/'entrypoint.py')
entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(entry)
good={'accountId':'153828470928','region':'us-east-1','instanceId':'i-0cb486ae31a45d15e'}
entry.validate_identity(good,entry.SPEC['boot_id'])
cs=importlib.util.spec_from_file_location('lab_cleanup_test',root/'cleanup.py')
cleanup=importlib.util.module_from_spec(cs);cs.loader.exec_module(cleanup)
cleanup.validate_identity(good,entry.SPEC['boot_id'])
try:cleanup.validate_identity(dict(good,region='sa-east-1'),entry.SPEC['boot_id']);raise AssertionError('cleanup wrong region accepted')
except cleanup.Held:pass
for wrong in (dict(good,accountId='000000000000'),dict(good,region='sa-east-1'),dict(good,instanceId='i-00000000000000000')):
    try:entry.validate_identity(wrong,entry.SPEC['boot_id']);raise AssertionError('wrong LAB identity accepted')
    except entry.Held:pass
try:entry.validate_identity(good,'00000000-0000-0000-0000-000000000000');raise AssertionError('wrong boot accepted')
except entry.Held:pass
source=entry.verify_source(root)
target=source/'runtime'/'nft_owner.py';original=target.read_bytes()
try:
    target.write_bytes(original+b'\n# altered\n')
    try:entry.verify_source(root);raise AssertionError('altered source accepted')
    except entry.Held:pass
finally:target.write_bytes(original)
extra=source/'runtime'/'unexpected.py';extra.write_text('# extra\n')
try:
    try:entry.verify_source(root);raise AssertionError('extra source accepted')
    except entry.Held:pass
finally:extra.unlink()
entry.verify_source(root)
summary=json.loads((root/'bundle-summary.json').read_bytes());unit=(root/summary['unit']).read_text()
assert 'Type=exec' in unit and 'RuntimeDirectoryMode=0700' in unit
assert 'ExecStopPost=/usr/bin/python3 -B '+summary['install_path']+'/cleanup.py' in unit
import hashlib,re
assert re.fullmatch('[0-9a-f]{12}',summary['nonce'])
assert hashlib.sha256((root/'cleanup.py').read_bytes()).hexdigest()==entry.SPEC['cleanup_sha256']==summary['cleanup_sha256']
assert hashlib.sha256(unit.encode()).hexdigest()==entry.SPEC['unit_sha256']==summary['unit_sha256']
assert summary['production_authority'] is False and summary['operational_controller'] is False
print('PASS sealed LAB identity, exact boot, source tampering and extra-file negatives; cleanup unit shape')
