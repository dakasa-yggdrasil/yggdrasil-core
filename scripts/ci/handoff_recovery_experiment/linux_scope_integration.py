"""Disposable Ubuntu systemd/cgroup integration; never touches production."""
import base64,hashlib,json,os,secrets,subprocess,tempfile,time
from pathlib import Path
import owner_scope as scope
import scope_collector
import frozen_native
assert os.geteuid()==0
run_id=secrets.token_hex(10);unit=scope.unit_for(run_id)
with tempfile.TemporaryDirectory(prefix='scope-integration-') as tmp:
 d=Path(tmp);os.chmod(d,0o700);out=d/'out';out.mkdir(mode=0o700);diags=d/'diagnostics';diags.mkdir(mode=0o700)
 source=d/'fixture_owner.py'
 # The owner receives its script hash as an argument to avoid a self-hashing file.
 source.write_text("import sys\nsys.path.insert(0,"+repr(str(Path(__file__).resolve().parent))+")\nimport owner_scope\nowner_scope.persist_self_lease(run_id="+repr(run_id)+",source_path=__file__,source_sha256=sys.argv[1],output_directory="+repr(str(out))+")\n");os.chmod(source,0o600)
 digest=hashlib.sha256(source.read_bytes()).hexdigest()
 try:
  subprocess.run(['/usr/bin/systemd-run','--unit='+unit,'--wait','--property=Type=oneshot','--property=KillMode=control-group','--property=Delegate=no','--property=Restart=no','/usr/bin/python3','-B',str(source),digest],check=True,timeout=30,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  lease=json.loads((out/'OWNER-LEASE.PUBLIC.json').read_bytes());assert lease['source_sha256']==digest
  # Synthetic SSM is deliberately not evidence of AWS or Brain execution.
  expected={'command_id':'fixture','instance_id':'fixture','request_sha256':'fixture'};ssm={'schema':'verified_ssm_terminal_transport_only_v1','terminal_does_not_prove_remote_process_or_job_absent':True,**expected}
  for attempt in range(20):
   attempt_dir=diags/str(attempt);attempt_dir.mkdir(mode=0o700)
   try:
    got=scope_collector.collect(lease=lease,expected_ssm=expected,ssm_terminal=ssm,native=frozen_native.native,diagnostic_directory=attempt_dir)
    break
   except scope.Held as e:
    if str(e)!='NO_PENDING_SYSTEMD_JOBS' or attempt==19:
     row=json.loads((attempt_dir/'JOBS-ORIGINAL-IO.PRIVATE.json').read_bytes());print('LAST_JOBS_OUTPUT',base64.b64decode(row['stdout_base64']).decode(),flush=True);raise
    time.sleep(1)
  assert got['result']['owner_and_cgroup_empty'] is True
  print(json.dumps({'actual_linux_systemd_scope_and_native_io':True,'ssm_fixture_only':True,'production_authority':False}))
 finally:
  subprocess.run(['/usr/bin/systemctl','reset-failed',unit],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
