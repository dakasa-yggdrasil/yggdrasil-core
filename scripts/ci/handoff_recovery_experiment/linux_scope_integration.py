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
 source.write_text("import sys\nsys.path.insert(0,"+repr(str(Path(__file__).resolve().parent))+")\nimport owner_scope\nowner_scope.persist_self_lease(run_id="+repr(run_id)+",source_path=__file__,source_sha256=sys.argv[1],output_directory="+repr(str(out))+")\nprint('LEASE_WRITTEN', flush=True)\n");os.chmod(source,0o600)
 digest=hashlib.sha256(source.read_bytes()).hexdigest()
 try:
  call=subprocess.run(['/usr/bin/systemd-run','--unit='+unit,'--wait','--pipe','--property=Type=oneshot','--property=KillMode=control-group','--property=Delegate=no','--property=Restart=no','/usr/bin/python3','-B',str(source),digest],check=True,timeout=30,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  assert b'LEASE_WRITTEN' in call.stdout
  lease=json.loads((out/'OWNER-LEASE.PUBLIC.json').read_bytes());assert lease['source_sha256']==digest
  # Synthetic SSM is deliberately not evidence of AWS or Brain execution.
  command_id='12345678-1234-1234-1234-123456789abc';instance_id='i-0123456789abcdef0';req={'DocumentName':'AWS-RunShellScript','InstanceIds':[instance_id],'Parameters':{'commands':['fixture'],'executionTimeout':['285']}};request_bytes=json.dumps(req).encode()
  t={'exit_code':0,'captured_output_truncated':False,**{k:True for k in ('native_started','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined')}}
  def diagnostic(value):
   b=json.dumps(value).encode();return {'schema':'private_original_baker_SSH_diagnostic_v1','original_local_transport':t,'stdout_base64':base64.b64encode(b).decode(),'stdout_sha256':hashlib.sha256(b).hexdigest(),'stdout_bytes':len(b)}
  send={'Command':{**req,'CommandId':command_id}};get={'CommandId':command_id,'InstanceId':instance_id,'DocumentName':'AWS-RunShellScript','Status':'Success','ResponseCode':0}
  evidence={'request_bytes':request_bytes,'send_diagnostic':diagnostic(send),'get_diagnostic':diagnostic(get),'command_id':command_id,'instance_id':instance_id,'expected_request_sha256':hashlib.sha256(request_bytes).hexdigest()}
  attempt_dir=diags/'0';attempt_dir.mkdir(mode=0o700)
  try:
   got=scope_collector.collect(lease=lease,ssm_evidence=evidence,native=frozen_native.native,diagnostic_directory=attempt_dir)
   assert got['result']['owner_and_cgroup_empty'] is True
   outcome='terminal_scope_observed'
  except scope.Held as e:
   if str(e)!='NO_PENDING_SYSTEMD_JOBS':raise
   # Some GitHub VM images retain unrelated Azure disk jobs. Preserve the
   # strict HOLD and verify the actual collected output rather than cancelling.
   job=json.loads((attempt_dir/'JOBS-ORIGINAL-IO.PRIVATE.json').read_bytes());assert base64.b64decode(job['stdout_base64']).strip()
   unit_io=json.loads((attempt_dir/'UNIT-ORIGINAL-IO.PRIVATE.json').read_bytes());unit_output=base64.b64decode(unit_io['stdout_base64']).decode();assert 'MainPID=0' in unit_output and ('ActiveState=inactive' in unit_output or 'ActiveState=failed' in unit_output)
   owner=scope_collector.fs_read('/proc/'+str(lease['pid'])+'/stat');assert owner['status']=='absent' or (owner['status']=='ok' and scope.start_ticks(owner['content'])!=lease['start_ticks'])
   outcome='held_for_real_pending_jobs'
  print(json.dumps({'actual_linux_systemd_owner_lease_and_native_io':True,'result':outcome,'ssm_fixture_only':True,'production_authority':False}))

 finally:
  subprocess.run(['/usr/bin/systemctl','reset-failed',unit],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
