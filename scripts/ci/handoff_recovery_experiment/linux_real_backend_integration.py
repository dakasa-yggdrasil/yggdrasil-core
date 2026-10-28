"""Disposable Linux controller service, locks and config CAS integration.

Only the native systemd START, file CAS and flock are real; all network, Core,
Guardian, source and SSM qualifications are explicitly synthetic fixtures.
"""
import hashlib,os,subprocess,tempfile,time
from pathlib import Path
import recovery_core,bound_recovery_driver,frozen_native
assert os.geteuid()==0
service=Path('/run/systemd/system/dakasa-capacity-network.service')
assert not os.path.lexists(service),'DO_NOT_REPLACE_EXISTING_UNIT'
sha=lambda b:hashlib.sha256(b).hexdigest()
with tempfile.TemporaryDirectory(prefix='recovery-integration-') as tmp:
 d=Path(tmp);os.chmod(d,0o700);ml=d/'maintenance.lock';cl=d/'controller.lock';config=d/'config.json';ready=d/'ready'
 for p,data in ((ml,b''),(cl,b''),(config,b'new')):p.write_bytes(data);os.chmod(p,0o600)
 fixture=d/'controller.py';fixture.write_text("import fcntl,os,time\nfd=os.open("+repr(str(cl))+",os.O_RDWR|os.O_NOFOLLOW)\nfcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\nopen("+repr(str(ready))+",'w').write('ready')\ntime.sleep(30)\n");os.chmod(fixture,0o600)
 service.write_text('[Unit]\nDescription=Disposable CI recovery fixture\n[Service]\nType=simple\nExecStart=/usr/bin/python3 -B '+str(fixture)+'\nRestart=no\nKillMode=control-group\n');os.chmod(service,0o644)
 class Inspector:
  last_binding={'schema':'bound_handoff_recovery_marker_namespace_v1','marker_directory':str(d),'marker_absence_or_recovery_authorized':False}
  def check_once(self,old,expected):return sha(old)==expected['old_config_sha256']
  def snapshot(self):
   return {'owner_terminal':True,'previous_recovery_start_terminal':False,'unit_hashes_exact':True,'runtime_hashes_exact':True,'boot_identity_exact':True,'hub_and_cold_unchanged':True,'core_healthy':True,'config_is_regular_single_link':True,'nft_structure_exact':True,'config_sha256':sha(config.read_bytes()),'guardian_state':'inactive','controller_state':'inactive','controller_pid_absent':True,'controller_cgroup_empty':True,'controller_start_job_pending':False,'guardian_cgroup_empty':True,'check_once_old_config_success':True}
  def observe_started(self):
   deadline=time.monotonic()+10
   while time.monotonic()<deadline:
    if ready.exists():return {'new_controller_identity_verified':True,'same_47_native_handles':True}
    time.sleep(.1)
   raise TimeoutError('FIXTURE_CONTROLLER_FAILED_TO_ACQUIRE_LOCK')
 try:
  subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=True,timeout=10)
  backend=bound_recovery_driver.BoundLinuxBackend(maintenance_path=ml,controller_path=cl,config_path=config,marker_directory=d,run_id='a'*20,inspector=Inspector(),native=frozen_native.native,expected_uid=0)
  result=recovery_core.recover_with_backend(backend,{'old_config_sha256':sha(b'old'),'new_config_sha256':sha(b'new')},b'old')
  assert result['action']=='distinct_start_closed' and config.read_bytes()==b'old' and ready.read_text()=='ready'
  assert result['guardian_requalification_needed'] is True and result['no_gap_inferred'] is False
  print('{"actual_systemd_start_and_controller_flock":true,"actual_file_cas_and_marker":true,"scope_network_guardian_and_ssm_are_fixtures":true,"production_authority":false}',flush=True)
 finally:
  subprocess.run(['/usr/bin/systemctl','stop','dakasa-capacity-network.service'],check=False,timeout=10,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  try:service.unlink()
  except FileNotFoundError:pass
  subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=False,timeout=10,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
