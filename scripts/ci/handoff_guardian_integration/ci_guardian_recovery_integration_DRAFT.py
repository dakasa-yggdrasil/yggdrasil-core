"""Disposable hosted CI VM only; no AWS, production, LAB, or guest serial.

Uses two uniquely named systemd services, actual shared flocks and native
systemctl invocation. The inspector's Core, nft, scope, boot and SSM claims are
synthetic; this is not full recovery, takeover, traffic, or current15 proof.
Requires an isolated runner because daemon-reload is global to its manager.
"""
import hashlib,json,os,secrets,subprocess,tempfile,time
from pathlib import Path
import bound_recovery_driver as driver,linux_guardian_backend as gb,frozen_native
DRAFT_ONLY=False
def need(v,r):
 if not v:raise RuntimeError(r)
def call(args):return subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=20).stdout
def properties(unit):
 raw=call(['/usr/bin/systemctl','show',unit,'--property=ActiveState,SubState,MainPID,InvocationID']);rows=[x.split('=',1) for x in raw.decode().splitlines()];need(len(rows)==4 and len(dict(rows))==4,'EXACT_PROPERTIES');return dict(rows)
def main():
 need(not DRAFT_ONLY and os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted','ONLY_DISPOSABLE_GITHUB_HOSTED_CI')
 run=secrets.token_hex(10);handoff=secrets.token_hex(10);controller='codex-fixture-controller-'+run+'.service';guardian='codex-fixture-guardian-'+run+'.service';files=[Path('/run/systemd/system')/controller,Path('/run/systemd/system')/guardian]
 need(all(not os.path.lexists(x) for x in files),'OWN_UNIT_NAMES_ABSENT')
 with tempfile.TemporaryDirectory(prefix='guardian-recovery-ci-') as tmp:
  root=Path(tmp);os.chmod(root,0o700);folder=root/('Core263-pair-handoff-'+handoff);folder.mkdir(mode=0o700);locks=root/'locks';locks.mkdir(mode=0o700);ml=locks/'maintenance.lock';cl=locks/'controller.lock';gl=locks/'guardian.lock';config=root/'config';ready=root/'guardian.ready'
  for p,raw in ((ml,b''),(cl,b''),(gl,b''),(config,b'old')):p.write_bytes(raw);os.chmod(p,0o600)
  worker=root/'worker.py';worker.write_text("import fcntl,os,sys,time\nfd=os.open(sys.argv[1],os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\nif len(sys.argv)>2: open(sys.argv[2],'x').close()\ntime.sleep(90)\n");os.chmod(worker,0o600)
  for path,lock,extra in ((files[0],cl,''),(files[1],gl,' '+str(ready))):
   body='[Unit]\nDescription=Disposable isolated CI recovery fixture\n[Service]\nType=simple\nExecStart=/usr/bin/python3 -B '+str(worker)+' '+str(lock)+extra+'\nRestart=no\nKillMode=control-group\nRuntimeMaxSec=90s\n'
   fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
   with os.fdopen(fd,'w')as f:f.write(body);f.flush();os.fsync(f.fileno())
  class Inspector:
   def __init__(self):
    self.lease={'run_id':handoff};self.old=config;self.expected={'old_config_sha256':hashlib.sha256(b'old').hexdigest(),'new_config_sha256':hashlib.sha256(b'new').hexdigest()};self.g=type('G',(),{'read':staticmethod(lambda p,*_:Path(p).read_bytes())})();self.last_binding={'schema':'bound_handoff_recovery_marker_namespace_v1','marker_directory':str(folder),'marker_absence_or_recovery_authorized':False}
   def identity(self):
    v=properties(controller);need(v['ActiveState']=='active' and v['SubState']=='running' and int(v['MainPID'])>1,'ACTUAL_CONTROLLER_RUNNING');pid=int(v['MainPID']);raw=Path('/proc/'+str(pid)+'/stat').read_text();return {'pid':pid,'invocation_id':v['InvocationID'],'start_ticks':int(raw[raw.rfind(')')+1:].split()[19])}
   def snapshot(self):
    c=properties(controller);g=properties(guardian);return {'owner_terminal':True,'previous_recovery_start_terminal':False,'unit_hashes_exact':True,'runtime_hashes_exact':True,'boot_identity_exact':True,'hub_and_cold_unchanged':True,'core_healthy':True,'config_is_regular_single_link':True,'nft_structure_exact':True,'config_sha256':hashlib.sha256(config.read_bytes()).hexdigest(),'guardian_state':'inactive' if g['ActiveState']=='inactive' else 'active','guardian_cgroup_empty':g['ActiveState']=='inactive','controller_state':'running' if c['ActiveState']=='active' else 'inactive','controller_identity_verified':c['ActiveState']=='active','controller_start_job_pending':False}
   def observe_existing_controller(self):return {'existing_controller_identity_verified':True,'start_attribution_not_inferred':True,'same_47_native_handles':True,'all_four_observed_positive':True,'controller_identity':self.identity()}
   def snapshot_guardian(self):
    i=self.identity();g=properties(guardian);return {'owner_terminal':True,'previous_guardian_start_terminal':False,'controller_identity_verified':True,'controller_identity':i,'controller_config_is_reviewed_old':config.read_bytes()==b'old','core_healthy':True,'same_47_handles':True,'all_four_backends_positive':True,'hub_and_cold_unchanged':True,'unit_hashes_exact':True,'runtime_hashes_exact':True,'boot_identity_exact':True,'guardian_state':g['ActiveState'],'guardian_cgroup_empty':g['ActiveState']=='inactive','prior_guardian_identity_absent':True,'no_pending_jobs':True}
   def observe_guardian(self):
    end=time.monotonic()+10
    while time.monotonic()<end:
     g=properties(guardian)
     if g['ActiveState']=='active' and g['SubState']=='running' and ready.exists():return {'distinct_guardian_lifetime':True,'same_controller_identity':self.identity(),'fixture_guardian_pid':int(g['MainPID'])}
     time.sleep(.1)
    raise TimeoutError('GUARDIAN_NOT_READY')
  i=Inspector();oldroot=driver.BRAIN_ROOT;oldbuild=driver.build_controller;oldguard=driver.build_guardian;oldflag=driver.COMBINED_RECOVERY_ENABLED;oldstart=gb.START;oldunit=gb.GUARDIAN
  try:
   call(['/usr/bin/systemctl','daemon-reload']);call(['/usr/bin/systemctl','start',controller]);need(properties(guardian)['ActiveState']=='inactive','GUARDIAN_INITIAL_INACTIVE')
   driver.BRAIN_ROOT=root;driver.COMBINED_RECOVERY_ENABLED=True;gb.GUARDIAN=guardian;gb.START=['/usr/bin/systemctl','start',guardian]
   driver.build_controller=lambda **kw:driver.BoundLinuxBackend(maintenance_path=ml,controller_path=cl,config_path=config,marker_directory=folder,run_id=run,inspector=i,native=frozen_native.native,expected_uid=0)
   driver.build_guardian=lambda **kw:driver.BoundGuardianBackend(maintenance_path=ml,guardian_path=gl,marker_directory=folder,run_id=run,inspector=i,native=frozen_native.native,expected_uid=0)
   ref=driver.execute_controller_then_guardian(inspector=i,native=frozen_native.native,run_id=run);record=json.loads(Path(ref['path']).read_bytes());need(hashlib.sha256(Path(ref['path']).read_bytes()).hexdigest()==ref['sha256'] and record['result']['guardian_start_attempted'] is True and ready.exists(),'REAL_GUARDIAN_START_AND_DURABLE_RETURN')
   need(record['own_current15_not_inferred'] is True and record['no_gap_not_inferred'] is True,'NO_FABRICATED_QUALIFICATION')
  finally:
   driver.BRAIN_ROOT=oldroot;driver.build_controller=oldbuild;driver.build_guardian=oldguard;driver.COMBINED_RECOVERY_ENABLED=oldflag;gb.START=oldstart;gb.GUARDIAN=oldunit
   failures=[]
   for unit in (guardian,controller):
    try:
     call(['/usr/bin/systemctl','stop',unit]);v=properties(unit);need(v['ActiveState']=='inactive' and v['SubState']=='dead' and v['MainPID']=='0','OWN_UNIT_STOPPED')
     cg=Path('/sys/fs/cgroup/system.slice')/unit/'cgroup.events'
     if cg.exists():need(dict(x.split() for x in cg.read_text().splitlines()).get('populated')=='0','OWN_CGROUP_EMPTY')
    except BaseException as error:failures.append(type(error).__name__)
   if not failures:
    try:
     jobs=call(['/usr/bin/systemctl','list-jobs','--no-pager','--no-legend']);need(all(u.encode() not in jobs for u in (guardian,controller)),'NO_OWN_PENDING_JOBS')
     for path in files:path.unlink()
     call(['/usr/bin/systemctl','daemon-reload'])
     for unit in (guardian,controller):
      raw=call(['/usr/bin/systemctl','show',unit,'--property=LoadState,ActiveState,SubState,MainPID']);rows=[x.split('=',1) for x in raw.decode().splitlines()];need(len(rows)==4 and len(dict(rows))==4 and dict(rows).get('LoadState')=='not-found' and dict(rows).get('MainPID')=='0','OWN_UNIT_REMOVED')
    except BaseException as error:failures.append(type(error).__name__)
   need(not failures,'OWN_CLEANUP_FAILED_'+','.join(failures))
  print(json.dumps({'actual_controller_guardian_units':True,'actual_guardian_start_and_flocks':True,'own_units_terminal_and_removed':True,'scope_nft_core_ssm_synthetic':True,'production_authority':False}),flush=True)
if __name__=='__main__':main()
