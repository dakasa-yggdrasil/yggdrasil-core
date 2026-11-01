"""Disposable systemd test of generated cleanup; IMDS identity is simulated."""
import importlib.util,json,os,select,subprocess,sys,time,uuid
from pathlib import Path
bundle=Path(sys.argv[1]).resolve();mode=sys.argv[2]
assert mode in ('clean','foreign')
summary=json.loads((bundle/'bundle-summary.json').read_bytes());nonce=summary['nonce'];slice_name=summary['slice'];parent=summary['unit']
unit_file=Path('/run/systemd/system')/parent
holder='ci-rotation-holder-'+nonce+'-'+uuid.uuid4().hex+'.service';holder_file=Path('/run/systemd/system')/holder
children=['ci-guarded-precommit-'+nonce+'-'+uuid.uuid4().hex+'.service']
if mode=='foreign':children.append('ci-foreign-'+nonce+'.service')
else:children.append('ci-rotation-holder-'+nonce+'-'+uuid.uuid4().hex+'.service')
wrapper=bundle/'ci_cleanup_wrapper.py';fds=[];reservation=None

def run(*args,check=True):return subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=check,timeout=30)
def props(unit):
 out=run('/usr/bin/systemctl','show',unit,'--property=MainPID,ControlGroup,ActiveState,InvocationID').stdout
 return dict(line.split('=',1) for line in out.splitlines())
def terminal(fd):
 poll=select.poll();poll.register(fd,select.POLLIN);return bool(poll.poll(0))
try:
 # Tests the generated cleanup code and real systemd lifecycle. Only the
 # EC2 identity lookup is simulated on this non-AWS ephemeral runner.
 wrapper.write_text('import importlib.util\ns=importlib.util.spec_from_file_location("generated_cleanup",'+repr(str(bundle/'cleanup.py'))+')\nm=importlib.util.module_from_spec(s);s.loader.exec_module(m)\nm.imds_identity=lambda:{"accountId":"153828470928","region":"us-east-1","instanceId":"i-0cb486ae31a45d15e"}\nm.validate_identity=lambda document,boot: None\nm.main()\n')
 unit_file.write_text('[Service]\nType=exec\nExecStart=/usr/bin/sleep 120\nExecStopPost=/usr/bin/python3 -B '+str(wrapper)+'\n')
 runtime='/run/dakasa-elastic-lab-'+nonce+'/source'
 run('/usr/bin/systemctl','daemon-reload');run('/usr/bin/systemctl','start',parent)
 es=importlib.util.spec_from_file_location('lab_entry_preflight',bundle/'entrypoint.py')
 entry=importlib.util.module_from_spec(es);es.loader.exec_module(entry)
 entry.validate_empty_slice()
 holder_file.write_text('[Service]\nType=simple\nSlice='+slice_name+'\nRuntimeMaxSec=20s\nExecStart=/usr/bin/nsenter --net=/proc/123/ns/net /usr/bin/python3 -B '+runtime+'/runtime/ci_holder_process.py '+runtime+'/guardian47.sock '+runtime+'/holder-go '+runtime+'/holder-acquired '+runtime+'/holder-revoked\n')
 run('/usr/bin/systemctl','daemon-reload')
 inv=props(parent)['InvocationID'];assert len(inv)==32
 directory=Path('/var/lib/dakasa-elastic-lab-rehearsal-runs');directory.mkdir(mode=0o700,exist_ok=True)
 reservation=directory/nonce
 fd=os.open(reservation,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  os.write(fd,(json.dumps({'unit':parent,'boot_id':summary['boot_id'],'invocation_id':inv},sort_keys=True)+'\n').encode());os.fsync(fd)
 finally:os.close(fd)
 run('/usr/bin/systemctl','show',holder)
 for child in children:
  run('/usr/bin/systemd-run','--quiet','--no-block','--unit='+child,'--slice='+slice_name,'/usr/bin/sleep','120')
  deadline=time.monotonic()+5
  while True:
   state=props(child)
   if state['ActiveState']=='active' and int(state['MainPID'])>1:break
   if time.monotonic()>deadline:raise RuntimeError('CHILD_NOT_ACTIVE')
   time.sleep(.02)
  assert slice_name in state['ControlGroup'].split('/')
  fds.append(os.pidfd_open(int(state['MainPID'])))
 try:entry.validate_empty_slice();raise AssertionError('occupied slice accepted')
 except entry.Held:pass
 run('/usr/bin/systemctl','kill','--kill-whom=main','--signal=KILL',parent)
 deadline=time.monotonic()+30
 while props(parent)['ActiveState'] not in ('failed','inactive'):
  if time.monotonic()>deadline:raise RuntimeError('PARENT_CLEANUP_TIMEOUT')
  time.sleep(.05)
 log=run('/usr/bin/journalctl','-u',parent,'--no-pager','-n','50').stdout
 if mode=='clean':
  for fd in fds:assert terminal(fd),'AUXILIARY_SURVIVED_PARENT_DEATH'
  assert not holder_file.exists() and 'LAB_AUXILIARY_CLEANUP_CONFIRMED' in log,log
  print('PASS actual generated cleanup after SIGKILL, exact auxiliary identities and orphan holder unit')
 else:
  assert all(not terminal(fd) for fd in fds),'FOREIGN_UNIT_WAS_TERMINATED'
  assert holder_file.exists() and 'FOREIGN_UNIT_IN_LAB_SLICE' in log,log
  print('PASS generated cleanup refuses foreign unit and leaves all slice tasks untouched')
finally:
 for fd in fds:os.close(fd)
 for child in children:run('/usr/bin/systemctl','stop',child,check=False)
 run('/usr/bin/systemctl','stop',parent,check=False)
 run('/usr/bin/systemctl','stop',slice_name,check=False)
 unit_file.unlink(missing_ok=True);holder_file.unlink(missing_ok=True)
 if reservation is not None:reservation.unlink(missing_ok=True)
 wrapper.unlink(missing_ok=True);run('/usr/bin/systemctl','daemon-reload',check=False)
