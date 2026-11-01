"""Real systemd regression: parent SIGKILL runs slice cleanup for auxiliary units."""
import os,select,subprocess,time,uuid
from pathlib import Path
uid=uuid.uuid4().hex[:12];slice_name='dakasa-elastic-lab-'+uid+'.slice'
parent='ci-lab-parent-'+uid+'.service';children=['ci-lab-child-a-'+uid+'.service','ci-lab-child-b-'+uid+'.service']
unit_file=Path('/run/systemd/system')/parent;fds=[]
def run(*args,check=True):return subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=check,timeout=10)
def props(unit):
 out=run('/usr/bin/systemctl','show',unit,'--property=MainPID,ControlGroup,ActiveState').stdout
 return dict(line.split('=',1) for line in out.splitlines())
try:
 unit_file.write_text('[Service]\nType=exec\nExecStart=/usr/bin/sleep 120\nExecStopPost=/usr/bin/systemctl stop '+slice_name+'\n')
 run('/usr/bin/systemctl','daemon-reload');run('/usr/bin/systemctl','start',parent)
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
 run('/usr/bin/systemctl','kill','--kill-whom=main','--signal=KILL',parent)
 for fd in fds:
  poll=select.poll();poll.register(fd,select.POLLIN);assert poll.poll(10000),'AUXILIARY_SURVIVED_PARENT_DEATH'
 print('PASS parent SIGKILL triggers systemd ExecStopPost and terminates both auxiliary slice processes')
finally:
 for fd in fds:os.close(fd)
 run('/usr/bin/systemctl','stop',parent,check=False)
 run('/usr/bin/systemctl','stop',slice_name,check=False)
 unit_file.unlink(missing_ok=True);run('/usr/bin/systemctl','daemon-reload',check=False)
