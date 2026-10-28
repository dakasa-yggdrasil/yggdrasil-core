"""Read-only Linux collector for a future isolated owner scope.

No CLI and no production authority: caller must source-pin this module and native,
verify the exact lease and SSM diagnostics, and hold the maintenance mutex. Captured
facts are snapshots; the one-shot owner launch must not be replayable.
"""
import errno,hashlib,json,os,time
from pathlib import Path
import owner_scope as contract
import ssm_terminal_custody
class Held(Exception):pass
def fs_read(path):
 fd=None;data=bytearray();failure=None
 try:
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  while True:
   b=os.read(fd,4096)
   if not b:break
   data.extend(b)
   if len(data)>65536:raise Held('BOUNDED_FS_READ')
 except OSError as e:failure=e.errno
 finally:
  if fd is not None:os.close(fd)
 if failure is not None:
  return {'path':path,'fd_closed':True,'status':'absent' if failure==errno.ENOENT else 'error','errno':failure,'content':None}
 return {'path':path,'fd_closed':True,'status':'ok','errno':None,'content':bytes(data).decode('ascii')}
def command(argv,native,diagnostic):
 raw,facts=native(argv,deadline=time.monotonic()+8,stdin=b'',env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C'},cap=1<<20,diagnostic_path=diagnostic)
 diagnostic_record=json.loads(Path(diagnostic).read_bytes());return {'argv':argv,'stdout':raw.decode('utf-8'),'stdout_sha256':hashlib.sha256(raw).hexdigest(),'transport':facts,'original_diagnostic':diagnostic_record}
def collect(*,lease,ssm_evidence,native,diagnostic_directory,kind='handoff'):
 ssm_terminal=ssm_terminal_custody.qualify(**ssm_evidence);expected_ssm={k:ssm_terminal[k] for k in ('command_id','instance_id','request_sha256')}
 unit=contract.unit_for(lease['run_id'],kind);contract.need(lease.get('cgroup')=='/system.slice/'+unit and type(lease.get('pid'))is int and lease['pid']>1,'EXACT_LEASE_PATHS_BEFORE_READ');d=Path(diagnostic_directory);contract.need(d.is_absolute(),'ABSOLUTE_PRIVATE_DIAGNOSTIC_DIRECTORY')
 unit_read=command(['/usr/bin/systemctl','show',unit,'--property=Id,ActiveState,MainPID,ControlGroup,KillMode,Delegate,Restart'],native,d/'UNIT-ORIGINAL-IO.PRIVATE.json')
 jobs=command(['/usr/bin/systemctl','list-jobs','--no-pager','--no-legend'],native,d/'JOBS-ORIGINAL-IO.PRIVATE.json')
 boot=fs_read('/proc/sys/kernel/random/boot_id');cg=fs_read('/sys/fs/cgroup'+lease['cgroup']+'/cgroup.events');pid=fs_read('/proc/'+str(lease['pid'])+'/stat')
 result=contract.validate_terminal(lease=lease,boot_read=boot,unit_read=unit_read,cgroup_read=cg,pid_read=pid,jobs_read=jobs,ssm_terminal=ssm_terminal,expected_ssm=expected_ssm,kind=kind)
 return {'result':result,'unit_original':unit_read,'jobs_original':jobs,'boot_read':boot,'cgroup_read':cg,'pid_read':pid}
