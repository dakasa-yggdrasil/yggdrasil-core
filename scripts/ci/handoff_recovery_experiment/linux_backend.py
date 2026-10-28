"""Linux handoff recovery primitives, draft without a production entry point.

The inspector and SSM-custody verifier are deliberately not supplied here.
They must derive each snapshot from the production host and authentic terminal
SSM receipt, bind the exact original run and check all process trees and jobs.
Do not use an unverified caller-provided snapshot to authorize production.
"""
import contextlib,fcntl,hashlib,json,os,stat,time
from pathlib import Path
import recovery_core as core

UNIT='dakasa-capacity-network.service'
START=['/usr/bin/systemctl','--job-mode=ignore-dependencies','start',UNIT]
class LinuxBackend:
 def __init__(self,*,maintenance_path,controller_path,config_path,marker_directory,run_id,inspector,native,expected_uid=0):
  core.need(os.name=='posix' and len(run_id)==20 and all(c in '0123456789abcdef' for c in run_id),'LINUX_SCOPE_RUN_ID')
  self.maintenance_path=Path(maintenance_path);self.controller_path=Path(controller_path);self.config_path=Path(config_path);self.marker_directory=Path(marker_directory)
  core.need(all(p.is_absolute() for p in (self.maintenance_path,self.controller_path,self.config_path,self.marker_directory)),'ABSOLUTE_LINUX_PATHS')
  self.run_id=run_id;self.inspector=inspector;self.native=native;self.expected_uid=expected_uid;self.holding_maintenance=False;self.holding_controller=False;self._own_marker_claimed=False;self._own_marker=None;self._start_called=False
 def _open_lock(self,path):
  d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   ds=os.fstat(d);core.need(ds.st_uid==self.expected_uid and not stat.S_IMODE(ds.st_mode)&0o022,'SAFE_LOCK_DIRECTORY')
   fd=os.open(path.name,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=d)
   try:
    s=os.fstat(fd);core.need(stat.S_ISREG(s.st_mode) and s.st_uid==self.expected_uid and s.st_nlink==1 and not stat.S_IMODE(s.st_mode)&0o022,'SAFE_LOCK_FILE');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    fresh=os.stat(path.name,dir_fd=d,follow_symlinks=False);core.need(stat.S_ISREG(fresh.st_mode) and (fresh.st_dev,fresh.st_ino)==(s.st_dev,s.st_ino),'LOCK_NAME_STILL_SAME_INODE');return fd
   except BaseException:os.close(fd);raise
  finally:os.close(d)
 @contextlib.contextmanager
 def maintenance_lock(self):
  core.need(not self.holding_maintenance and not self.holding_controller,'NONREENTRANT_MAINTENANCE_LOCK');fd=self._open_lock(self.maintenance_path);self.holding_maintenance=True
  try:yield
  finally:self.holding_maintenance=False;os.close(fd)
 @contextlib.contextmanager
 def controller_lock(self):
  core.need(self.holding_maintenance and not self.holding_controller,'LOCK_ORDER');fd=self._open_lock(self.controller_path);self.holding_controller=True
  try:yield
  finally:self.holding_controller=False;os.close(fd)
 def snapshot(self):
  core.need(self.holding_maintenance,'MAINTENANCE_LOCK_REQUIRED');core.need(self._own_marker_claimed or not os.path.lexists(self.marker_directory/'ROOT-ONE-RECOVERY-POSSIBLE-START.PUBLIC.json'),'PREVIOUS_POSSIBLE_RECOVERY_START_REQUIRES_SEPARATE_RECONCILIATION');v=self.inspector.snapshot()
  core.need(type(v)is dict and 'maintenance_lock_owned' not in v and 'controller_lock_owned' not in v,'INSPECTOR_MUST_NOT_ASSERT_LOCKS')
  return {**v,'maintenance_lock_owned':self.holding_maintenance,'controller_lock_owned':self.holding_controller}
 def verify_reviewed_old_config(self,old_bytes,expected):
  core.need(self.holding_maintenance and self.holding_controller,'BOTH_LOCKS_REQUIRED');core.need(self.inspector.check_once(old_bytes,expected) is True,'ORIGINAL_CLOSED_CHECK_ONCE_REQUIRED')
 def restore(self,old_bytes,current_sha,old_sha):
  core.need(self.holding_maintenance and self.holding_controller,'BOTH_LOCKS_REQUIRED');return core.restore_old_config(self.config_path,old_bytes,current_sha,old_sha,self.expected_uid)
 def claim_start_once(self,expected):
  core.need(self.holding_maintenance and self.holding_controller,'BOTH_LOCKS_REQUIRED');d=os.open(self.marker_directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   ds=os.fstat(d);core.need(ds.st_uid==self.expected_uid and not stat.S_IMODE(ds.st_mode)&0o077,'PRIVATE_MARKER_DIRECTORY')
   name='ROOT-ONE-RECOVERY-POSSIBLE-START.PUBLIC.json';data=(json.dumps({'schema':'handoff_recovery_possible_start_intent_v1','run_id':self.run_id,'old_config_sha256':expected['old_config_sha256'],'new_config_sha256':expected['new_config_sha256']},sort_keys=True,separators=(',',':'))+'\n').encode()
   fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=d)
   with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
   os.fsync(d)
   marker={'schema':'handoff_recovery_possible_start_marker_v1','run_id':self.run_id,'path':str(self.marker_directory/name),'sha256':hashlib.sha256(data).hexdigest(),'exclusive_create':True,'file_fsync':True,'directory_fsync':True,'readback_verified':False}
   core.need(self.readback_marker(marker)==data,'MARKER_READBACK');marker['readback_verified']=True;self._own_marker_claimed=True;self._own_marker=dict(marker);return marker
  finally:os.close(d)
 def readback_marker(self,marker):
  path=Path(marker['path']);core.need(path==self.marker_directory/'ROOT-ONE-RECOVERY-POSSIBLE-START.PUBLIC.json','EXACT_MARKER_PATH');raw,_=core.read_regular(path,self.expected_uid);return raw
 def start_once(self):
  core.need(self.holding_maintenance and not self.holding_controller,'MAINTENANCE_HELD_CONTROLLER_RELEASED')
  core.need(not self._start_called,'RECOVERY_START_NEVER_REPEATED');core.need(self._own_marker_claimed and self._own_marker is not None,'ORIGINAL_DURABLE_MARKER_REQUIRED');raw=self.readback_marker(self._own_marker);core.need(hashlib.sha256(raw).hexdigest()==self._own_marker['sha256'],'ORIGINAL_MARKER_IMMEDIATELY_BEFORE_START')
  # ignore-dependencies is limited to this exact unit: hub/cold are separately
  # revalidated active and unchanged by the inspector, so no dependency restarts.
  self._start_called=True
  started=time.monotonic();_,facts=self.native(START,deadline=started+20,stdin=b'',env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C'},cap=1<<20,diagnostic_path=getattr(self,'start_diagnostic',None))
  return {**facts,'argv':list(START),'started_monotonic':started,'finished_monotonic':time.monotonic()}
 def observe_started(self):return self.inspector.observe_started()
