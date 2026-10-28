"""Reviewed handoff-recovery primitives. No CLI, no production adapter or API calls.

A Linux adapter must hold both the handoff maintenance mutex and controller
mutex before snapshot, ensure the original owner/SSM transport is terminal, and
verify the caller-supplied state from the real system. Network/kernel continuity,
Guardian requalification, and actual systemd process supervision remain
separate obligations. These functions never assert those obligations passed.
"""
import hashlib,json,os,re,stat
from pathlib import Path

class Held(RuntimeError): pass

def need(value, guard):
 if not value: raise Held(guard)

def digest(raw): return hashlib.sha256(raw).hexdigest()


def decide(snapshot, expected, require_controller_lock=True):
 """Decide only after a fresh locked snapshot and original owner closure.

 The adapter must derive snapshot from native calls, not from user input. A
 queued/unknown START never causes another START; an independently observed dead
 controller after terminal owner closure may receive a distinct corrective START.
 """
 need(type(snapshot) is dict and type(expected) is dict,'TYPED_SNAPSHOT')
 for k in ('owner_terminal','maintenance_lock_owned','unit_hashes_exact','runtime_hashes_exact','boot_identity_exact','hub_and_cold_unchanged','core_healthy','config_is_regular_single_link','nft_structure_exact'):
  need(snapshot.get(k) is True,'REQUIRED_'+k.upper())
 need(expected.get('old_config_sha256') != expected.get('new_config_sha256'),'DISTINCT_REVIEWED_CONFIGS')
 cfg=snapshot.get('config_sha256')
 need(cfg in (expected.get('old_config_sha256'),expected.get('new_config_sha256')),'CONFIG_NOT_IN_REVIEWED_PAIR')
 need(snapshot.get('guardian_state') in ('inactive','active'),'UNKNOWN_GUARDIAN_STATE')
 state=snapshot.get('controller_state')
 need(state in ('running','inactive','failed','activating'),'UNKNOWN_CONTROLLER_STATE')
 if state=='running':
  need(snapshot.get('controller_identity_verified') is True,'RUNNING_IDENTITY_NOT_QUALIFIED')
  return {'action':'observe_running_controller','config_sha256':cfg,'start_requested':False,'restore_old_config':False,'guardian_requalification_needed':True}
 if state=='activating' or snapshot.get('controller_start_job_pending') is True:
  return {'action':'observe_pending_start','config_sha256':cfg,'start_requested':False,'restore_old_config':False,'guardian_requalification_needed':True}
 need(not require_controller_lock or snapshot.get('controller_lock_owned') is True,'CONTROLLER_LOCK_NOT_HELD_FOR_CONFIG_CAS')
 need(snapshot.get('controller_pid_absent') is True and snapshot.get('controller_cgroup_empty') is True,'DEAD_CONTROLLER_NOT_PHYSICALLY_JOINED')
 need(snapshot.get('controller_start_job_pending') is False,'UNKNOWN_START_JOB')
 need(snapshot.get('guardian_state')=='inactive' and snapshot.get('guardian_cgroup_empty') is True,'GUARDIAN_MUST_BE_STOPPED_AND_JOINED')
 need(snapshot.get('check_once_old_config_success') is True,'OLD_CONFIG_CHECK_ONCE_REQUIRED')
 return {'action':'restore_old_if_needed_then_distinct_start','config_sha256':cfg,'start_requested':True,'restore_old_config':cfg==expected['new_config_sha256'],'guardian_requalification_needed':True}


def read_regular(path, expected_uid):
 flags=os.O_RDONLY|os.O_NOFOLLOW|getattr(os,'O_CLOEXEC',0)
 fd=os.open(path,flags)
 try:
  a=os.fstat(fd)
  need(stat.S_ISREG(a.st_mode) and a.st_uid==expected_uid and a.st_nlink==1 and stat.S_IMODE(a.st_mode)==0o600,'CONFIG_FILE_SAFETY')
  chunks=[];size=0
  while True:
   b=os.read(fd,65536)
   if not b: break
   size+=len(b);need(size<=32768,'CONFIG_TOO_LARGE');chunks.append(b)
  z=os.fstat(fd)
  need((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns),'CONFIG_CHANGED_DURING_READ')
  return b''.join(chunks), (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)
 finally:os.close(fd)


def restore_old_config(path, old_bytes, expected_current_sha, expected_old_sha, expected_uid):
 """File CAS under both externally held locks. Never call without stopped unit.

 External mutators must honor those locks. Rechecks inode+bytes immediately
 before atomic replace; foreign writers that ignore the lock require separate
 control and cannot be excluded by POSIX rename alone.
 """
 path=Path(path);need(path.is_absolute(),'ABSOLUTE_CONFIG_PATH');need(type(old_bytes) is bytes and len(old_bytes)>0 and digest(old_bytes)==expected_old_sha,'OLD_BYTES_HASH')
 current,identity=read_regular(path,expected_uid);need(digest(current)==expected_current_sha,'EXPECTED_CURRENT_CONFIG_SHA')
 if current==old_bytes:return {'changed':False,'after_sha256':expected_old_sha}
 tmp=path.parent/('.'+path.name+'.recovery-'+os.urandom(12).hex())
 fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,'wb') as f:f.write(old_bytes);f.flush();os.fsync(f.fileno())
  again,identity2=read_regular(path,expected_uid)
  need(identity2==identity and digest(again)==expected_current_sha,'CONFIG_CAS_CHANGED')
  os.replace(tmp,path)
  directory=os.open(path.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
  try:os.fsync(directory)
  finally:os.close(directory)
  after,_=read_regular(path,expected_uid);need(after==old_bytes,'CONFIG_POST_REPLACE_MISMATCH')
  return {'changed':True,'after_sha256':digest(after)}
 finally:
  try:tmp.unlink()
  except FileNotFoundError:pass


def recover_with_backend(backend, expected, old_bytes):
 """Orchestrate once with a separately reviewed concrete Linux backend.

 Keep maintenance lock throughout. Hold controller lock for stopped-state
 checks and any configuration CAS, then release it *before* START because
 the actual controller acquires it for its entire lifetime. A fresh post-unlock
 snapshot must still show stopped/no job before one distinct START. Noncooperative
 actors that ignore the maintenance mutex are outside this serialization.
 The durable possible-send marker precedes release/START. Unknown outcomes
 are not retried. No bundled backend talks to production.
 """
 need(digest(old_bytes)==expected.get('old_config_sha256'),'OLD_BYTES_NOT_EXACT')
 with backend.maintenance_lock():
  initial=backend.snapshot()
  need(initial.get('previous_recovery_start_terminal') is True,'PREVIOUS_RECOVERY_START_UNRESOLVED')
  if initial.get('controller_state') in ('running','activating') or initial.get('controller_start_job_pending') is True:
   plan=decide(initial,expected)
   return {'action':plan['action'],'start_attempted':False,'restore_performed':False,'guardian_requalification_needed':plan['guardian_requalification_needed']}
  with backend.controller_lock():
   snap=backend.snapshot()
   need(snap.get('previous_recovery_start_terminal') is True,'PREVIOUS_RECOVERY_START_UNRESOLVED')
   plan=decide(snap,expected)
   if not plan['start_requested']:
    return {'action':plan['action'],'start_attempted':False,'restore_performed':False,'guardian_requalification_needed':plan['guardian_requalification_needed']}
   backend.verify_reviewed_old_config(old_bytes,expected)
   restored=False
   if plan['restore_old_config']:
    receipt=backend.restore(old_bytes,expected['new_config_sha256'],expected['old_config_sha256'])
    need(receipt.get('after_sha256')==expected['old_config_sha256'],'RESTORE_RECEIPT_MISMATCH');restored=receipt.get('changed') is True
   fresh=backend.snapshot()
   need(fresh.get('previous_recovery_start_terminal') is True,'PREVIOUS_RECOVERY_START_UNRESOLVED')
   next_plan=decide(fresh,expected)
   need(next_plan['start_requested'] is True and next_plan['restore_old_config'] is False and next_plan['config_sha256']==expected['old_config_sha256'],'STATE_CHANGED_BEFORE_START')
   marker=backend.claim_start_once(expected)
   need(type(marker) is dict and set(marker)=={'schema','run_id','path','sha256','exclusive_create','file_fsync','directory_fsync','readback_verified'} and marker.get('schema')=='handoff_recovery_possible_start_marker_v1' and re.fullmatch('[0-9a-f]{20}',str(marker.get('run_id'))) is not None and type(marker.get('path')) is str and marker['path'].startswith('/') and re.fullmatch('[0-9a-f]{64}',str(marker.get('sha256'))) is not None and all(marker.get(k) is True for k in ('exclusive_create','file_fsync','directory_fsync','readback_verified')),'DURABLE_POSSIBLE_START_MARKER_REQUIRED')
   marker_bytes=backend.readback_marker(marker)
   need(type(marker_bytes) is bytes and 0<len(marker_bytes)<=4096 and digest(marker_bytes)==marker['sha256'],'POSSIBLE_START_MARKER_READBACK_SHA')
   try:marker_value=json.loads(marker_bytes)
   except (ValueError,UnicodeDecodeError):raise Held('POSSIBLE_START_MARKER_JSON')
   need(marker_value=={'schema':'handoff_recovery_possible_start_intent_v1','run_id':marker['run_id'],'old_config_sha256':expected['old_config_sha256'],'new_config_sha256':expected['new_config_sha256']},'POSSIBLE_START_MARKER_CONTENT')
  # controller.lock must now be released; the new controller itself needs it.
  after_unlock=backend.snapshot()
  need(after_unlock.get('controller_lock_owned') is False and after_unlock.get('maintenance_lock_owned') is True,'WRONG_LOCK_STATE_AT_START')
  need(after_unlock.get('previous_recovery_start_terminal') is True,'PREVIOUS_RECOVERY_START_UNRESOLVED')
  post_plan=decide(after_unlock,expected,require_controller_lock=False)
  need(post_plan['start_requested'] is True and post_plan['restore_old_config'] is False and post_plan['config_sha256']==expected['old_config_sha256'],'STATE_CHANGED_AFTER_CONTROLLER_UNLOCK')
  custody=backend.start_once()
  need(type(custody) is dict and custody.get('exit_code')==0 and custody.get('captured_output_truncated') is False and all(custody.get(k) is True for k in ('native_started','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined')),'START_OUTCOME_NOT_CLOSED_ZERO')
  observation=backend.observe_started()
  need(type(observation) is dict and observation.get('new_controller_identity_verified') is True and observation.get('same_47_native_handles') is True,'STARTED_CONTROLLER_OR_STRUCTURE_NOT_VERIFIED')
  return {'action':'distinct_start_closed','start_attempted':True,'restore_performed':restored,'guardian_requalification_needed':True,'possible_start_marker':marker,'start_custody':custody,'observation':observation,'no_gap_inferred':False}
