"""Bind recovery marker namespace to an original isolated handoff, source-only.

The source-pinned caller must load genuine closed SSM diagnostics and exact
original remote files; this pure join does not authenticate fabricated inputs,
inspect marker absence, or authorize any service action.
"""
import hashlib,json,re
from pathlib import PurePosixPath
ROOT=PurePosixPath('/opt/dakasa/capacity-network')
class Held(Exception):pass
def need(v,g):
 if not v:raise Held(g)
def bind(*,lease_bytes,lease_original_ref,scope_bytes,scope_original_ref,baseline_bytes,baseline_original_ref,handoff_marker_bytes,handoff_marker_original_ref,terminal_scope,ssm_original,expected_source_sha256,expected_admission_sha256):
 need(all(type(v)is bytes and len(v)<=32768 for v in (lease_bytes,scope_bytes,baseline_bytes,handoff_marker_bytes)),'BOUNDED_ORIGINAL_RECORDS');lease=json.loads(lease_bytes);scope=json.loads(scope_bytes);baseline=json.loads(baseline_bytes);handoff_marker=json.loads(handoff_marker_bytes);run=lease['run_id'];need(re.fullmatch('[a-f0-9]{20}',str(run)) is not None,'EXACT_HANDOFF_RUN')
 folder=ROOT/('Core263-pair-handoff-'+run)
 for ref,raw,name in ((lease_original_ref,lease_bytes,'OWNER-LEASE.PUBLIC.json'),(scope_original_ref,scope_bytes,'HANDOFF-SCOPE.PUBLIC.json'),(baseline_original_ref,baseline_bytes,'RECOVERY-BASELINE.PUBLIC.json')):
  need(type(ref)is dict and set(ref)=={'path','sha256'}and ref['path']==str(folder/name) and ref['sha256']==hashlib.sha256(raw).hexdigest(),'EXACT_ORIGINAL_HANDOFF_RECORD')
 unit='dakasa-network-handoff-'+run+'.service';need(lease['schema']=='handoff_isolated_owner_lease_v1' and lease['source_sha256']==expected_source_sha256 and lease['unit']==unit and lease['cgroup']=='/system.slice/'+unit and type(lease['pid'])is int and lease['pid']>1 and type(lease['start_ticks'])is int and lease['start_ticks']>0,'EXACT_ORIGINAL_OWNER_LEASE')
 need(re.fullmatch('[a-f0-9]{64}',str(expected_source_sha256)) and re.fullmatch('[a-f0-9]{64}',str(expected_admission_sha256)),'EXACT_REVIEWED_SOURCE_AND_ADMISSION_HASHES')
 need(scope['schema']=='Root_Core263_original_pair_handoff_scope_v1' and scope['source_sha256']==expected_source_sha256 and scope['admission_sha256']==expected_admission_sha256 and re.fullmatch('[a-f0-9]{64}',str(scope['old_controller_config_sha256'])) and re.fullmatch('[a-f0-9]{64}',str(scope['new_controller_config_sha256'])) and scope['old_controller_config_sha256']!=scope['new_controller_config_sha256'],'EXACT_ORIGINAL_REVIEWED_SCOPE')
 need(type(handoff_marker_original_ref)is dict and handoff_marker_original_ref=={'path':str(ROOT/'ROOT-ONE-CORE263-TWO-PAIR-HANDOFF'),'sha256':hashlib.sha256(handoff_marker_bytes).hexdigest()},'EXACT_ORIGINAL_HANDOFF_ONE_SHOT_MARKER')
 need(handoff_marker=={'source_sha256':expected_source_sha256,'run_id':run,'recovery_baseline_ref':baseline_original_ref,'isolated_owner_lease_ref':lease_original_ref,'unknown_or_failed_original_replay_permitted':False},'ORIGINAL_HANDOFF_MARKER_BINDS_BASELINE_AND_LEASE')
 need(baseline.get('schema')=='Root_Core263_preSTOP_recovery_baseline_v1'and baseline.get('run_id')==run and baseline.get('source_sha256')==expected_source_sha256 and baseline.get('boot_id')==lease.get('boot_id') and baseline.get('old_config_sha256')==scope['old_controller_config_sha256']and baseline.get('new_config_sha256')==scope['new_controller_config_sha256']and baseline.get('current_core_or_handoff_completion_not_inferred') is True,'EXACT_PRESTOP_BASELINE_SCOPE')
 need(terminal_scope.get('schema')=='handoff_owner_scope_terminal_check_v1' and terminal_scope.get('run_id')==run and terminal_scope.get('unit')==unit and terminal_scope.get('owner_lease_sha256')==lease_original_ref['sha256'] and terminal_scope.get('boot_id')==lease.get('boot_id') and terminal_scope.get('same_boot') is True and terminal_scope.get('owner_and_cgroup_empty') is True and terminal_scope.get('no_pending_systemd_jobs') is True and terminal_scope.get('terminal_ssm_distinct') is True,'SAME_TERMINAL_OWNER_SCOPE')
 expected_ssm={k:ssm_original.get(k)for k in ('command_id','instance_id','request_sha256')};need(ssm_original.get('schema')=='verified_ssm_terminal_transport_only_v1' and terminal_scope.get('ssm_original')==expected_ssm and ssm_original.get('terminal_does_not_prove_remote_process_or_job_absent') is True,'SAME_TERMINAL_SSM_CUSTODY')
 return {'schema':'bound_handoff_recovery_marker_namespace_v1','handoff_run_id':run,'marker_directory':str(folder),'lease_original_ref':lease_original_ref,'scope_original_ref':scope_original_ref,'recovery_baseline':baseline,'recovery_baseline_original_ref':baseline_original_ref,'terminal_ssm_command_id':expected_ssm['command_id'],'old_config_sha256':scope['old_controller_config_sha256'],'new_config_sha256':scope['new_controller_config_sha256'],'marker_absence_or_recovery_authorized':False}
