"""Re-derive a Guardian invocation's own first 15-second historical observation.

Pure verifier; caller supplies independently source-pinned tail/coverage/journal
modules and authentic whole original references. This is historical evidence,
not a fresh-now route guarantee or a new original120 qualification.
"""
import math,re
class Held(Exception):pass
def need(v,g):
 if not v:raise Held(g)
def closed(t):
 need(type(t)is dict and type(t.get('exit_code'))is int and t['exit_code']==0 and t.get('captured_output_truncated') is False and all(t.get(k)is True for k in ('native_started','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined')),'ORIGINAL_CLOSED_ZERO_GUARDIAN_READ')
def qualify(*,p,ref,boot_id,guardian_invocation,guardian_source_sha256,authority_sha256,controller_identity,guardian_start_original,tail,coverage,journal):
 need(re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',boot_id) is not None and re.fullmatch('[a-f0-9]{32}',guardian_invocation) is not None,'EXACT_BOOT_AND_GUARDIAN_INVOCATION')
 root='/var/lib/dakasa-capacity-network-recovery/'+boot_id+'-GUARDIAN-'+guardian_invocation+'-FIRST-CURRENT15';need(ref['path']==root+'-RETURN.PUBLIC.json','OWN_GUARDIAN_INVOCATION_FIRST_RETURN')
 raw=p.raw(ref);need(p.sha(raw)==ref['sha256'],'WHOLE_ORIGINAL_GUARDIAN_RETURN');v=p.loads(raw);need(v['schema']=='Root_owning_finite512_current15_readonly_observation_v1' and v['source_sha256']==guardian_source_sha256 and v['standing_config_sha256']==authority_sha256 and v['identity']==controller_identity,'SAME_GUARDIAN_SOURCE_AUTHORITY_AND_CONTROLLER')
 need(type(guardian_start_original)is dict and guardian_start_original.get('argv')==['/usr/bin/systemctl','start','dakasa-capacity-network-guardian.service'],'EXACT_ORIGINAL_GUARDIAN_START_ARGV');closed(guardian_start_original);start=guardian_start_original['started_monotonic'];finished=guardian_start_original['finished_monotonic'];need(type(start)in(int,float) and math.isfinite(start) and type(finished)in(int,float) and math.isfinite(finished) and start<=finished,'EXACT_ORIGINAL_START_CLOCKS')
 rows=v['original_public_read_output_refs'];calls=v['original_native_calls'];need(type(rows)is list and 1<=len(rows)<=128 and sum(row['bytes']for row in rows)<=32<<20,'FINITE_OWN_GUARDIAN_ORIGINAL_READS');bodies={}
 for row in rows:
  i=row['original_call_index'];need(type(i)is int and 0<=i<len(calls),'ORIGINAL_GUARDIAN_READ_INDEX');r=row['output_ref'];need(r['path'].startswith(root+'-READ-') and r['sha256']==row['sha256'],'ONLY_GUARDIAN_INVOCATION_READ_FAMILY');body=p.raw(r);call=calls[i];closed(call['original_transport']);need(call['role']==row['role'] and call['argv']==row['argv'] and call['stdout_sha256']==row['sha256']==p.sha(body) and call['stdout_bytes']==row['bytes']==len(body),'EXACT_GUARDIAN_ORIGINAL_NATIVE_OUTPUT');bodies.setdefault(row['role'],[]).append(body)
 roles=('current15-exact-finite512-tail','current15-one-after-cursor-closing','native-dynamic-expiries');need(all(len(bodies.get(role,[]))==1 for role in roles),'ONE_EXACT_OWN_TAIL_SUFFIX_AND_KERNEL');prefix,suffix,kernel=(bodies[role][0] for role in roles);need(p.raw(v['prefix_ref'])==prefix and p.raw(v['suffix_ref'])==suffix,'EXACT_ORIGINAL_PREFIX_AND_SUFFIX_REFS')
 measured=tail.measure(prefix,suffix,controller_identity,boot_id,v['prefix_observed_monotonic'],v['finished_monotonic'],coverage,journal);actual_kernel=coverage.kernel_text(kernel);need(measured==v['measurement'] and measured['qualified_15_seconds'] is True and actual_kernel==v['kernel'] and actual_kernel['all_four_backends_and_reverse_sources_positive'] is True,'REDERIVED_GUARDIAN_FIRST15_AND_FOUR_BACKENDS')
 current=measured['current_continuous_window'];need(current['start']<=v['kernel_observed']<=current['observed_until']<=v['finished_monotonic']<current['guaranteed_until'],'ORIGINAL_KERNEL_SAMPLE_WITHIN_OWN_CURRENT_WINDOW')
 need(type(v['finished_monotonic'])in(int,float) and math.isfinite(v['finished_monotonic']) and start<=v['prefix_observed_monotonic']<=v['finished_monotonic'] and finished<=v['finished_monotonic'],'OWN_FIRST15_FINISHED_AFTER_ORIGINAL_START')
 return {'schema':'verified_guardian_own_first15_historical_v1','guardian_invocation':guardian_invocation,'controller_identity':controller_identity,'return_ref':ref,'first15_rederived':True,'historical_only':True,'fresh_current15_or_original120_inferred':False}
