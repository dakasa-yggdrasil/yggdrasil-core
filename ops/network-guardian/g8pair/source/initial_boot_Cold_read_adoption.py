"""Initial-boot Cold read-adoption; no restoration or service operation.

Root must bind this Source before any native use. Later-boot path is separate.
"""
import base64,hashlib,json,os,time
from pathlib import Path

def read_adopt(owner,g,owning_invocation_started):
 R=g.require;started=owning_invocation_started;work=started+165
 R(owner.boot==g.INITIAL_BOOT and 0<=started<=time.monotonic()<work,'ONLY_ORIGINAL_INITIAL_BOOT_WITHIN_TOTAL_COLD165_UNIT180')
 owner.deadline=work;R(not owner.insert_remaining and owner.start_admitted is False,'READ_ADOPTION_HAS_NO_KERNEL_INSERT_OR_SERVICE_START_CAPABILITY');seal=owner.static();own=owner.properties(g.COLD)
 R(own['MainPID']==own['ExecMainPID']==str(os.getpid())and own['ActiveState']=='activating'and own['SubState']=='start'and own['InvocationID']==os.environ.get('INVOCATION_ID')and own['ControlGroup']=='/system.slice/'+g.COLD and g.read('/proc/self/cgroup',4096)==('0::/system.slice/'+g.COLD+'\n').encode(),'GENUINE_NEW_COLD_ONESHOT_INVOCATION')
 # The exact earlier failed Cold invocation is retained from the already
 # owning-qualified rescue originals; it is never relabeled current/zero.
 wrapper=g.loads(owner.proof_original(owner.Core262_context['network_R43_execution_proofs']['recipe_ref']));aliases={row['original_ref']['path']:row for row in wrapper['public_ref_relocations']}
 def original(ref):
  row=aliases.get(ref['path'])
  if row is not None:R(row['original_ref']==ref and row['local_ref']['sha256']==ref['sha256'],'SAME_GENUINE_PUBLIC_RESCUE_ALIAS');return owner.proof_original(row['local_ref'])
  return owner.proof_original(ref)
 reader=g.loads(owner.proof_original(owner.Core262_context['network_R43_return_ref']));rescue=g.loads(original(reader['rescue_original_return_ref']));rows=[]
 for ref in rescue['native_original_call_refs']:
  value=g.loads(original(ref))
  if value['role']=='properties-'+g.COLD:rows.append((ref,value))
 R(len(rows)==1,'ONE_GENUINE_OLD_COLD_FAILURE_ORIGINAL');oldref,oldrow=rows[0];f=oldrow['original_transport'];R(type(f.get('exit_code'))is int and f['exit_code']==0 and f.get('captured_output_truncated')is False and all(f.get(k)is True for k in('native_started','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined')),'ORIGINAL_READ_OF_OLD_COLD_CLOSED_ZERO_NOT_OLD_COLD_SUCCESS');raw=base64.b64decode(oldrow['stdout_base64'],validate=True);R(g.sha(raw)==oldrow['stdout_sha256'],'WHOLE_ORIGINAL_FAILED_COLD_PROPERTIES');old=dict(v.split('=',1)for v in raw.decode().splitlines());R(old['MainPID']=='0'and old['ActiveState']=='failed'and old['ExecMainPID']=='301128'and old['ExecMainStatus']=='1'and old['InvocationID']!=own['InvocationID']and not Path('/proc/301128').exists(),'OLD301128_FAILED_CLOSED_RETAINED_DISTINCT_FROM_THIS_INVOCATION')
 identity=owner.identity();R(identity['pid']==314992 and identity['start_ticks']==504987939 and identity['InvocationID']=='173115bbae9f44c6b9b91015d4b4d31f'and identity['cmdline_sha256']=='cabb48bd17d533081ea6e896da00279ff5c58cec330064a4e62561025598ad32','SAME_INITIAL_BOOT_RESCUED_CONTROLLER_R0');hub=owner.properties(g.HUB);R(hub['MainPID']=='0'and hub['ActiveState']=='active'and hub['SubState']=='exited'and hub['ExecMainPID']=='811760'and hub['InvocationID']=='8af2cbd73dc8410da4f173845b90efe3','SAME_ORIGINAL_HUB_NO_START')
 def core_current():
  core=owner.Core262_context;want=core['same_native_identity'];k=['/usr/local/bin/k3s','kubectl','--kubeconfig=/etc/rancher/k3s/k3s.yaml','--request-timeout=3s','-n','dakasa']
  def read_private(role,argv):
   R(time.monotonic()+6<work,'SAME_ORIGINAL_COLD_READ_BUDGET');body,f=owner.n.native(argv,deadline=min(work-1,time.monotonic()+6),env=owner.B.SAFE,cap=8<<20,custody={},diagnostic_path=None);R(type(f.get('exit_code'))is int and f['exit_code']==0 and f.get('captured_output_truncated')is False and all(f.get(a)is True for a in('native_started','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined')),'ORIGINAL_PRIVATE_CORE_READ_CLOSED_ZERO');owner.calls.append({'schema':'Root_initial_Cold_private_Core_read_metadata_v1','role':role,'argv':argv,'original_transport':{a:f[a]for a in('pid','exit_code','native_started','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined','captured_output_truncated')if a in f},'private_body_discarded':True,'stdout_sha256':None,'stdout_bytes':None});return body
  deployment=json.loads(read_private('Core-deployment',k+['get','deployment','yggdrasil','-o','json']));pods=json.loads(read_private('Core-pods',k+['get','pods','-l','app=yggdrasil','-o','json']));R(deployment['metadata']['uid']=='a58ab8c2-da48-46c1-ae62-a650141eeb86'and deployment['metadata']['generation']==262 and len(pods['items'])==1,'FRESH_ACTUAL_CORE262_ONE_PRIMARY');pod=pods['items'][0];statuses=pod['status']['containerStatuses'];R(len(statuses)==1 and statuses[0]['name']=='core','EXACT_ONE_CORE_CONTAINER');status=statuses[0];native={'pod_name':pod['metadata']['name'],'pod_uid':pod['metadata']['uid'],'container_id':status['containerID'],'image_id':status['imageID'],'restart_count':status['restartCount'],'started_at':status['state']['running']['startedAt']};R(native==want and status['ready']is True and status['restartCount']==0,'FRESH_SAME_CORE262_NATIVE_R0')
  for endpoint in('healthz','readyz'):
   raw=read_private('Core-'+endpoint,k+['get','--raw','/api/v1/namespaces/dakasa/pods/'+want['pod_name']+':9080/proxy/'+endpoint])
   if endpoint=='healthz':R(raw.strip()==b'ok','FRESH_CORE_HEALTH')
   else:v=json.loads(raw);R(v.get('status')=='ready'and v.get('rabbitmq_status')=='ok','FRESH_CORE_AND_BROKER_READY')
  return native
 before=core_current();after=[]
 def bracket_Core_after():after.append(core_current())
 observed,prefix,suffix,public_reads=g.reader.observe(owner,g,before_kernel=bracket_Core_after);finished=time.monotonic();R(len(after)==1 and before==after[0]and observed['identity']==identity and owner.identity()==identity and owner.properties(g.HUB)==hub and finished<work and finished<observed['measurement']['current_continuous_window']['guaranteed_until'],'SAME_CORE_CONTROLLER_HUB_AND_ORIGINAL_CURRENT15_READ_SCOPE')
 key=owner.boot+'-INITIAL-COLD-READ-ADOPTION-'+own['InvocationID'];current_ref=g.reader.persist(owner,g,observed,prefix,suffix,public_reads,key+'-CURRENT15');path=g.LEDGER/(key+'-RETURN.PUBLIC.json');value={'schema':'Root_initial_boot_Cold_distinct_original_read_adoption_return_v1','source_sha256':owner.sha,'boot_id':owner.boot,'own_COLD_properties':own,'old_failed_Cold_original_ref':oldref,'old_failed_Cold_properties':old,'old_Cold301128_failed_reclassified':False,'controller_identity_before_after':[identity,identity],'Hub_properties_before_after':[hub,hub],'Core262_native_before_after':[before,after[0]],'WG_public_shape':observed['WG_public_shape'],'transport':observed['transport'],'measurement':observed['measurement'],'kernel':observed['kernel'],'kernel_observed':observed['kernel_observed'],'current15_original_return_ref':current_ref,'original_native_read_calls':owner.calls,'started_monotonic':started,'original_work_deadline':work,'finished_monotonic':finished,'insert_count':0,'kernel_service_Controller_Hub_or_Core_mutations':0,'cold_kernel_restoration_or_new120_qualified':False,'original_current15_read_adoption_only':True};g.once(path,g.wire(value));return value,{'path':str(path),'sha256':g.sha(g.wire(value))}
