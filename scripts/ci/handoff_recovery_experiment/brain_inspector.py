"""Candidate Brain-native observer for the handoff recovery backend.

No entry point or production authority. Construction requires independently
validated handoff scope, original terminal SSM diagnostics, source-pinned native
and Guardian modules, and a 0600 staged old config. All observations are reads;
caller must hold maintenance lock and never replay unknown SSM/systemd effects.
"""
import hashlib,json,os,re,time
from pathlib import Path
import scope_collector
import owner_scope
class Held(Exception):pass
def need(v,g):
 if not v:raise Held(g)
def sha(b):return hashlib.sha256(b).hexdigest()
class BrainInspector:
 def __init__(self,*,guardian,base,bridge,coverage,native,expected,lease,ssm_evidence,old_config_path,diagnostic_root):
  self.g,self.base,self.bridge,self.coverage,self.native=guardian,base,bridge,coverage,native
  self.expected,self.lease,self.ssm_evidence=expected,lease,ssm_evidence;self.old=Path(old_config_path);self.out=Path(diagnostic_root);self.seq=0
  need(self.old.is_absolute() and self.out.is_absolute(),'ABSOLUTE_PRIVATE_PATHS')
  self.authority_raw=self.g.read(self.g.CONFIG,32768,0o600);self.authority=self.g.loads(self.authority_raw);self.g.validate(self.authority)
  need(sha(self.authority_raw)==expected['guardian_authority_sha256'] and sha(self.g.read(self.g.SELF,131072,0o600))==expected['guardian_source_sha256'],'EXACT_PREVIOUS_GUARDIAN_AUTHORITY_AND_SOURCE')
  need(sha(self.g.read(self.old,32768,0o600))==expected['old_config_sha256'],'EXACT_STAGED_OLD_CONFIG')
 def call(self,argv,timeout=10,cap=8<<20):
  self.seq+=1;raw,f=self.native(argv,deadline=time.monotonic()+timeout,stdin=b'',env=self.base.SAFE,cap=cap,diagnostic_path=self.out/('NATIVE-%05d.PRIVATE.json'%self.seq))
  need(type(f.get('exit_code')) is int and f['exit_code']==0 and f.get('captured_output_truncated') is False and all(f.get(k)is True for k in ('native_started','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined')),'ORIGINAL_NATIVE_READ_CLOSED_ZERO');return raw
 def properties(self,unit):
  raw=self.call(['/usr/bin/systemctl','show',unit,'--property='+self.g.PROPS]);rows=[line.split('=',1)for line in raw.decode('ascii').splitlines()];need(all(len(r)==2 for r in rows) and len(rows)==len(self.g.PROPS.split(',')) and len({r[0]for r in rows})==len(rows),'EXACT_UNIT_PROPERTIES');return dict(rows)
 def cgroup_empty(self,unit):
  row=scope_collector.fs_read('/sys/fs/cgroup/system.slice/'+unit+'/cgroup.events');need(row['status'] in ('ok','absent') and (row['status']!='absent' or row['errno']==2),'KNOWN_CGROUP_READ')
  if row['status']=='absent':return True
  vals=dict(line.split()for line in row['content'].splitlines());return vals.get('populated')=='0'
 def static(self):
  g=self.g;need(g.read(g.CONFIG,32768,0o600)==self.authority_raw,'UNCHANGED_GUARDIAN_AUTHORITY')
  for unit,key in ((g.UNIT,'controller_unit_sha256'),(g.GUARDIAN,'guardian_unit_sha256'),(g.HUB,'hub_unit_sha256'),(g.COLD,'cold_unit_sha256')):need(sha(g.read('/etc/systemd/system/'+unit,32768))==self.authority[key],'EXACT_FOUR_UNIT_HASHES')
  need(sha(g.read('/etc/systemd/system.control/'+g.UNIT+'.d/50-CPUQuota.conf',4096))==self.bridge.DROPIN_SHA,'EXACT_CONTROLLER_DROPIN')
  need(set(p.name for p in g.RUNTIME.iterdir())==set(g.RUNTIME_HASHES) and all(sha(g.read(g.RUNTIME/n))==h for n,h in g.RUNTIME_HASHES.items()),'EXACT_THIRTEEN_RUNTIME_FILES')
  for unit in(g.HUB,g.COLD):
   v=self.properties(unit);need(v==self.expected['prior_unit_properties'][unit] and v['ActiveState']=='active'and v['SubState']=='exited'and v['Result']=='success','SAME_READY_HUB_COLD')
  need(not self.call(['/usr/bin/systemctl','list-jobs','--no-pager','--no-legend']).strip(),'NO_SYSTEMD_JOB_PENDING')
  link=json.loads(self.call(['/usr/sbin/ip','-d','-j','link','show','dev','wg-capacity']));need(len(link)==1 and 'UP'in link[0]['flags'] and link[0]['mtu']==1280,'SAME_WIREGUARD_LINK')
  for rule in self.base.rules().values():self.call(['/usr/sbin/iptables','-w','2','-t','mangle','-C','POSTROUTING',*rule])
  for rule in self.bridge.functional_rules(self.base.BRIDGE_OPERATION).values():self.call(['/usr/sbin/iptables','-w','2','-C','FORWARD',*rule])
  return self.structure(),self.core()
 def structure(self):
  raw=self.call(['/usr/sbin/nft','-a','-j','list','ruleset']);owned,_=self.bridge._objects(raw);need(len(owned)==47 and sha(self.bridge._structure(owned,keep_handles=False))==self.bridge.AST47,'SAME_NFT_STRUCTURE');actual=sha(self.bridge._structure(owned,keep_handles=True));need(actual==self.expected['handles_sha256'],'SAME_47_NFT_HANDLES');return actual
 def core(self):
  k=['/usr/local/bin/k3s','kubectl','--kubeconfig=/etc/rancher/k3s/k3s.yaml','--request-timeout=3s','-n','dakasa'];d=json.loads(self.call(k+['get','deployment','yggdrasil','-o','json']));pods=json.loads(self.call(k+['get','pods','-l','app=yggdrasil','-o','json']))['items'];e=self.expected['core']
  need(d['metadata']['uid']==e['deployment_uid'] and d['metadata']['generation']==e['generation'] and all(d['status'].get(i)==1 for i in ('replicas','readyReplicas','updatedReplicas','availableReplicas')) and len(pods)==1,'SAME_SINGLE_READY_CORE_DEPLOYMENT');p=pods[0];cs=p['status']['containerStatuses'];need(p['metadata']['uid']==e['pod_uid'] and len(cs)==1 and cs[0]['ready'] is True and cs[0]['imageID']==e['image_id'] and cs[0]['containerID']==e['container_id'] and cs[0]['restartCount']==e['restart_count'],'SAME_CORE_POD_LIFETIME')
  ready=json.loads(self.call(k+['get','--raw','/api/v1/namespaces/dakasa/pods/'+p['metadata']['name']+':9080/proxy/readyz']));need(ready.get('status')=='ready' and ready.get('rabbitmq_status')=='ok','CORE_AND_RABBITMQ_READY');return e
 def check_once(self,old_bytes,expected):
  need(sha(old_bytes)==expected['old_config_sha256'] and self.g.read(self.old,32768,0o600)==old_bytes,'EXACT_OLD_CONFIG_CHECK_PATH')
  raw=self.call(['/usr/bin/python3','-B',str(self.g.RUNTIME/'controller.py'),'--config',str(self.old),'--check-once'],timeout=35);v=json.loads(raw.splitlines()[-1]);need(v.get('schema')=='root_R11_static_empty_and_current_readonly_check_v1' and v.get('applied') is False and v.get('backends')==['broker','core','rds','redis'] and v.get('prometheus_sources')==1 and v.get('held_native_read_classes')=={},'ACTUAL_OLD_READONLY_CHECK_ONCE');return True
 def prior_controller_terminated(self):
  prior=self.expected['prior_controller'];need(type(prior['pid'])is int and prior['pid']>1 and type(prior['start_ticks'])is int and prior['start_ticks']>0,'EXACT_PRIOR_PID_AND_START_TICKS');r=scope_collector.fs_read('/proc/'+str(prior['pid'])+'/stat')
  need(r['fd_closed'] is True,'PRIOR_PROCESS_READ_CLOSED')
  if r['status']=='absent':need(r['errno']==2,'ONLY_EXPLICIT_PRIOR_PROCESS_ENOENT');return True
  need(r['status']=='ok' and r['errno'] is None,'PRIOR_PROCESS_READ_KNOWN');return owner_scope.start_ticks(r['content'])!=prior['start_ticks']
 def snapshot(self):
  self.seq+=1;scope_dir=self.out/('SCOPE-%05d'%self.seq);scope_dir.mkdir(mode=0o700);scope=scope_collector.collect(lease=self.lease,ssm_evidence=self.ssm_evidence,native=self.native,diagnostic_directory=scope_dir)
  need(scope['result']['owner_and_cgroup_empty'] is True,'ISOLATED_HANDOFF_OWNER_TERMINAL');boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();need(boot==self.expected['boot_id'],'SAME_BOOT');cfg=sha(self.g.read(self.g.NEW_CONFIG,32768,0o600));need(cfg in (self.expected['old_config_sha256'],self.expected['new_config_sha256']),'ONLY_REVIEWED_CONFIG_PAIR');handles,core=self.static();p=self.properties(self.g.UNIT);gp=self.properties(self.g.GUARDIAN)
  state='running' if p['ActiveState']=='active' and p['SubState']=='running' else ('activating' if p['ActiveState']=='activating' else p['ActiveState']);guardian='active' if gp['ActiveState']=='active' and gp['SubState']=='running' else ('inactive' if gp['ActiveState']=='inactive' and gp['MainPID']=='0' else 'unknown')
  running_ok=False
  if state=='running':
   need(p['MainPID'].isdigit() and int(p['MainPID'])>1 and re.fullmatch('[a-f0-9]{32}',p['InvocationID']) is not None,'ACTUAL_RUNNING_CONTROLLER_IDENTITY');pid=int(p['MainPID']);cmd=Path('/proc/'+str(pid)+'/cmdline').read_bytes();expected_cmd=b'\0'.join(x.encode()for x in ['/usr/bin/python3','-B',str(self.g.RUNTIME/'controller.py'),'--config',str(self.g.NEW_CONFIG),'--run'])+b'\0';need(cmd==expected_cmd,'EXACT_RUNNING_CONTROLLER_COMMAND');running_ok=True
  dead=state in ('inactive','failed') and p['MainPID']=='0' and self.cgroup_empty(self.g.UNIT) and self.prior_controller_terminated();guardian_empty=guardian=='inactive' and self.cgroup_empty(self.g.GUARDIAN)
  checked=self.check_once(self.g.read(self.old,32768,0o600),self.expected) if dead and guardian_empty else False
  return {'owner_terminal':True,'previous_recovery_start_terminal':False,'unit_hashes_exact':True,'runtime_hashes_exact':True,'boot_identity_exact':True,'hub_and_cold_unchanged':True,'core_healthy':True,'config_is_regular_single_link':True,'nft_structure_exact':True,'config_sha256':cfg,'guardian_state':guardian,'guardian_cgroup_empty':guardian_empty,'controller_state':state,'controller_identity_verified':running_ok,'controller_pid_absent':dead,'controller_cgroup_empty':dead,'controller_start_job_pending':False,'check_once_old_config_success':checked}
 def observe_started(self):
  deadline=time.monotonic()+90;prior=self.expected['prior_controller'];identity=None
  while time.monotonic()<deadline:
   p=self.properties(self.g.UNIT)
   if p['ActiveState']=='failed':raise Held('NEW_CONTROLLER_FAILED')
   if p['ActiveState']=='active' and p['SubState']=='running':
    need(p['MainPID'].isdigit() and int(p['MainPID'])>1 and re.fullmatch('[a-f0-9]{32}',p['InvocationID']) is not None,'ACTUAL_STARTED_CONTROLLER');pid=int(p['MainPID']);path=Path('/proc/'+str(pid));first=(path/'stat').read_text();end=first.rfind(')');need(end>=0,'ACTUAL_NEW_PROC_STAT');ticks=first[end+1:].split()[19];need(ticks.isdigit(),'ACTUAL_NEW_START_TICKS');cmd=(path/'cmdline').read_bytes();want=b'\0'.join(x.encode()for x in ['/usr/bin/python3','-B',str(self.g.RUNTIME/'controller.py'),'--config',str(self.g.NEW_CONFIG),'--run'])+b'\0';need(cmd==want,'ACTUAL_NEW_CONTROLLER_COMMAND');after=(path/'stat').read_text();need(after[after.rfind(')')+1:].split()[19]==ticks,'UNREUSED_NEW_PID')
    current={'pid':pid,'invocation_id':p['InvocationID'],'start_ticks':int(ticks)};need(current['pid']!=prior['pid'] and current['invocation_id']!=prior['invocation_id'],'DISTINCT_NEW_CONTROLLER_LIFETIME');need(identity in (None,current),'SAME_NEW_CONTROLLER_LIFETIME');identity=current
    handles=self.structure();self.core();sample=self.coverage.kernel_text(self.call(['/usr/sbin/nft','-a','list','table','inet','dakasa_capacity_network']))
    if sample['all_four_backends_and_reverse_sources_positive']:
     return {'new_controller_identity_verified':True,'same_47_native_handles':True,'all_four_observed_positive':True,'controller_identity':identity,'handles_sha256':handles}
   time.sleep(1)
  raise Held('NEW_CONTROLLER_BACKENDS_NOT_QUALIFIED_IN_90_SECONDS')
