"""Root-only AWSgen8 typed82 terminal; default inert. No delete/Guest/SQL writes.
Explicit reviewed new Core263/schema82 context required. One IDs-only POST,
GET-only after any possible send; old failure, expiry and unknown ACK retained.
"""
import argparse,contextlib,datetime,hashlib,json,os,re,secrets,stat,sys,time,types,urllib.error
from pathlib import Path
Q=Path(__file__).resolve().parent;P=Q.parent
NATIVE=P/'notify-runtime-IAM-provisioner-r3-review/frozen_native.py'
NATIVE_SHA='2c6b9178f99a0c0717407dfe8f44f881386f817eeadadafa681a6825add75b62'
OP=Path('/Volumes/DaKasa - Data/Users/dakasa/Documents/Codex/2026-10-16/task-2/activation/sdk-source3-adoption-preparation/context-monorepo/yggdrasil/dakasa/eks-wake-toolkit/operator_session.py')
OP_SHA='91829020361ceaf81f1419a54c7c9de919e22f7faeac093c78344067e44c6fba'
HTTP=Q/'wire_http_DRAFT.py'
HTTP_SHA='635c164b674c9c75f018e259ade94b3ed122883d7f7d8ef93a3199106c84e8a8'
CLEANUP={'path':str(P/'ROOT-CORE262-GEN8-AWS-CLEANUP-da9eeb08d7c9cb5a685a/RETURN.PUBLIC.json'),'sha256':'ba42e4b5aae77e5f8d7932d7d4e52e6dad3ccd232946a83417fafb5a21076fb1'}
CLEANUP_WHOLE={'path':str(P/'ROOT-WHOLE-CORE262-GEN8-AWS-CLEANUP-da9eeb08d7c9cb5a685a/RETURN.PUBLIC.json'),'sha256':'25f0d35d16242251a9cdef4c43bd335144c2d727d9dbf54a4a9f502f571e94c4'}
CLEANUP_OWNER={'path':str(P/'Core262-gen8-AWS-unenrolled-administrative-native-cleanup-source-review/operate_once.py'),'sha256':'3c790a048af3d21d73f900878e9555691f3305bc8e3fd864bd01588af63a81dd'}
MARKER=P/'ROOT-ONE-CORE263-SCHEMA82-AWS-GEN8-FAILED-ORIGINAL-POST'
# DRAFT only: this executable and both modules require independent review and
# custody qualification. The unconditional entrypoint HOLD remains in force.
WIRE_BIN=P/'ROOT-PROD-AWS-GEN8-WIRE-OWNED-BUILD-20261101/gen8wire'
WIRE_BIN_SHA='e7f0b67c85dcc0fdf191d64ecc57a356edb845492c6e4427c4dd8c9e34e7a338'
WIRE_GATE_SHA='438f1778a605d724e9967c5f87f7951be4a9a24034cd773cb2e965aa6fa6a3f7'
WIRE_OWNER_SHA='e74a377f24891ced4e21863a95f835f727aaf7ab2e37483cb8e2a6277df1fad2'
CLOCK_SHA='1509d6144d6048fbcb2f4b02949a251b0379e1f1da5b38a11031fbe9e12aa26d'
def require(v,g):
 if not v:raise RuntimeError(g)
def sha(b):return hashlib.sha256(b).hexdigest()
def read(path,cap=12<<20):
 p=Path(path);require(p.is_absolute()and p.resolve(strict=True)==p,'CANONICAL_SOURCE_OR_PUBLIC_REF');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb')as f:a=os.fstat(f.fileno());b=f.read(cap+1);z=os.fstat(f.fileno())
 require(stat.S_ISREG(a.st_mode)and a.st_uid==os.getuid()and a.st_nlink==1 and not stat.S_IMODE(a.st_mode)&0o022 and 0<len(b)==a.st_size<=cap and(a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns),'WHOLE_STABLE_OWNED_PUBLIC_SOURCE');return b
def context_owned(path,cap=64<<20):
 # Native public stdout/stderr originals may be genuine empty regular files.
 # This reader is scoped only to the unchanged Core context qualifier.
 p=Path(path);require(p.is_absolute()and p.resolve(strict=True)==p,'CANONICAL_CONTEXT_PUBLIC_ORIGINAL');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb')as f:a=os.fstat(f.fileno());b=f.read(cap+1);z=os.fstat(f.fileno())
 require(stat.S_ISREG(a.st_mode)and a.st_uid==os.getuid()and a.st_nlink==1 and not stat.S_IMODE(a.st_mode)&0o022 and 0<=len(b)==a.st_size<=cap and(a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns),'WHOLE_STABLE_OWNED_CONTEXT_PUBLIC_ORIGINAL');return b
def load(path,pin):
 b=read(path);require(sha(b)==pin,'EXACT_SOURCE_PIN');m=types.ModuleType('Root_gen7_'+Path(path).stem);m.__file__=str(path);exec(compile(b,str(path),'exec'),m.__dict__);return m
def original(ref):
 require(type(ref)is dict and set(ref)=={'path','sha256'},'EXACT_PUBLIC_REF');b=read(ref['path']);require(sha(b)==ref['sha256'],'WHOLE_PUBLIC_REF_PIN');return b
def ref(path):return{'path':str(path),'sha256':sha(read(path))}
def persist_send_marker(marker,value,once):
 # The new directory entry must survive a crash before any possible POST.
 marker.mkdir(mode=0o700)
 parent=os.open(marker.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(parent)
 finally:os.close(parent)
 once(marker/'POSSIBLE-SEND.PUBLIC.json',value)
def safe_facts(f):return{k:f.get(k)for k in('native_started','exit_code','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined','captured_output_truncated')}
class Engine:
 def __init__(self,args,c,n,core,out):
  self.a,self.c,self.n,self.core,self.out=args,c,n,core,out;self.t=c.TARGETS['aws'];self.provider='aws';self.hard=time.monotonic()+240;self.seq=0;self.calls=[];self.awsenv=None;self.wire=None;self.continuous=load(Q/'clock_guard_DRAFT.py',CLOCK_SHA).init();self.env=dict(n.SAFE,KUBECONFIG=str(P/'kubeconfig'))
  self.p,self.b,self.s=c.policy(c.loads(original({'path':str(P/self.t['policy_dir']/'POLICY-ACTIVATION-RETURN.PUBLIC.json'),'sha256':self.t['policy_ref_sha']})),self.t)
 def call(self,label,argv,stdin=b'',env=None,seconds=15,nonzero=False):
  self.seq+=1;require(time.monotonic()+seconds<self.hard,'ONE_GLOBAL_ORIGINAL_REMAINDER');facts={};body=None
  try:body,f=self.n.native(argv,stdin=stdin,deadline=min(self.hard,time.monotonic()+seconds),env=env or self.n.SAFE,cap=2<<20,custody=facts,diagnostic_path=None)
  finally:
   facts=dict(getattr(self.n.native,'last_custody',None)or facts);safe=safe_facts(facts);path=self.out/('%03d-%s-CALL.PUBLIC.json'%(self.seq,label));self.n.once(path,safe);self.calls.append({'label':label,'ref':ref(path)})
  if nonzero:
   require(all(safe.get(k)is True for k in('native_started','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined'))and safe['captured_output_truncated']is False,'ORIGINAL_NATIVE_COMPLETE_NONZERO_RETURN')
  else:require(self.c.closed(safe),'ORIGINAL_NATIVE_ZERO_CLOSE_EOF_JOIN')
  return body,f
 def current_core(self,label):
  e=self.core['same_native_identity'];b,_=self.call(label,[str(P/'tooling/kubectl'),'--context','dakasa-brain','--request-timeout=8s','-n','dakasa','get','pod',e['pod_name'],'-o','json'],env=self.env)
  v=self.c.loads(b);rows=v['status']['containerStatuses'];require(len(rows)==1 and rows[0]['name']=='core','ONE_CURRENT_CORE');s=rows[0]
  got={'pod_name':v['metadata']['name'],'pod_uid':v['metadata']['uid'],'container_id':s['containerID'],'image_id':s['imageID'],'restart_count':s['restartCount'],'started_at':s['state']['running']['startedAt']}
  require(got==e and got['restart_count']==0 and v['status']['phase']=='Running'and not v['metadata'].get('deletionTimestamp')and s['ready']is True and any(x['type']=='Ready'and x['status']=='True'for x in v['status']['conditions']),'SAME_CURRENT_CORE263_SCHEMA82_READY_R0_LIFETIME')
 def snapshot(self,label):
  snapshot_start=self.continuous()[0]
  query=read(Q/'READONLY-EXACT-GEN8-AWS.sql',65536);require(sha(query)==self.c.SQL_SHA,'EXACT_GEN8_SCHEMA82_READONLY_SQL');base=[str(P/'tooling/kubectl'),'--context','dakasa-brain','--request-timeout=8s','-n','dakasa'];uid=base+['get','pod','unified-database-0','-o','jsonpath={.metadata.uid}']
  before,_=self.call(label+'-DB-BEFORE',uid,env=self.env);require(before.decode()==self.c.DB_UID,'PHYSICAL_DB_BEFORE')
  shell='PGAPPNAME=root-gen8-witnessed-unenrolled-readonly PGPASSWORD="$POSTGRES_PASSWORD" psql -XqAt -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d yggdrasil -f -'
  raw,_=self.call(label+'-DB-READ',base+['exec','-i','unified-database-0','-c','postgres','--','sh','-c',shell],stdin=query,env=self.env)
  after,_=self.call(label+'-DB-AFTER',uid,env=self.env);require(after==before,'SAME_PHYSICAL_DB_AFTER_ROLLBACK');v=self.c.loads(raw);r=self.c.validate(v,self.provider,self.p,self.b,self.s)
  # Whole original fingerprints stay RAM-only; no private wire/body/hash export.
  self.n.once(self.out/(label+'-ELIGIBILITY.PUBLIC.json'),{'provider':self.provider,'grant_id':self.t['grant'],'preregistration_id':self.t['pre'],'job_id':self.t['job'],'run_id':self.t['run'],'generation':8,'baseline_and_assessed_capacity':0,'installation_count':0,'resource_slot_count':0,'other_live_work_count':0,'originals_expired':True,'original_witness_and_unknown_ACK_preserved':True,'physical_schema':82,'native_or_SQL_mutations':0})
  if label=='PRE-TERMINAL':self.snapshot_cutoff=snapshot_start+15_000_000_000
  return v,r
 def aws(self,label,op,args,notfound=None):
  allowed={'describe-instances','describe-volumes','describe-network-interfaces','describe-images'};require(op in allowed,'CLOSED_AWS_OPS')
  if self.awsenv is None:self.awsenv=self.n.aws_auth(min(self.hard-20,time.monotonic()+25),P);self.awsenv['AWS_MAX_ATTEMPTS']='1'
  raw,f=self.call(label,['/usr/local/bin/aws','--region','us-east-1','--cli-connect-timeout','3','--cli-read-timeout','10','--no-paginate','ec2',op,*args,'--output','json'],env=self.awsenv,nonzero=True)
  if f['exit_code']==0:require(self.c.closed(safe_facts(f)),'AWS_NATIVE_ZERO');return self.c.loads(raw),False
  require(notfound is not None and f['exit_code']==254 and f.get('error_code')==notfound and raw.strip()==b'','EXACT_NATIVE_NOT_FOUND_ONLY');return None,True
 def absence(self):
  t=self.t;physical=self.c.PHYSICAL
  require(self.wire is None and t['rid']=='i-0696296a8cb2d3d30','EXACT_ONE_INSTANCE_WIRE')
  gate=load(Q/'wire_gate_DRAFT.py',WIRE_GATE_SHA);owner=load(Q/'wire_owned_DRAFT.py',WIRE_OWNER_SHA)
  self.wire=owner.WireObservation(str(self.out),str(WIRE_BIN),WIRE_BIN_SHA,lambda argv,**kw:self.call('INSTANCE-WIRE',argv,**kw),self.awsenv,gate,self.continuous)
  _,vgone=self.aws('VOLUME-ABSENCE','describe-volumes',['--volume-ids',physical['root_volume_id']],'InvalidVolume.NotFound');_,ngone=self.aws('ENI-ABSENCE','describe-network-interfaces',['--network-interface-ids',physical['primary_eni_id']],'InvalidNetworkInterfaceID.NotFound');return vgone and ngone
 def prior_cleanup(self):
  c=self.c;v=c.loads(original(CLEANUP));w=c.loads(original(CLEANUP_WHOLE));original(CLEANUP_OWNER)
  require(w['schema']=='Root_single_pinned_public_native_closed_zero_v1'and w['source_ref']==CLEANUP_OWNER,'GENUINE_HISTORICAL_ADMIN_WHOLE_SOURCE')
  require(c.closed(c.loads(original(w['original_caller_ref'])))and c.loads(original(w['child_return_ref']))=={'directory':str(Path(CLEANUP['path']).parent),'return_ref':CLEANUP},'GENUINE_ADMIN_ORIGINAL_OUTER_ZERO_AND_EXACT_RETURN')
  require(v['schema']=='Root_Core262_gen8_exact_administrative_cleanup_return_v1'and v['source_sha256']==CLEANUP_OWNER['sha256']and v['contract_sha256']=='729e297991b531a42b7b1fd4fa52959e43e0e2e163720ae91fbe7b424f432efa'and v['provider']=='aws'and[v[k]for k in('grant_id','preregistration_id','job_id','run_id')]==[self.t[k]for k in('grant','pre','job','run')]and v['Core_ledger_POST_requested']is False and v['direct_SQL_DDL_DML_Guest_workflow_or_policy_mutations']==0,'EXACT_PREVIOUS_ADMIN_ONLY_NO_LEDGER_AUTHORITY')
  require(v['result']['physical']==c.PHYSICAL and v['result']['administrative_native_absence']is True and v['result']['originals_unchanged']is True and v['result']['Guest_retirement_quiescence_or_business_authority']is False,'HISTORICAL_EXACT_VM_EBS_ENI_ABSENCE_NOT_GUEST_QUIESCENCE')
  return v
 def fresh_absence(self):
  if self.awsenv is None:self.awsenv=self.n.aws_auth(min(self.hard-20,time.monotonic()+25),P);self.awsenv['AWS_MAX_ATTEMPTS']='1'
  raw,_=self.call('CURRENT-AWS-ACCOUNT',['/usr/local/bin/aws','--region','us-east-1','--cli-connect-timeout','3','--cli-read-timeout','10','--no-paginate','sts','get-caller-identity','--output','json'],env=self.awsenv)
  require(self.c.loads(raw)['Account']=='153828470928','EXACT_CURRENT_NATIVE_AWS_ACCOUNT');require(self.absence(),'FRESH_EXACT_VM_ROOT_EBS_PRIMARY_ENI_ABSENT');self.wire.check()
 def ledger(self,post):
  c=self.c;self.current_core('BEFORE-CORE');self.prior_cleanup();h=load(HTTP,HTTP_SHA);op=load(OP,OP_SHA);selected=None;sent=False;responses={};facts=[];before=None
  def opener(req,timeout):
   nonlocal sent
   path=req.full_url.removeprefix(h.SERVER);session=path=='/api/v1/auth/session'
   require(req.full_url==h.SERVER+path and((session and req.get_method()=='GET'and req.data is None)or(selected is not None and path==selected[1]and req.get_method()==selected[0])),'ONLY_AUTH_SESSION_AND_EXACT_FAILED_ORIGINAL_ROUTE')
   if not session and req.get_method()=='POST':
    require(post and before is not None and not sent and c.loads(req.data)=={'grant_id':self.t['grant'],'job_id':self.t['job']},'ONE_IDS_ONLY_FAILED_ORIGINAL_POST')
    c.fresh(before[0]);self.wire.check();persist_send_marker(MARKER,{'source_sha256':self.a.execute_reviewed_sha256,'contract_sha256':self.a.contract_sha256,'grant_id':self.t['grant'],'job_id':self.t['job'],'new_Core_publication':c.NEW_CORE_SOURCE,'Core_context_ref':dict(zip(('path','sha256'),self.a.Core_context_ref)),'wire_receipt_ref':ref(Path(self.wire.path)/'receipt.json'),'wire_intent_ref':ref(Path(self.wire.path)/'intent.json'),'wire_request_id':self.wire.receipt['request_id'],'eligibility_ref':ref(self.out/'PRE-TERMINAL-ELIGIBILITY.PUBLIC.json'),'eligibility_observed_at':before[0]['observed_at'],'never_replay':True,'GET_only_after_unknown':True},self.n.once);sent=True;self.wire.check();c.fresh(before[0])
   try:
    limit=min(self.hard,time.monotonic()+35)
    if not session and req.get_method()=='POST':
     now_mono=time.monotonic();age=(datetime.datetime.now(datetime.timezone.utc)-c.utc(before[0]['observed_at'])).total_seconds();require(-2<=age<15,'FRESH_SNAPSHOT_BEFORE_TRANSPORT');limit=min(limit,self.wire.cutoff,now_mono+15-max(age,0));continuous_limit=min(self.wire.continuous_cutoff,self.snapshot_cutoff);response=h.native_open(req,timeout,limit,facts,continuous=self.continuous,continuous_deadline=continuous_limit)
    else:response=h.native_open(req,timeout,limit,facts)
    if not session:responses[(req.get_method(),path)]=response.status
    return response
   except urllib.error.HTTPError as error:
    if not session:responses[(req.get_method(),path)]=error.code
    raise
  def request(method,path,body=None):
   nonlocal selected
   selected=(method,path);responses.pop(selected,None)
   try:return op.request(path,method=method,body=body,tries=1,timeout=35,max_bytes=2<<20,relogin_wait=0,allow_replay=False)
   except BaseException:
    require(method=='GET'and responses.get(selected)==404,'UNCERTAIN_OR_REFUSED_REQUEST_GET_ONLY_NO_REPLAY');return None
  with open(os.devnull,'w')as sink,contextlib.redirect_stdout(sink),contextlib.redirect_stderr(sink):
   os.environ['YGGDRASIL_CONFIG']='/Volumes/DaKasa - Data/Users/dakasa/.yggdrasil/config.yaml';op.configure(relogin_wait_seconds=0);require(op.SERVER==h.SERVER,'FIXED_OPERATOR_SERVER');op._ygg_open=opener
   if post:
    require(not MARKER.exists(),'ONE_POSSIBLE_POST_NEVER_REPLAY');require(request('GET',c.ROUTE+'/'+self.t['grant'])is None,'NO_EXISTING_FAILED_TERMINAL_BEFORE_ONE_POST')
    self.fresh_absence();before=self.snapshot('PRE-TERMINAL');self.current_core('FINAL-CORE')
    returned=request('POST',c.ROUTE,{'grant_id':self.t['grant'],'job_id':self.t['job']});require(responses.get(('POST',c.ROUTE))==201,'ONE_ORIGINAL_CREATED_RESPONSE');c.summary(returned,before[1])
   value=request('GET',c.ROUTE+'/'+self.t['grant']);c.summary(value,before[1]if before is not None else None)
  require(facts and all(x.get(k)is True for x in facts for k in('body_EOF','declared_length_complete','response_closed','connection_closed','same_socket_watchdog_joined','returned_before_deadline')),'EVERY_ORIGINAL_HTTP_FULL_CLOSE_JOIN')
  self.n.once(self.out/'HTTP-FACTS.PUBLIC.json',facts);self.current_core('AFTER-CORE')
  return {'typed82_summary':value,'historical_admin_absence_ref':CLEANUP,'old_failure_deadline_and_unknown_ACK_preserved':True,'new_Guest_generation_still_needs_fresh_assessment':True,'GET_never_replays_POST':True}
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--execute',action='store_true');ap.add_argument('--execute-reviewed-sha256');ap.add_argument('--contract-sha256');ap.add_argument('--action',choices=('inspect','post','get'));ap.add_argument('--Core-context-source-ref',nargs=2);ap.add_argument('--Core-context-ref',nargs=2);ap.add_argument('--out',type=Path);a=ap.parse_args()
 if not a.execute:print(json.dumps({'execute':False,'native_API_SQL_or_private_reads':0}));return
 raise RuntimeError('DRAFT_CORE32FE_NATIVE_WIRE_AND_ACTUAL_CONTEXT_NOT_QUALIFIED')
 require(a.execute_reviewed_sha256==sha(read(Path(__file__)))and a.contract_sha256 and a.action and a.Core_context_source_ref and a.Core_context_ref,'REVIEWED_OPERATOR_AND_EXPLICIT_NEW_SCHEMA82_CONTEXT_OPERANDS')
 c=load(Q/'contract.py',a.contract_sha256);n=load(NATIVE,NATIVE_SHA);ctxref=dict(zip(('path','sha256'),a.Core_context_ref));k=load(*a.Core_context_source_ref);core=k.qualify(types.SimpleNamespace(require=require,owned=context_owned,sha=sha,loads=c.loads),c.loads(original(ctxref)))
 require(core['Core_source']==c.NEW_CORE_SOURCE and core['CODE']==c.NEW_CORE_CODE and core['schema_version']==82 and core['actual_deployment_generation']==263 and core['Core_firstReady600_qualified']is True,'GENUINE_NEW_CORE566_SCHEMA82_GENERATION263_ORIGINAL600_NOT_OLD26281')
 require(a.out and a.out.parent==P and re.fullmatch('ROOT-CORE263-SCHEMA82-AWS-GEN8-'+a.action.upper()+'-[0-9a-f]{20}',a.out.name)and not a.out.exists(),'NEW_EXCLUSIVE_OUTPUT');os.umask(0o077);a.out.mkdir(mode=0o700);e=Engine(a,c,n,core,a.out)
 try:
  if a.action=='inspect':
   e.current_core('INITIAL-CORE');e.prior_cleanup();e.fresh_absence();v,row=e.snapshot('CURRENT');e.current_core('FINAL-CORE');e.wire.check();result={'eligibility_only_not_terminal_authority':True,'exact_native_absence':True,'historical_admin_absence_ref':CLEANUP};schema='Root_Core263_schema82_AWSgen8_failed_original_inspection_v1'
  else:result=e.ledger(a.action=='post');schema='Root_Core263_schema82_AWSgen8_failed_original_operator_v1'
  report={'schema':schema,'source_sha256':a.execute_reviewed_sha256,'contract_sha256':a.contract_sha256,'new_Core_publication':c.NEW_CORE_SOURCE,'Core_context_source_ref':dict(zip(('path','sha256'),a.Core_context_source_ref)),'Core_context_ref':ctxref,'provider':'aws','grant_id':e.t['grant'],'preregistration_id':e.t['pre'],'job_id':e.t['job'],'run_id':e.t['run'],'result':result,'original_calls':e.calls,'direct_SQL_DDL_DML_Guest_workflow_policy_or_provider_mutations':0,'Core_typed82_POST_requested':a.action=='post','original_outer_zero_still_required':True};n.once(a.out/'RETURN.PUBLIC.json',report);print(json.dumps({'directory':str(a.out),'return_ref':ref(a.out/'RETURN.PUBLIC.json')}),flush=True)
 except BaseException as error:
  n.once(a.out/'HOLD.PUBLIC.json',{'class':type(error).__name__,'guard':str(error)if isinstance(error,RuntimeError)and re.fullmatch('[A-Z0-9_]{1,160}',str(error))else None,'no_automatic_POST_replay':True,'GET_only_after_possible_send':True});raise SystemExit(78)
 finally:
  if e.wire is not None:e.wire.close()
  e.env.clear()
  if e.awsenv is not None:e.awsenv.clear()
if __name__=='__main__':main()
