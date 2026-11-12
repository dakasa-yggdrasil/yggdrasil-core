#!/usr/bin/env python3
"""Artifact assembly only. No target import, derivation, Native, auth or API call.
Root supplies its actual existing CI attestation and manual standing review.
The standing configuration itself is derived later by the existing Native stage.
"""
import ast,hashlib,ipaddress,json,os,re,stat,subprocess
from pathlib import Path
SOURCE_BOUND=False
INPUTS_REF=None
BINDINGS_REF=None
EXPECTED_HEAD=None
EXPECTED_R=None
EXPECTED_D=None
OLD_MANIFEST_SHA='556705e7181bbd1df28b9c863d25f09b9b285f19e50e2a644afe5f2e8c0a36c3'
CONTROLLER_REVIEW_SHA=None
CONTROLLER_UNIT_SHA=None
PREFIX='ops/network-guardian/g15pair/'
PREP_ROOT=Path('/Users/giovanniriosmartins/Documents/Codex/2026-10-19/task/ELASTIC-ARTIFACTS-20261111/R12-M14-G22-PAIR-INERT-COMPILER')
CAP=16<<20
class Hold(RuntimeError):pass
def need(ok,guard):
 if not ok:raise Hold(guard)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def wire(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def loads(raw):
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'DUPLICATE_JSON_KEY');out[k]=v
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(Hold('NONFINITE_JSON')))
def digest(x):return type(x)is str and re.fullmatch('[a-f0-9]{64}',x)is not None and x!='0'*64
def read_ref(r,cap=CAP):
 need(type(r)is dict and set(r)=={'path','sha256'}and type(r['path'])is str and digest(r['sha256']),'CLOSED_INPUT_REF')
 p=Path(r['path']);need(p.is_absolute()and p.resolve(strict=True)==p,'CANONICAL_EXISTING_INPUT')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_uid==os.geteuid()and a.st_nlink==1 and not stat.S_IMODE(a.st_mode)&0o022 and 0<a.st_size<=cap,'OWNED_BOUNDED_INPUT')
  out=bytearray()
  while len(out)<=cap:
   b=os.read(fd,min(65536,cap+1-len(out)))
   if not b:break
   out.extend(b)
  z=os.fstat(fd);n=p.lstat();key=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  raw=bytes(out);need(key(a)==key(z)==key(n)and len(raw)==a.st_size and sha(raw)==r['sha256'],'STABLE_EXACT_INPUT_BYTES');return raw
 finally:os.close(fd)
def literal(tree,name):
 nodes=[n for n in tree.body if isinstance(n,ast.Assign)and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id==name]
 need(len(nodes)==1,'ONE_SOURCE_ASSIGNMENT_'+name);v=nodes[0].value
 if isinstance(v,ast.Call):
  need(isinstance(v.func,ast.Name)and v.func.id=='frozenset'and len(v.args)==1 and not v.keywords,'ONLY_LITERAL_FROZENSET_METADATA');return frozenset(ast.literal_eval(v.args[0]))
 return ast.literal_eval(v)
PYTHON_BINDINGS={
 'source/network_guardian.py':{'PROPOSAL_BOUND','HEAD_CORE_SOURCE','HEAD_NEW_CORE_DIGEST','G22_CONTROLLER_CONFIG_SHA'},
 'tools/pair_change_contract.py':{'PROPOSAL_BOUND','SOURCE_R','NEW_DIGEST','G22_CONFIG_SHA','OLD_CORE_POD_UID','OLD_CORE_CONTAINER_ID'},
 'tools/derive_g15pair_controller_config.py':{'PROPOSAL_BOUND','HEAD_NEW_CORE_DIGEST','G22_CONFIG_SHA'},
 'tools/derive_standing_config.py':{'PROPOSAL_BOUND'},
}
BOUND_UNITS={'units/dakasa-capacity-network-cold-transport.service','units/dakasa-capacity-network-guardian.service'}
PACKAGE_BINDINGS={'files','base_Core_source','amd64_Core_manifest_digest','controller_config_sha256','controller_unit_sha256','source_bound','proposal_bound','source_unit_hash_arguments_bound','inert_unit_source_sha_argument','bound_Guardian_bytes','fixed_width_latebind_Guardian_bytes'}
def literal_inverse(raw,bound,names):
 def assignments(data):
  tree=ast.parse(data);out={};lines=data.splitlines(keepends=True);offset=[0]
  for line in lines:offset.append(offset[-1]+len(line))
  for n in tree.body:
   if isinstance(n,ast.Assign)and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id in names:
    name=n.targets[0].id;need(name not in out and isinstance(n.value,ast.Constant),'ONE_LITERAL_HEADER_'+name)
    out[name]=(n.value.value,offset[n.value.lineno-1]+n.value.col_offset,offset[n.value.end_lineno-1]+n.value.end_col_offset)
  need(set(out)==names,'EXACT_CLOSED_LITERAL_HEADERS');return out
 a=assignments(raw);b=assignments(bound);inverse=bound
 for name,(_,lo,hi)in sorted(b.items(),key=lambda row:row[1][1],reverse=True):
  _,start,end=a[name];inverse=inverse[:lo]+raw[start:end]+inverse[hi:]
 need(inverse==raw,'WHOLE_BYTE_INVERSE_ONLY_ROOT_LITERAL_BINDINGS')
 need(a['PROPOSAL_BOUND'][0]is False and b['PROPOSAL_BOUND'][0]is True,'QUALIFIED_GIT_INERT_ROOT_COPY_BOUND')
 for name in names-{'PROPOSAL_BOUND'}:need(a[name][0]is None,'QUALIFIED_GIT_FUTURE_DATA_NULL_'+name)
 return {name:value[0]for name,value in b.items()}
def bound_source_overlay(git_blob,binding):
 need(type(binding)is dict and set(binding)=={'schema','source_commit','reviewed_by_root','bound_source_refs'}and binding['schema']=='g22_root_literal_source_bindings_v1'and binding['source_commit']==EXPECTED_HEAD and binding['reviewed_by_root']is True,'CLOSED_ROOT_LITERAL_DATA_BINDING_NOT_CI_GIT_BYTES')
 refs=binding['bound_source_refs'];names=set(PYTHON_BINDINGS)|BOUND_UNITS|{'PACKAGE.json'}
 need(type(refs)is dict and set(refs)==names,'EXACT_SEVEN_ROOT_BOUND_SOURCE_REFS')
 raw={name:git_blob(PREFIX+name)for name in names};bound={name:read_ref(refs[name])for name in names};values={}
 for name,allowed in PYTHON_BINDINGS.items():values[name]=literal_inverse(raw[name],bound[name],allowed)
 G=values['source/network_guardian.py'];C=values['tools/pair_change_contract.py'];D=values['tools/derive_g15pair_controller_config.py']
 head=C['G22_CONFIG_SHA'];need(digest(head)and G['G22_CONTROLLER_CONFIG_SHA']==D['G22_CONFIG_SHA']==head,'ONE_CONCRETE_C22_PIN')
 need(C['SOURCE_R']==G['HEAD_CORE_SOURCE']==EXPECTED_R and C['NEW_DIGEST']==EXPECTED_D and G['HEAD_NEW_CORE_DIGEST']==D['HEAD_NEW_CORE_DIGEST']=='sha256:'+EXPECTED_D,'ONE_ACTUAL_FUTURE_R_D_BINDING')
 need(type(C['OLD_CORE_POD_UID'])is str and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',C['OLD_CORE_POD_UID'])and type(C['OLD_CORE_CONTAINER_ID'])is str and re.fullmatch('containerd://[a-f0-9]{64}',C['OLD_CORE_CONTAINER_ID']),'ROOT_REAL_CORE11_POD_AND_CONTAINER_DATA')
 guardian_sha=sha(bound['source/network_guardian.py']);old_guardian_sha=sha(raw['source/network_guardian.py'])
 need(len(bound['source/network_guardian.py'])<=131072,'EXISTING_GUARDIAN_SOURCE_CAP')
 for name in BOUND_UNITS:
  old_arg=('--source-sha256 '+old_guardian_sha).encode();new_arg=('--source-sha256 '+guardian_sha).encode()
  need(raw[name].count(old_arg)==1 and bound[name]==raw[name].replace(old_arg,new_arg,1),'ONLY_UNIT_GUARDIAN_SHA_ARGUMENT_LATEBIND')
 old=loads(raw['PACKAGE.json']);package=loads(bound['PACKAGE.json'])
 need(old['source_bound']is False and old['proposal_bound']is False and all(h==sha(git_blob(PREFIX+n))for n,h in old['files'].items()),'QUALIFIED_INERT_SOURCE15_DAG_EXACT_GIT_BYTES')
 need(set(old)==set(package)and wire({k:old[k]for k in old if k not in PACKAGE_BINDINGS})==wire({k:package[k]for k in package if k not in PACKAGE_BINDINGS}),'PACKAGE_ONLY_EXISTING_LITERAL_BINDING_METADATA')
 need(package['source_bound']is True and package['proposal_bound']is True and package['base_Core_source']==EXPECTED_R and package['amd64_Core_manifest_digest']=='sha256:'+EXPECTED_D and package['controller_config_sha256']==head and package['controller_unit_sha256']==CONTROLLER_UNIT_SHA,'PACKAGE_SAME_ROOT_R_D_C22_AND_CONTROLLER_UNIT')
 need(package['inert_unit_source_sha_argument']==guardian_sha and package['source_unit_hash_arguments_bound']is True and package['bound_Guardian_bytes']==package['fixed_width_latebind_Guardian_bytes']==len(bound['source/network_guardian.py'])and package['prepared_Guardian_bytes']==len(raw['source/network_guardian.py']),'PACKAGE_ACTUAL_BOUND_GUARDIAN_SHA_AND_SIZE')
 need(package['operational_ci_qualified']is False and package['operational_source_commit']is None,'BOUND_BYTES_NOT_RELABELED_CI_GIT_BLOB')
 need(set(package['files'])==set(old['files'])and all(h==sha(bound[n]if n in bound else git_blob(PREFIX+n))for n,h in package['files'].items()),'BOUND_SOURCE15_FILE_DAG_EXACT')
 proof={'schema':'g22_root_literal_source_overlay_provenance_v1','qualified_git_commit':EXPECTED_HEAD,'root_binding_ref':BINDINGS_REF,'bound_bytes_are_CI_git_blobs':False,'whole_byte_inverse_only_allowlisted_literals':True,'all_function_class_bodies_unchanged_by_binding':True,'raw_git_files':{n:sha(v)for n,v in raw.items()},'root_bound_files':{n:sha(v)for n,v in bound.items()},'future_native_standing_or_swap_qualified':False}
 return bound,proof

def main():
 need(SOURCE_BOUND is True and type(INPUTS_REF)is dict and type(BINDINGS_REF)is dict and type(EXPECTED_HEAD)is str and re.fullmatch('[a-f0-9]{40}',EXPECTED_HEAD)and EXPECTED_HEAD!='0'*40 and type(EXPECTED_R)is str and re.fullmatch('[a-f0-9]{40}',EXPECTED_R)and EXPECTED_R!='0'*40 and digest(EXPECTED_D),'INERT_NO_FILE_OR_GIT_IO_BEFORE_ROOT_BINDING')
 c=loads(read_ref(INPUTS_REF));keys={'schema','source_worktree','out','ci_attestation_ref','root_controller_review_ref','root_standing_review_ref','controller_unit_ref','predecessor_manifest_ref','actual_M13_swap_return_ref','continuity_peer_ipv4','expected_controller_identity','expected_guardian_identity'}
 need(type(c)is dict and set(c)==keys and c['schema']=='g15_external_package_artifact_inputs_v1','CLOSED_ARTIFACT_INPUTS_NOT_APPROVAL')
 W=Path(c['source_worktree']);out=Path(c['out']);need(W.is_absolute()and W.resolve(strict=True)==W and out.is_absolute()and out.parent==PREP_ROOT and out.parent.resolve(strict=True)==out.parent and not out.exists(),'FIXED_EXISTING_SOURCE_AND_NEW_OUTPUT_PARENT')
 def git_blob(name):
  need(name.startswith(PREFIX)and '..'not in Path(name).parts,'FIXED_GIT_SOURCE_SCOPE')
  r=subprocess.run(['git','show',EXPECTED_HEAD+':'+name],cwd=W,capture_output=True,check=False,timeout=15)
  need(r.returncode==0 and 0<len(r.stdout)<=CAP,'EXACT_COMMITTED_GIT_BLOB');return r.stdout
 overlay,provenance=bound_source_overlay(git_blob,loads(read_ref(BINDINGS_REF)))
 def blob(name):
  local=name.removeprefix(PREFIX)
  return overlay[local]if name.startswith(PREFIX)and local in overlay else git_blob(name)
 contract=blob(PREFIX+'tools/pair_change_contract.py');tree=ast.parse(contract)
 modules=literal(tree,'MODULES');tools=literal(tree,'TOOLS');helpers=literal(tree,'HELPERS');roles=literal(tree,'REQUIRED_CI')
 need(len(modules)==8 and len(set(modules))==8 and len(tools)==4 and len(set(tools))==4 and len(helpers)==7 and len(roles)==18,'EXISTING_CLOSED_G15_SOURCE_ROSTERS')
 need(literal(tree,'PROPOSAL_BOUND')is True and literal(tree,'SOURCE_R')==EXPECTED_R and literal(tree,'NEW_DIGEST')==EXPECTED_D,'EXACT_CURRENT_BOUND_R8_SOURCE_DATA')
 protected={}
 for name in('EXPECTED_INHERITED_REFS','EXPECTED_G8_PROOF_REFS','EXPECTED_G9_PROOF_REFS'):
  value=literal(tree,name);need(type(value)is dict and not(set(protected)&set(value)),'DISJOINT_PROTECTED_REFERENCE_ROLES');protected.update(value)
 need(len(protected)==43,'EXACT_SOURCE_PROTECTED43')
 oldraw=read_ref(c['predecessor_manifest_ref']);need(sha(oldraw)==OLD_MANIFEST_SHA,'EXACT_ORIGINAL_M13_ORDINARY_PACKAGE_MANIFEST')
 old=loads(oldraw);refs=old['protected_refs'];need(len(refs)==43 and len({r['path']for r in refs})==43 and {r['path']:r['sha256']for r in refs}==protected,'M13_PROTECTED43_EXACT_CURRENT_SOURCE_UNION')
 EXPECTED_CONTROLLER=c['expected_controller_identity'];EXPECTED_GUARDIAN=c['expected_guardian_identity']
 for value in(EXPECTED_CONTROLLER,EXPECTED_GUARDIAN):
  need(type(value)is dict and set(value)=={'boot_id','pid','start_ticks','InvocationID','ExecMainStartTimestampMonotonic'}and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',str(value['boot_id']))and type(value['pid'])is int and value['pid']>1 and type(value['start_ticks'])is int and value['start_ticks']>0 and re.fullmatch('[a-f0-9]{32}',str(value['InvocationID']))and re.fullmatch('[1-9][0-9]*',str(value['ExecMainStartTimestampMonotonic'])),'EXACT_ROOT_RETAINED_M13_PHYSICAL_IDENTITY_DATA')
 need(EXPECTED_CONTROLLER['boot_id']==EXPECTED_GUARDIAN['boot_id']and EXPECTED_CONTROLLER['pid']!=EXPECTED_GUARDIAN['pid'],'SAME_BOOT_DISTINCT_RETAINED_M13_LIFETIMES')
 swap_raw=read_ref(c['actual_M13_swap_return_ref']);need(sha(swap_raw)=='178d0f95c6f783ec372e88db23660ea9f258a90af23ca181dca5873bbe56900b','EXACT_RETAINED_ORDINARY_M13_SWAP_ORIGINAL')
 swapped=loads(swap_raw)
 need(type(swapped)is dict and set(swapped)=={'schema','status','result','automatic_replay','Guest_or_Core_business_authority'}and swapped['schema']=='g15_pair_swap_return_v1'and swapped['status']=='CONFIG_SWAP_OK'and swapped['automatic_replay']is False and swapped['Guest_or_Core_business_authority']is False,'GENUINE_M13_ORDINARY_SWAP_NOT_M6_TYPED_REPAIR_ALIAS')
 prior=swapped['result'];need(type(prior)is dict and set(prior)=={'source_commit','source_R','amd64_D','controller','guardian','controller_config_sha256','new_guardian_source_sha256','standing_sha256','actual_new_full120_ref','own_daemon_first_current15_ref','independent_current15','all_inherited_budget_and_original_refs_unchanged','Core_Cold_Hub_or_provider_mutation','continuity','conservative_per_role_gap_seconds'},'CLOSED_RETAINED_M13_ORDINARY_SWAP_RESULT')
 need(old['source_commit']==prior['source_commit']=='8005bbc004e3eb6930dd3be19d0e85dc019c2352'and old['source_R']==prior['source_R']=='446dad7e7ea8fee062643919bb893438fd71ed47'and old['amd64_D']==prior['amd64_D']=='8d79a2284adaac863cf8ae1dc0ee6853195cb643402936b753b55cbddfc290ad'and prior['controller']==EXPECTED_CONTROLLER and prior['guardian']==EXPECTED_GUARDIAN,'ACTUAL_M13_NEW_CONTROLLER_AND_GUARDIAN_NOT_ITS_PREDECESSOR_IDENTITIES')
 need(prior['controller_config_sha256']=='ac8f33749c6730c3be11c09cb5105ab9ccbec5d70edae57fe8a308c821bcbd74'and prior['new_guardian_source_sha256']=='83a13f9d42c49c6c6e22ad97534abe514081f7c3dd6a30da882147d8acd2dbde'and prior['standing_sha256']=='ba8a29554ad25716aad5a0697de7432b4a9f0631317799a8fb4a5fec74c0ea36'and prior['independent_current15']is True and prior['all_inherited_budget_and_original_refs_unchanged']is True and prior['Core_Cold_Hub_or_provider_mutation']is False,'RETAINED_M13_STANDING_CONFIG_AND_BUDGET_ORIGINALS')
 need(all(type(r)is dict and set(r)=={'path','sha256'}and type(r['path'])is str and Path(r['path']).is_absolute()and digest(r['sha256'])for r in(prior['actual_new_full120_ref'],prior['own_daemon_first_current15_ref'])),'RETAINED_M13_ORIGINAL_FULL120_AND_OWN15_REFS_NOT_NEW_QUALIFICATION')
 continuity=prior['continuity'];gaps=prior['conservative_per_role_gap_seconds'];need(type(continuity)is dict and continuity['peer']=='10.200.24.145'and continuity['port']==9447 and type(continuity['attempts'])is int and continuity['attempts']>0 and type(continuity['failure'])is int and continuity['failure']==0 and continuity['path_ok']==continuity['attempts']and type(gaps)is dict and len(gaps)==6 and all(type(v)is int and v==0 for v in gaps.values()),'RETAINED_M13_CONTINUITY_ZERO_GAPS_AND_NO_CORE_COLD_HUB_MUTATION')
 peer=c['continuity_peer_ipv4'];need(peer=='10.200.24.145'and old['continuity_peer_ipv4']==peer and str(ipaddress.IPv4Address(peer))==peer,'EXACT_RETAINED_CONTINUITY_PEER_EXISTING_NATIVE_CHECK_STILL_REQUIRED')
 ci_raw=read_ref(c['ci_attestation_ref']);ci=loads(ci_raw)
 need(type(ci)is dict and set(ci)=={'schema','commit','reviewed_by_root','runs'}and ci['schema']=='guardian_g15_exact_source_ci_v1'and ci['commit']==EXPECTED_HEAD and ci['reviewed_by_root']is True and type(ci['runs'])is list and len(ci['runs'])==len(roles),'ACTUAL_ROOT_EXISTING_CLOSED_CI_ATTESTATION_NO_AUTOMATIC_APPROVAL')
 need(all(type(r)is dict and set(r)=={'id','name','event','head_sha','status','conclusion','attempt'}and type(r['id'])is int and r['id']>0 and r['head_sha']==EXPECTED_HEAD and r['status']=='completed'and r['conclusion']=='success'and type(r['attempt'])is int and r['attempt']>=1 for r in ci['runs'])and len({r['id']for r in ci['runs']})==len(roles)and {(r['name'],r['event'])for r in ci['runs']}==roles,'ALL18_ACTUAL_REVIEWED_SOURCE_NAME_EVENT_RUNS_SUCCESS')
 controller_review=read_ref(c['root_controller_review_ref'],8192);standing_review=read_ref(c['root_standing_review_ref'],8192);unit=read_ref(c['controller_unit_ref'],32768)
 need(sha(controller_review)==CONTROLLER_REVIEW_SHA and sha(unit)==CONTROLLER_UNIT_SHA and len(standing_review.strip())>0,'EXACT_CONTROLLER_INPUTS_AND_REQUIRED_MANUAL_ROOT_STANDING_REVIEW')
 controller_review.decode('utf-8');standing_review.decode('utf-8')
 source_package=blob(PREFIX+'PACKAGE.json');runtime_data=loads(source_package);files={n:blob(PREFIX+n)for n in['source/'+n for n in modules]+['units/dakasa-capacity-network-cold-transport.service','units/dakasa-capacity-network-guardian.service']}
 pins={n:sha(b)for n,b in files.items()};source_pins=runtime_data['files'];need(set(source_pins)==set(pins)|{'README.md'}|{'tools/'+n for n in tools}and all(source_pins[n]==h for n,h in pins.items())and len(pins)==10 and runtime_data['controller_unit_sha256']==sha(unit),'EXACT_SOURCE15_TO_SEPARATE_RUNTIME_PACKAGE10')
 need(all(sha(blob(PREFIX+n))==h for n,h in source_pins.items()),'ALL_SOURCE_PACKAGE15_FILES_EXACT_GIT_BYTES')
 runtime_data['files']=pins;runtime=wire(runtime_data);inverse=loads(runtime);inverse['files']=source_pins;need(inverse==loads(source_package),'ONLY_PACKAGE_FILES_MAP_NARROWED_NO_METADATA_OR_AUTHORITY_FLAG_CHANGE')
 need(all(pins['source/'+n]==h for n,h in helpers.items()),'SEVEN_HELPERS_UNCHANGED')
 tool_data={n:blob(PREFIX+'tools/'+n)for n in tools};tool_pins={n:sha(b)for n,b in tool_data.items()}
 manifest={'schema':'guardian_g15pair_operational_package_v1','source_commit':EXPECTED_HEAD,'source_R':EXPECTED_R,'amd64_D':EXPECTED_D,'runtime_package_sha256':sha(runtime),'files':pins,'tools':tool_pins,'controller_unit_sha256':sha(unit),'root_controller_review_sha256':sha(controller_review),'root_standing_review_sha256':sha(standing_review),'expected_controller_identity':prior['controller'],'expected_guardian_identity':prior['guardian'],'protected_refs':refs,'ci_attestation':ci,'continuity_peer_ipv4':peer}
 need(len(manifest)==15,'EXISTING_CLOSED15_MANIFEST_ABI')
 payload={'PACKAGE.json':runtime,'MANIFEST.json':wire(manifest),'controller.service':unit,'ROOT-CONTROLLER-REVIEW.txt':controller_review,'ROOT-STANDING-REVIEW.txt':standing_review,**files,**{'tools/'+n:b for n,b in tool_data.items()}}
 os.umask(0o077);out.mkdir(mode=0o700,exist_ok=False)
 for name,raw in payload.items():
  p=out/name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True);fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
  need(p.read_bytes()==raw,'EXACT_ARTIFACT_READBACK')
 for folder in sorted([p for p in out.rglob('*')if p.is_dir()]+[out],key=lambda p:len(p.parts),reverse=True):
  fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:os.fsync(fd)
  finally:os.close(fd)
 print(json.dumps({'status':'EXTERNAL_ARTIFACT_PACKAGE_ASSEMBLED_NO_NATIVE_ACTION','out':str(out),'source_commit':EXPECTED_HEAD,'manifest_sha256':sha(payload['MANIFEST.json']),'source_PACKAGE_sha256':sha(source_package),'root_literal_binding_provenance':provenance,'external_runtime_PACKAGE_transform':'Only files map narrowed Root-bound Source15 to runtime10; qualified Git inert bytes and Root literal bindings are separately identified','runtime_files':len(files),'operational_tools':len(tools),'protected_refs':43,'standing_config_derived_locally':False,'actual_predecessor_identities_from_retained_M13_swap_not_current_health_claim':True,'continuity_still_requires_existing_Native_stage_check':True,'root_standing_review_was_input_not_generated':True,'files':{n:{'bytes':len(b),'sha256':sha(b)}for n,b in payload.items()}},sort_keys=True))
if __name__=='__main__':main()
