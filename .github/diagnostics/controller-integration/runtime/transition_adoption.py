"""R37 original read-adoption and explicit Root temporary connectivity.

Root authorization is a distinct 60-second connectivity operation. It grants
no capacity, observation freshness or continuous-window credit. Existing
static rules/handles are read-adopted; this module never sends an nft write.
Only Root's separate one-shot operator may apply render_transition_elements.
"""
import copy
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
import time


STATE=Path('/run/dakasa-capacity-network')
AUTH_PATH=STATE/'r37-connectivity-authority.json'
OLD_CONFIG=Path('/etc/dakasa/capacity-network/controller.r41.production.json')
NEW_CONFIG=Path('/etc/dakasa/capacity-network/controller.r42-cold-unknown184014.production.json')
SCHEMA='Root_network_transition_connectivity_v1'
ADOPTION_SCHEMA='capacity_owned_nft_original_read_adoption_v1'
COLLECTIONS={'core_ready4','prometheus_ready4','backend_forward4','backend_dnat4'}
RECEIPT_KEYS={'schema','operation_id','root_uid','boot_id','started_monotonic','deadline_monotonic','old_config_sha256','new_config_sha256','prestate_root_sha256','expected_handles','collections','Root_review'}
TABLE='dakasa_capacity_network'
SETS={'peers4','vips4','remote_vips4','core_ready4','prometheus_ready4','backend_forward4'}
CHAINS={'prerouting','input_guard','admit_new','forward_guard','output_guard','postrouting'}
class Held(Exception):pass
def require(ok,code):
    if not ok:raise Held(code)

def wire(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def number(v):return type(v)in(int,float)and math.isfinite(v)
def _unique(rows):
    result={}
    for k,v in rows:
        require(k not in result,'R37_NO_DUPLICATE_JSON_KEYS');result[k]=v
    return result
def loads(raw):return json.loads(raw,object_pairs_hook=_unique,parse_constant=lambda _:require(False,'R37_FINITE_JSON'))
def _hash(v):return type(v)is str and re.fullmatch('[a-f0-9]{64}',v)is not None

def _handles(value):
    require(type(value)is list and len(value)==47,'R37_EXACT_47_ACTUAL_HANDLES')
    result={}
    for row in value:
        require(type(row)is dict and set(row)=={'key','handle'} and type(row['key'])is list and all(type(v)is str for v in row['key']) and type(row['handle'])is int and row['handle']>0,'R37_TYPED_NATIVE_HANDLE')
        key=tuple(row['key']);require(key not in result,'R37_UNIQUE_NATIVE_OBJECT');result[key]=row['handle']
    require(sum(k[0]=='rule'for k in result)==33 and set(k for k in result if k[0]!='rule')=={('table',TABLE),*(('set',x)for x in SETS),('map','backend_dnat4'),*(('chain',x)for x in CHAINS)} and {k for k in result if k[0]=='rule'} and len({v for k,v in result.items()if k[0]in('rule','set','map')})==40,'R37_COMPLETE_UNIQUE_COMPILED_HANDLES')
    return result

def scope_of(snapshot):
    require(type(snapshot)is dict and snapshot.get('schema')=='root_original_R11_native_kernel_ms_snapshot_v1' and snapshot.get('all_four_backends_and_reverse_sources_positive')is True,'R37_CURRENT_COMPLETE_POSITIVE_SCOPE')
    rows=snapshot['dynamic_collections'];require(type(rows)is dict and set(rows)==COLLECTIONS,'R37_FOUR_COLLECTION_SCOPE_ONLY')
    result={}
    for name in sorted(COLLECTIONS):
        require(type(rows[name])is list,'R37_TYPED_SCOPE_ROWS')
        result[name]=sorted([{'value':v['value'],'target':v['target']}for v in rows[name]],key=wire)
    _validate_scope(result)
    return result

def _residual_scope(snapshot):
    rows=snapshot['dynamic_collections']
    result={name:sorted([{'value':v['value'],'target':v['target']}for v in rows[name]],key=wire)for name in sorted(COLLECTIONS)}
    _validate_scope(result,complete=False)
    return result

def _validate_scope(rows,*,complete=True):
    require(type(rows)is dict and set(rows)==COLLECTIONS,'R37_EXACT_FOUR_SCOPE_NAMES')
    for name,items in rows.items():
        require(type(items)is list and (1 if complete else 0)<=len(items)<=(8 if name=='core_ready4'else 1 if name=='prometheus_ready4'else 4) and len({wire(x)for x in items})==len(items),'R37_UNIQUE_BOUNDED_SCOPE')
        require(all(type(x)is dict and set(x)=={'value','target'} and type(x['value'])is str and(x['target']is None or type(x['target'])is str)for x in items),'R37_TYPED_SCOPE_VALUE_TARGET')
        require(items==sorted(items,key=wire),'R37_CANONICAL_SCOPE_ORDER')
    cores=rows['core_ready4'];prom=rows['prometheus_ready4'];dnat=rows['backend_dnat4'];forward=rows['backend_forward4']
    require(not complete or(len(dnat)==len(forward)==4 and len(prom)==1),'R37_COMPLETE_FIXED_BACKEND_SCOPE')
    for v in cores+prom:require(v['target']is None and str(ipaddress.IPv4Address(v['value']))==v['value'] and ipaddress.IPv4Address(v['value'])in ipaddress.IPv4Network('10.244.0.0/16'),'R37_CORE_PROM_CANONICAL_ADDRESS')
    require(not prom or prom[0]['value']not in {v['value']for v in cores},'R37_DISTINCT_REVERSE_ROLES')
    expected={'10.201.24.1 . 9443':('core','9443'),'10.201.24.1 . 5671':('broker','32674'),'10.201.24.2 . 5432':('rds','5432'),'10.201.24.3 . 6379':('redis','6379')}
    require({x['value']for x in dnat}<=set(expected) and(not complete or {x['value']for x in dnat}==set(expected)),'R37_EXACT_THREE_VIPS_FOUR_PORTS')
    joined=set()
    for v in dnat:
        target=(v['target']or'').split(' . ');role,port=expected[v['value']]
        require(len(target)==2 and target[1]==port and str(ipaddress.IPv4Address(target[0]))==target[0] and ipaddress.IPv4Address(target[0])in ipaddress.IPv4Network('10.244.0.0/16'if role=='core'else'172.18.0.0/16'),'R37_EXACT_BACKEND_ADDRESS_PORT_ROLE')
        if role=='core':require(target[0]in {v['value']for v in cores},'R37_CORE_FORWARD_REVERSE_JOIN')
        joined.add(v['value']+' . '+v['target'])
    require(all(v['target']is None for v in forward) and {v['value']for v in forward}==joined,'R37_EXACT_FORWARD_DNAT_SCOPE_JOIN')

def validate_receipt(receipt,new_config_sha,boot,now):
    require(type(receipt)is dict and set(receipt)==RECEIPT_KEYS and receipt['schema']==SCHEMA,'R37_CLOSED_ROOT_CONNECTIVITY_RECEIPT')
    require(type(receipt['root_uid'])is int and receipt['root_uid']==0 and type(receipt['operation_id'])is str and re.fullmatch('[a-f0-9]{20}',receipt['operation_id'])is not None,'R37_EXPLICIT_ROOT_OPERATION')
    require(type(boot)is str and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',boot)is not None and receipt['boot_id']==boot,'R37_SAME_ACTUAL_BOOT')
    require(all(_hash(receipt[k])for k in ('old_config_sha256','new_config_sha256','prestate_root_sha256')) and _hash(new_config_sha) and receipt['new_config_sha256']==new_config_sha and receipt['old_config_sha256']!=new_config_sha,'R37_EXACT_OLD_NEW_CONFIG_AND_PRESTATE_ROOT')
    start,end=receipt['started_monotonic'],receipt['deadline_monotonic']
    require(number(start)and number(end)and number(now)and 0<=start<=now<end and end-start==60.0,'R37_SINGLE_ORIGINAL_60_SECOND_MONOTONIC_BUDGET')
    require(type(receipt['Root_review'])is str and 120<=len(receipt['Root_review'])<=4096,'R37_EXPLICIT_REVIEWED_CONNECTIVITY_SCOPE')
    _handles(receipt['expected_handles']);_validate_scope(receipt['collections'])
    return receipt

def render_transition_elements(receipt,now):
    # Pure typed constructor; it cannot send. Root owns the one original send.
    validate_receipt(receipt,receipt['new_config_sha256'],receipt['boot_id'],now)
    milliseconds=math.floor(1000*(receipt['deadline_monotonic']-now-.250))
    require(0<milliseconds<=60000,'R37_NO_TEMPORARY_TIMEOUT_PAST_ORIGINAL_DEADLINE')
    lines=[]
    for name in ('core_ready4','prometheus_ready4','backend_forward4','backend_dnat4'):
        kind='map'if name=='backend_dnat4'else'set'
        lines.append('flush '+kind+' inet '+TABLE+' '+name)
        elements=[v['value']+' timeout '+str(milliseconds)+'ms'+(' : '+v['target']if v['target']is not None else'')for v in receipt['collections'][name]]
        lines.append('add element inet '+TABLE+' '+name+' { '+', '.join(elements)+' }')
    return ('\n'.join(lines)+'\n').encode()

def read_root(path,cap):
    path=Path(path);parent=path.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode)and parent.st_uid==0 and not stat.S_IMODE(parent.st_mode)&0o077 and not path.parent.is_symlink(),'R37_ROOT_PRIVATE_PARENT')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb')as f:
        a=os.fstat(f.fileno());raw=f.read(cap+1);b=os.fstat(f.fileno())
    require(stat.S_ISREG(a.st_mode)and a.st_uid==0 and a.st_nlink==1 and stat.S_IMODE(a.st_mode)==0o600 and 0<len(raw)==a.st_size<=cap and(a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns),'R37_ROOT0600_FULL_STABLE_ORIGINAL_FILE')
    return raw

def _boot():return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
def _ticks():
    raw=Path('/proc/self/stat').read_bytes();value=raw[raw.rfind(b')')+1:].split()[19]
    require(value.isdigit(),'R37_ACTUAL_CONTROLLER_START_TICKS');return int(value)
def _receipt(config_sha):
    try:raw=read_root(AUTH_PATH,32768)
    except FileNotFoundError:return None,None
    receipt=loads(raw);validate_receipt(receipt,config_sha,_boot(),time.monotonic())
    require(sha(read_root(OLD_CONFIG,32768))==receipt['old_config_sha256'] and sha(read_root(NEW_CONFIG,32768))==config_sha,'R37_ACTUAL_OLD_AND_NEW_CONFIG_BYTES')
    require(not (STATE/('r37-connectivity-closed-'+receipt['operation_id']+'.PUBLIC.json')).exists(),'R37_CLOSED_ROOT_OPERATION_NEVER_REPLAYED')
    return receipt,sha(raw)

def _duration(text,maximum=30000):
    import re
    parts=re.findall(r'([0-9]+)(ms|[dhms])',text)
    require(parts and ''.join(n+u for n,u in parts)==text and len({u for _,u in parts})==len(parts),'EXACT_NATIVE_TEXT_DURATION')
    value=sum(int(n)*{'d':86400000,'h':3600000,'m':60000,'s':1000,'ms':1}[u]for n,u in parts)
    require(0<=value<=maximum,'BOUNDED_NATIVE_TEXT_REMAINDER');return value

def kernel_text(raw,*,max_timeout_ms=30000):
    import ipaddress,re
    require(type(max_timeout_ms)is int and max_timeout_ms in(30000,60000),'R37_CLOSED_TIMEOUT_BOUND')
    require(type(raw)is bytes and 0<len(raw)<=262144,'BOUNDED_ORIGINAL_NATIVE_TABLE_TEXT')
    text=raw.decode('ascii');require(text.startswith('table inet dakasa_capacity_network { # handle '),'SAME_NATIVE_TABLE_TEXT_HEADER')
    found={}
    for kind,name,body in re.findall(r'^\t(set|map) ([a-z_0-9]+) \{[^\n]*\n(.*?)^\t\}',text,re.M|re.S):
        if name not in('core_ready4','prometheus_ready4','backend_forward4','backend_dnat4'):continue
        require(name not in found,'ONE_ORIGINAL_DYNAMIC_COLLECTION')
        elements=re.findall(r'elements = \{ ([^{}]*) \}',body)
        require(len(elements)<=1,'CLOSED_NATIVE_COLLECTION_ELEMENTS')
        rows=[]
        for value in elements[0].split(',')if elements else []:
            value=' '.join(value.split());m=re.fullmatch(r'(.+) timeout ([0-9a-z]+) expires ([0-9a-z]+)(?: : (.+))?',value)
            require(m is not None,'COMPLETE_NATIVE_TIMEOUT_AND_EXPIRY_TEXT')
            timeout,expires=_duration(m[2],max_timeout_ms),_duration(m[3],max_timeout_ms);require(expires<=timeout,'NATIVE_EXPIRY_NO_TIMEOUT_EXTENSION')
            rows.append({'value':m[1],'target':m[4],'timeout_ms':timeout,'expires_ms':expires})
        found[name]=rows
    require(set(found)=={'core_ready4','prometheus_ready4','backend_forward4','backend_dnat4'},'ALL_FOUR_DYNAMIC_COLLECTIONS_EXIST')
    cores,prom=found['core_ready4'],found['prometheus_ready4'];forward=found['backend_forward4'];dnat=found['backend_dnat4']
    require(len(cores)<=8 and len(prom)<=1 and len(forward)<=4 and len(dnat)<=4,'BOUNDED_NATIVE_DYNAMIC_COUNTS')
    for item in cores+prom:
        require(item['target']is None and ipaddress.IPv4Address(item['value'])in ipaddress.IPv4Network('10.244.0.0/16'),'SEPARATE_NATIVE_CORE_PROM_SOURCE_RANGE')
    require(not prom or prom[0]['value']not in{v['value']for v in cores},'SEPARATE_NATIVE_CORE_PROM_ROLES')
    expected={('10.201.24.1','9443'):('core','9443'),('10.201.24.1','5671'):('broker','32674'),('10.201.24.2','5432'):('rds','5432'),('10.201.24.3','6379'):('redis','6379')}
    kinds={};forward_values=set()
    for item in dnat:
        key=tuple(item['value'].split(' . '));target=tuple((item['target']or'').split(' . '))
        require(key in expected and len(target)==2,'ONLY_FOUR_FIXED_NATIVE_VIPS')
        role,port=expected[key];require(role not in kinds and target[1]==port and ipaddress.IPv4Address(target[0])in ipaddress.IPv4Network('10.244.0.0/16'if role=='core'else'172.18.0.0/16'),'FIXED_NATIVE_BACKEND_ROLE_AND_PORT')
        if role=='core':require(target[0]in{v['value']for v in cores},'NATIVE_CORE_REVERSE_AND_FORWARD_JOIN')
        kinds[role]=item;forward_values.add(' . '.join(key+target))
    require(all(v['target']is None for v in forward)and len({v['value']for v in forward})==len(forward)and {v['value']for v in forward}==forward_values,'SAME_NATIVE_FORWARD_AND_DNAT_TUPLES')
    positive=set(kinds)=={'core','broker','rds','redis'}and len(cores)>=1 and len(prom)==1 and all(v['expires_ms']>0 for rows in found.values()for v in rows)
    return {'schema':'root_original_R11_native_kernel_ms_snapshot_v1','all_four_backends_and_reverse_sources_positive':positive,'dynamic_collections':found,'minimum_actual_expires_ms':min((v['expires_ms']for rows in found.values()for v in rows),default=0)}


def _json_scope(rows,*,complete=True):
    found={}
    def value(v):
        if type(v)is str:return v
        require(type(v)is dict and set(v)=={'concat'} and type(v['concat'])is list and 2<=len(v['concat'])<=4,'R37_CLOSED_NATIVE_CONCAT')
        require(all(type(x)in(str,int)for x in v['concat']),'R37_TYPED_NATIVE_CONCAT')
        return ' . '.join(str(x)for x in v['concat'])
    for row in rows:
        kind=next(iter(row));data=row[kind];name=data.get('name')
        if kind not in('set','map')or name not in COLLECTIONS:continue
        entries=[]
        for item in data.get('elem',[]):
            target=None
            if kind=='map':
                require(type(item)is list and len(item)==2,'R37_CLOSED_NATIVE_MAP_ENTRY');item,target=item[0],value(item[1])
            require(type(item)is dict and set(item)=={'elem'} and type(item['elem'])is dict and set(item['elem'])=={'val','timeout','expires'},'R37_CLOSED_NATIVE_TIMEOUT_ENTRY')
            item=item['elem'];require(all(number(item[k])and 0<=item[k] for k in('timeout','expires')) and item['expires']<=item['timeout'],'R37_NATIVE_JSON_LIFETIME_BOUND')
            entries.append({'value':value(item['val']),'target':target})
        found[name]=sorted(entries,key=wire)
    _validate_scope(found,complete=complete);return found

def initialize(*,apply,_ownership,config_sha):
    import nft_owner as nft
    import native_structure as ns
    import native_io
    # Same-process original ownership token; never a disk/config structure pin.
    if not _ownership.exists:
        require(not AUTH_PATH.exists(),'R37_TEMPORARY_SCOPE_CANNOT_CREATE_ABSENT_TABLE')
        result,pin=nft.native_initialize_static(apply=apply,_ownership=_ownership)
        result['initial_structure_proof_kind']='original_native_apply_echo'
        return result,pin,None
    nft._consume_ownership(_ownership,.750)
    require(_hash(config_sha),'R37_ACTUAL_LOADED_CONFIG_HASH')
    receipt,receipt_sha=_receipt(config_sha)
    started=time.monotonic();reads=[]
    def original_json():
        out=nft.command(['/usr/sbin/nft','-j','list','ruleset'],role='ruleset_structure')
        require(out.returncode==0,'R37_ORIGINAL_FULL_NATIVE_READ0')
        rows,rules,origin=ns._objects(out.stdout,_with_origin=True)
        require(sha(ns._structure(rows,keep_handles=False))==ns.COMPILED_NATIVE_AST_SHA256,'R37_PRESENT_TABLE_EXACT_COMPILED_47_AST_NO_REPAIR')
        require(json.dumps(next(x['table']for x in rows if'table'in x),sort_keys=True,separators=(',',':'))==_ownership.header,'R37_SAME_ORIGINAL_NATIVE_TABLE_HEADER')
        nft.ruleset_mark_preflight(rules,_original_json=origin)
        reads.append({'sha256':sha(out.stdout),'bytes':len(out.stdout),'native_facts':native_io.last_facts()})
        return rows
    before=original_json()
    out=nft.command(['/usr/sbin/nft','-a','list','table','inet',TABLE],role='adopt_owned_text')
    require(out.returncode==0,'R37_ORIGINAL_NATIVE_DYNAMIC_TEXT_READ0')
    snapshot=kernel_text(out.stdout,max_timeout_ms=60000 if receipt is not None else 30000)
    text={'sha256':sha(out.stdout),'bytes':len(out.stdout),'native_facts':native_io.last_facts()}
    after=original_json();handles=ns._handles(after);scope=scope_of(snapshot)if receipt is not None else _residual_scope(snapshot)
    # JSON is used for tuple/handle bracketing only. Its numeric timer unit
    # is not assumed; the original native TEXT parser owns all ms bounds.
    require(handles==ns._handles(before) and _json_scope(before,complete=receipt is not None)==scope==_json_scope(after,complete=receipt is not None),'R37_STABLE_ORIGINAL_47_HANDLES_AND_FOUR_COLLECTION_SCOPE')
    if receipt is not None:
        validate_receipt(receipt,config_sha,_boot(),time.monotonic())
        require(handles==_handles(receipt['expected_handles']) and scope==receipt['collections'],'R37_ONLY_EXACT_ROOT_TRANSITION_SCOPE_READ_ADOPTED')
    returned=time.monotonic()
    pin=ns._OriginalStructure(handles,None,ns._CAPABILITY,proof_kind='original_owned_read_adoption',original_native_read_sha256=reads[-1]['sha256'])
    event={'schema':ADOPTION_SCHEMA,'phase':'existing_exact_47_read_adoption','initial_structure_proof_kind':'original_owned_read_adoption','applied':False,'native_mutations':0,'Core_or_VM_authority':False,'capacity_or_Core_freshness_credit':False,'read_started':started,'read_returned':returned,'compiled_native_ast_sha256':ns.COMPILED_NATIVE_AST_SHA256,'original_native_echo_handles':None,'original_native_read_handles':[{'key':list(k),'handle':v}for k,v in sorted(handles.items())],'original_native_reads':reads,'original_native_text_read':text,'preserved_dynamic_scope':scope,'preserved_minimum_actual_expires_ms':snapshot['minimum_actual_expires_ms'],'root_connectivity_receipt_sha256':receipt_sha,'temporary_connectivity_deadline':None if receipt is None else receipt['deadline_monotonic']}
    context=None if receipt is None else {'receipt':receipt,'receipt_sha256':receipt_sha,'adoption_returned':returned,'config_sha256':config_sha,'closed':False}
    return event,pin,context

def require_transition_live(context):
    if context is None or context['closed']:return
    validate_receipt(context['receipt'],context['config_sha256'],_boot(),time.monotonic())

def first_send_eligible(context,entries,cores,prom,errors,now):
    import nft_owner as nft
    if context is None or context['closed']:return True
    require_transition_live(context)
    return len(entries)==4 and {x.kind for x in entries}=={'core','broker','rds','redis'} and 1<=len(cores)<=8 and len(prom)==1 and errors=={} and all(x.observed_started>=context['adoption_returned'] and nft._kernel_remaining(x.expires,now,True,reserve_seconds=.250)>0 for x in(*entries,*cores,*prom))

def close_after_first_fresh_commit(context,result):
    import native_io
    if context is None or context['closed']:return None
    require_transition_live(context)
    require(result.get('schema')=='capacity_owned_nft_native_batch_v3' and result.get('phase')=='only_dynamic_elements' and result.get('applied')is True and result.get('Core_or_VM_authority')is False and result.get('held_native_read_classes')=={} and result.get('backends_admitted')==4 and result.get('prometheus_sources_admitted')==1 and set(result['backend_freshness'])=={'core','broker','rds','redis'} and 1<=len(result['core_source_freshness'])<=8 and len(result['prometheus_source_freshness'])==1,'R37_ONLY_GENUINE_FULL_FRESH_NORMAL_COMMIT_CLOSES_TRANSITION')
    started,returned=result['render_started'],result['native_apply_returned'];require(number(started)and number(returned)and context['adoption_returned']<=started<=returned<started+.250,'R37_ORIGINAL_FRESH_NORMAL_COMMIT_CLOCKS')
    for item in(*result['backend_freshness'].values(),*result['core_source_freshness'],*result['prometheus_source_freshness']):
        issued,expiry=item['original_started'],item['original_expires']
        require(context['adoption_returned']<=issued<=started and 0<expiry-issued<=30 and item['kernel_timeout_ms']==max(0,math.floor(1000*(expiry-started-.250))) and item['kernel_timeout_ms']>0,'R37_FRESH_NORMAL_LIFETIME_NOT_ROOT_CONNECTIVITY_CREDIT')
    facts=result['original_native_command_facts'];require(type(facts)is dict and facts.get('role')=='hot_dynamic_apply' and facts.get('closed_before_original_deadline_zero')is True and facts.get('stdin_sha256')==result['nft_source_sha256'],'R37_ORIGINAL_NORMAL_APPLY_CLOSED0')
    require(sha(read_root(AUTH_PATH,32768))==context['receipt_sha256'],'R37_SAME_ACTIVE_RECEIPT_BYTES_BEFORE_CLOSE')
    receipt=context['receipt'];closed={'schema':'Root_network_transition_connectivity_closed_v1','operation_id':receipt['operation_id'],'receipt_sha256':context['receipt_sha256'],'root_uid':os.geteuid(),'boot_id':_boot(),'controller_pid':os.getpid(),'controller_start_ticks':_ticks(),'old_config_sha256':receipt['old_config_sha256'],'new_config_sha256':receipt['new_config_sha256'],'prestate_root_sha256':receipt['prestate_root_sha256'],'normal_original_commit_sequence':result['commit_sequence'],'normal_original_commit_source_sha256':result['nft_source_sha256'],'normal_original_native_facts':facts,'normal_render_started':started,'normal_native_apply_returned':returned,'closed_monotonic':time.monotonic(),'temporary_authority_removed':True,'capacity_or_Core_freshness_credit':False}
    require(closed['root_uid']==0 and closed['closed_monotonic']<receipt['deadline_monotonic'],'R37_CLOSE_WITHIN_ORIGINAL_ROOT_CONNECTIVITY_DEADLINE')
    # The atomic normal commit already REPLACED all temporary map elements.
    # Remove/fsync the exact active file BEFORE claiming it was removed.
    require(sha(read_root(AUTH_PATH,32768))==context['receipt_sha256'],'R37_SAME_EXACT_ACTIVE_RECEIPT_REMOVED')
    AUTH_PATH.unlink();directory=os.open(STATE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)
    closed['closed_monotonic']=time.monotonic()
    require(closed['closed_monotonic']<receipt['deadline_monotonic'],'R37_ORIGINAL_DEADLINE_NOT_RENEWED_BY_CLOSE')
    native_io.process.once(STATE/('r37-connectivity-closed-'+receipt['operation_id']+'.PUBLIC.json'),closed)
    context['closed']=True
    return closed
