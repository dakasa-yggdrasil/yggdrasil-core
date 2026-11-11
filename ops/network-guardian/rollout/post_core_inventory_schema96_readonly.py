#!/usr/bin/env python3
"""INERT post-CoreR7/G15/schema96 operational READONLY observation.
Existing accepted operational reader, narrow successor only. No held S2 query,
provider authority, schema write, stage, PATCH, Root acceptance, N1 or E2E.
All actual rollout operands are supplied only after the real CAS/rollout.
"""
import argparse,base64,copy,datetime,hashlib,json,os,re,signal,stat,subprocess,sys,time,types
from pathlib import Path
CAP=1<<20
ROOT=Path('/var/lib/dakasa-core-rollout/g15pair')
SOURCE_BOUND=False
OPS_P = None
CAS_SOURCE_PATH=None
MANIFEST_SHA = None
CAS_RETURN_REF=None
SWAP_RETURN_REF = None
ROOT95_REF={'path': '/var/lib/dakasa-core-rollout/g14pair/goose95-r5-inputs-b684717e-c2d0-47db-a5d6-a5fea324a42d/ROOT95-ACCEPTANCE.PUBLIC.json', 'sha256': 'b80ec307962a67b8a28722c8fbf88add02c25de08847253fbae7838de1c0153d'}
ROOT96_REF=None
ROOT94_REF={'path': '/var/lib/dakasa-core-rollout/g12pair/goose94-r4-inputs-379aa02d-5ce5-4bf8-80e5-c9df4ec1898e/ROOT94-ACCEPTANCE.PUBLIC.json', 'sha256': '3ad88f1ada8cc96db0d6c6b0c3844a4de070e18f458cd6b053ab3a468b90c5e4'}
CORE14=None
CAS_CONFIG_REF=None
BUSINESS_LEDGER_PROJECTION=",\n'old_records',jsonb_build_object(\n 'forwards',(SELECT jsonb_build_object('rows',count(*),'sha256',encode(digest(COALESCE(jsonb_agg(to_jsonb(x) ORDER BY id,stage),'[]'::jsonb)::text,'sha256'),'hex')) FROM public.capacity_guest_retirement_forwards x),\n 'forward_reads',(SELECT jsonb_build_object('rows',count(*),'sha256',encode(digest(COALESCE(jsonb_agg(to_jsonb(x) ORDER BY id,stage),'[]'::jsonb)::text,'sha256'),'hex')) FROM public.capacity_guest_retirement_forward_reads x),\n 'http_dispositions',(SELECT jsonb_build_object('rows',count(*),'sha256',encode(digest(COALESCE(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb)::text,'sha256'),'hex')) FROM public.capacity_dispatch_http_maintenance_dispositions x))"
INDEX89_SQL="COALESCE((SELECT i.indisvalid AND i.indisready AND i.indislive AND NOT i.indisunique\n AND i.indrelid='public.workflow_runs'::regclass AND i.indnkeyatts=1 AND i.indnatts=1\n AND i.indpred IS NULL AND i.indexprs IS NULL AND a.amname='btree'\n AND pg_get_indexdef(i.indexrelid,1,false)='workflow_id'\n FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_am a ON a.oid=c.relam\n WHERE i.indexrelid=to_regclass('public.workflow_runs_workflow_id_idx')),false)"
CAS_SHA = None
CORE_R = None
CORE_D = None
M_PATH=Path('/var/lib/dakasa-core-rollout/traefik-cleanup-k3s-v3-2f25bdf7/cleanup_login_block_once_k3s_v3.py')
M_SHA='2f25bdf7b46c2ed9212d46c3547b40eecc5ad51d8cde345a099b9ec06748d2dd'
M_CONFIG=M_PATH.parent/'ROOT-CONFIG-K3S-V3.json'
M_CONFIG_SHA='dfdae8b9bb43706003b61f46e27d2f25c84578f2a4f642cac40c2f96b1812af2'
SERVICE='/api/v1/namespaces/dakasa/services/yggdrasil'
ENDPOINTS='/api/v1/namespaces/dakasa/endpoints/yggdrasil'
RS_BASE='/apis/apps/v1/namespaces/dakasa/replicasets/'

class Hold(RuntimeError):pass


def need(v,g):
 if not v:raise Hold(g)


def sha(b):return hashlib.sha256(b).hexdigest()


def closed(value,names,guard):
    need(type(value)is dict and set(value)==set(names.split()),guard)


def read_private(path, cap=CAP):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
             and stat.S_IMODE(before.st_mode) == 0o600, 'ROOT0600_REGULAR_PRIVATE_INPUT')
        raw = bytearray()
        while True:
            part = os.read(fd, min(65536, cap + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
            need(len(raw) <= cap, 'BOUNDED_PRIVATE_INPUT')
        after = os.fstat(fd)
        keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(all(getattr(before, k) == getattr(after, k) for k in keys), 'UNCHANGED_PRIVATE_INPUT')
        return bytes(raw)
    finally:
        os.close(fd)


def load(path,pin,name):
    raw=read_private(path);need(sha(raw)==pin,'EXACT_REVIEWED_DEFINITIONS')
    m=types.ModuleType(name);m.__file__=str(path);exec(compile(raw,str(path),'exec'),m.__dict__);return m


def ref(C,r,cap=32<<20):
    need(type(r)is dict and set(r)=={'path','sha256'} and Path(r['path']).is_absolute() and C.digest(r['sha256']),'CLOSED_REAL_PINNED_FILE_REF')
    b=C.read(Path(r['path']),cap,0o600);need(C.sha(b)==r['sha256'],'EXACT_ROOT_REVIEWED_ORIGINAL_REF');return b


def original_http(C,r):
    v=C.loads(ref(C,r));raw=base64.b64decode(v['raw_base64'],validate=True)
    need(v['status']==200 and v['framing_valid'] is True and len(raw)==v['raw_bytes'] and C.sha(raw)==v['raw_sha256'],'ORIGINAL_COMPLETE_METADATA_HTTP200')
    return raw


def saml_identity(M,raw):
    need(b'<!DOCTYPE'not in raw.upper() and b'<!ENTITY'not in raw.upper(),'BASELINE_SAML_NO_DTD')
    tree=M.ET.fromstring(raw);stable={'entity_id':tree.attrib['entityID'],'protocols':[],'certificates':[],'endpoints':[],'name_ids':[]}
    for e in tree.iter():
        local=e.tag.rsplit('}',1)[-1]
        if 'protocolSupportEnumeration'in e.attrib:stable['protocols'].append(e.attrib['protocolSupportEnumeration'])
        if local=='X509Certificate':stable['certificates'].append(''.join((e.text or '').split()))
        if local in ('SingleSignOnService','SingleLogoutService'):stable['endpoints'].append([local,sorted(e.attrib.items())])
        if local=='NameIDFormat':stable['name_ids'].append((e.text or '').strip())
    for k in ('protocols','certificates','endpoints','name_ids'):stable[k]=sorted(stable[k])
    need(stable['certificates'] and stable['endpoints'],'BASELINE_SAML_CERTIFICATES_AND_ENDPOINTS');return stable


def current_core(V,api,C,before,expected):
    d=api.get(V.DEP_URI);ps=api.get(V.PODS_URI);m=d['metadata'];s=d['status'];sp=d['spec']
    need(d['apiVersion']=='apps/v1' and d['kind']=='Deployment' and m['namespace']=='dakasa' and m['name']=='yggdrasil'
         and m['uid']==V.UID and m['generation']==expected['generation'] and not m.get('deletionTimestamp') and m['resourceVersion'].isdecimal(), 'EXACT_CURRENT_ROOT_OBSERVED_CORE_UID_GENERATION')
    need(sp.get('replicas',1)==1 and s['observedGeneration']==expected['generation'] and all(s.get(k)==1 for k in ('readyReplicas','updatedReplicas','availableReplicas'))
         and s.get('unavailableReplicas',0)==0 and len(ps['items'])==1,'EXACT_READY_SINGLETON_NEW_GENERATION')
    p=ps['items'][0];pm=p['metadata'];cs=p['status']['containerStatuses'];container=sp['template']['spec']['containers']
    need(pm['namespace']=='dakasa' and pm['uid']==expected['pod_uid'] and pm['uid']!=V.OLD_POD and not pm.get('deletionTimestamp') and p['status']['phase']=='Running'
         and len(container)==len(p['spec']['containers'])==len(cs)==1 and container[0]['name']=='core'
         and container[0]['image']==C.IMAGE_PREFIX+C.NEW_DIGEST and p['spec']['containers'][0]['name']=='core'
         and p['spec']['containers'][0]['image']==container[0]['image'] and cs[0]['name']=='core' and cs[0]['ready']is True
         and cs[0]['restartCount']==0 and cs[0].get('state',{}).get('running') and cs[0]['imageID'].rsplit(':',1)[-1]==C.NEW_DIGEST,'ACTUAL_NEW_READY_CORE_PLATFORM_ZERO_RESTART')
    owners=[x for x in pm.get('ownerReferences',[])if x.get('controller')is True]
    need(len(owners)==1 and owners[0]['apiVersion']=='apps/v1' and owners[0]['kind']=='ReplicaSet'
         and re.fullmatch('yggdrasil-[a-z0-9]{1,63}',owners[0]['name']),'ONE_SANITIZED_CONTROLLER_REPLICASET')
    rs=api.get(RS_BASE+owners[0]['name']);rm=rs['metadata'];ro=[x for x in rm.get('ownerReferences',[])if x.get('controller')is True]
    need(rs['apiVersion']=='apps/v1' and rs['kind']=='ReplicaSet' and rm['namespace']=='dakasa' and rm['uid']==owners[0]['uid']
         and not rm.get('deletionTimestamp') and len(ro)==1 and ro[0]['apiVersion']=='apps/v1' and ro[0]['kind']=='Deployment'
         and ro[0]['name']=='yggdrasil' and ro[0]['uid']==V.UID,'EXACT_POD_RS_DEPLOYMENT_OWNER_CHAIN')
    revision=rm.get('annotations',{}).get('deployment.kubernetes.io/revision')
    need(type(revision)is str and revision.isdecimal() and m['annotations'].get('deployment.kubernetes.io/revision')==revision,'CONTROLLER_REVISION_BOUND_TO_NEW_OWNED_RS')
    expected_spec=copy.deepcopy(before['spec']);expected_spec['template']['spec']['containers'][0]['image']=C.IMAGE_PREFIX+C.NEW_DIGEST
    need(sp==expected_spec,'FULL_DEPLOYMENT_SPEC_ONLY_CORE_IMAGE_CHANGED')
    annotations=copy.deepcopy(before['metadata']['annotations']);annotations['dakasa.io/core-source-commit']=V.CORE_R
    annotations['kubernetes.io/change-cause']=V.CHANGE_CAUSE;annotations['deployment.kubernetes.io/revision']=revision
    need(m['annotations']==annotations,'ONLY_SOURCE_CHANGECAUSE_AND_AUTHENTICATED_CONTROLLER_REVISION_ANNOTATIONS')
    em,bm=copy.deepcopy(m),copy.deepcopy(before['metadata']);bm['annotations']=annotations
    for key in ('resourceVersion','generation','managedFields'):em.pop(key,None);bm.pop(key,None)
    need(em==bm,'ALL_OTHER_DEPLOYMENT_METADATA_UNCHANGED')
    template=copy.deepcopy(rs['spec']['template']);podhash=template['metadata']['labels'].pop('pod-template-hash',None)
    need(podhash and pm.get('labels',{}).get('pod-template-hash')==podhash and template==sp['template']
         and all(pm.get('labels',{}).get(k)==v for k,v in sp['template']['metadata']['labels'].items()),'EXACT_NEW_RS_TEMPLATE_AND_POD_LABELS')
    need(rs['spec'].get('replicas',1)==1 and rs['status'].get('readyReplicas')==1 and rs['status'].get('availableReplicas')==1,'NEW_OWNED_RS_SINGLETON_READY')
    identity={'deployment_uid':V.UID,'generation':expected['generation'],'pod_uid':pm['uid'],'pod_name':pm['name'],'pod_ip':p['status']['podIP'],
                'node':p['spec']['nodeName'],'replicaset_uid':rm['uid'],'replicaset_name':rm['name'],'revision':revision,
                'image':container[0]['image'],'imageID':cs[0]['imageID'],'containerID':cs[0]['containerID'],
                'spec_sha256':C.sha(C.wire(sp)),'annotations_sha256':C.sha(C.wire(m['annotations'])),'pod_spec_sha256':C.sha(C.wire(p['spec']))}
    started=cs[0]['state']['running']['startedAt']
    need(type(started)is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})',started),'ACTUAL_ZONED_CONTAINER_START_LOWER_BOUND')
    metadata=lambda value:{k:v for k,v in value.items() if k not in('resourceVersion','managedFields')}
    actual14={'deployment_uid':V.UID,'generation':m['generation'],'replicaset_uid':rm['uid'],'replicaset_name':rm['name'],
        'pod_uid':pm['uid'],'pod_name':pm['name'],'container_id':cs[0]['containerID'],'container_started_at':started,
        'node_name':p['spec']['nodeName'],'deployment_metadata_sha256':C.sha(C.wire(metadata(m))),
        'replicaset_spec_sha256':C.sha(C.wire(rs['spec'])),'replicaset_metadata_sha256':C.sha(C.wire(metadata(rm))),
        'pod_spec_sha256':C.sha(C.wire(p['spec'])),'deployment_spec_sha256':C.sha(C.wire(sp))}
    need(actual14==expected,'EXACT_FOURTEEN_ROOT_ACTUAL_POST_CAS_CORE_FIELDS')
    return d,p,identity


def service_binding(api,M,C,baseline,pod):
    wanted=baseline['local_core_service'];service=api.get(SERVICE);sm=service['metadata'];ss=service['spec']
    need(service['apiVersion']=='v1' and service['kind']=='Service' and sm['namespace']=='dakasa' and sm['name']=='yggdrasil'
         and sm['uid']==wanted['uid'] and not sm.get('deletionTimestamp') and C.sha(C.wire(ss))==wanted['spec_sha256']
         and ss['clusterIP']==wanted['cluster_ip'] and ss['selector']==wanted['selector']
         and ss['ports']==[{'name':'http','port':9080,'protocol':'TCP','targetPort':'http'}],'EXACT_UNCHANGED_HTTP_SERVICE_SEPARATE_FROM_TLS_SERVICE')
    ep=api.get(ENDPOINTS);em=ep['metadata'];subs=ep.get('subsets',[])
    need(ep['apiVersion']=='v1' and ep['kind']=='Endpoints' and em['namespace']=='dakasa' and em['name']=='yggdrasil'
         and em['uid']==wanted['endpoint_uid'] and not em.get('deletionTimestamp') and len(subs)==1
         and set(subs[0])=={'addresses','ports'} and len(subs[0]['addresses'])==1
         and subs[0]['ports']==[{'name':'http','port':9080,'protocol':'TCP'}],'EXACT_CURRENT_SINGLE_READY_HTTP_ENDPOINT')
    address=subs[0]['addresses'][0];pm=pod['metadata']
    need(address['ip']==pod['status']['podIP'] and address.get('nodeName')==pod['spec']['nodeName']
         and address['targetRef']=={'kind':'Pod','name':pm['name'],'namespace':'dakasa','uid':pm['uid']},'HTTP_ENDPOINT_AUTHENTICATES_ACTUAL_NEW_POD')
    return ss['clusterIP']


def db_reference_projection(before,current):
    expected={name:{'configMapKeyRef':{'name':'yggdrasil-config','key':name}} for name in('DB_HOST','DB_NAME','DB_PORT','DB_USER')}
    expected['DB_PASSWORD']={'secretKeyRef':{'name':'yggdrasil-secrets','key':'DB_PASSWORD'}}
    inherited=[{'configMapRef':{'name':'yggdrasil-config'}},{'secretRef':{'name':'yggdrasil-secrets'}}]
    projections=[]
    for deployment in(before,current):
        container=deployment['spec']['template']['spec']['containers'][0];rows=container.get('env',[]);env={r['name']:r for r in rows}
        need(len(env)==len(rows),'NO_DUPLICATE_CORE_ENV_REFERENCES')
        for name,wanted in expected.items():
            if name in env:need(set(env[name])=={'name','valueFrom'} and env[name]['valueFrom']==wanted,'EXACT_CORE_DB_VALUEFROM_REFERENCE_ONLY')
        refs=container.get('envFrom',[])
        need(refs in([],inherited,list(reversed(inherited))) and (all(name in env for name in expected) or refs in(inherited,list(reversed(inherited)))),
            'ROOT_REVIEWED_CORE_DB_REFERENCE_SHAPE')
        projections.append({'envFrom':copy.deepcopy(refs),'explicit_DB_references':{name:copy.deepcopy(env[name]['valueFrom']) for name in expected if name in env}})
    need(projections[0]==projections[1],'DATABASE_REFERENCES_UNCHANGED_THROUGH_IMAGE_ONLY_PATCH')
    return projections[1]


LEGACY_CATALOG_SHA='c9d3664e43ef876a9a7a89c031bf75f761dbb0c70a664db2408058a6ce2431eb'
def catalog_sql(legacy, V):
    need(sha(legacy.encode()) == LEGACY_CATALOG_SHA and legacy.endswith(';\nCOMMIT;'), 'EXACT_REVIEWED_CATALOG_QUERY_OPERANDS')
    header, select = legacy.split('\nSELECT ', 1)
    select = select[:-len(';\nCOMMIT;')]
    return header + '\nWITH legacy AS (SELECT ' + select + ") SELECT jsonb_build_object('legacy',(SELECT * FROM legacy),'supplement',jsonb_build_object(" + """
'functions93',(SELECT COALESCE(jsonb_agg(jsonb_build_object('name',p.proname,'arguments',pg_get_function_identity_arguments(p.oid),'result',pg_get_function_result(p.oid),'language',l.lanname,'volatility',p.provolatile,'config',p.proconfig,'body',p.prosrc,'definition',pg_get_functiondef(p.oid)) ORDER BY p.proname),'[]'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='public' AND p.proname IN('guard_retirement_forward','guard_retirement_forward_read','guard_retirement_forward_delete_binding','retirement_forward_continuation_quiet','retirement_forward_continuation_valid')),
'columns90_91',(SELECT COALESCE(jsonb_agg(jsonb_build_object('table',a.attrelid::regclass::text,'name',a.attname,'number',a.attnum,'type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,'default',pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attrelid,a.attnum),'[]'::jsonb) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid IN('public.capacity_guest_retirement_forwards'::regclass,'public.capacity_guest_retirement_forward_reads'::regclass,'public.capacity_dispatch_http_maintenance_dispositions'::regclass) AND a.attnum>0 AND NOT a.attisdropped),
'index92_definition',(SELECT pg_get_indexdef(to_regclass('public.workflow_runs_busy_logical_idx'))),
'index92_valid',""" + V.workflow_busy_logical_index92_sql() + """
));
COMMIT;"""

def oneshots(cut):
    result = {}
    fixed = {cut.COLD: ('1861','a9e3007603694e08b5de045430e3abfd','17981074'),
             cut.HUB: ('14339','879eb7e50692482e9e4de2780b5f1179','45273170')}
    for unit, identity in fixed.items():
        p = cut.properties(unit)
        result[unit] = {k: p[k] for k in (*cut.IDENTITY_PROPS, 'NRestarts','ActiveState','SubState','Result')}
        need((p['ExecMainPID'], p['InvocationID'], p['ExecMainStartTimestampMonotonic']) == identity
             and p['MainPID'] == '0' and p['ActiveState'] == 'active' and p['SubState'] == 'exited'
             and p['Result'] == 'success' and p['NRestarts'] == '0', 'RETAINED_COLD_HUB_ONESHOTS_NO_EXECUTION')
    return result


def require_bound():
    # Every future Native observation is bound only after the real rollout.
    need(SOURCE_BOUND is True and type(CORE_R)is str and re.fullmatch('[a-f0-9]{40}',CORE_R)
        and type(CORE_D)is str and re.fullmatch('[a-f0-9]{64}',CORE_D)
        and type(CAS_SHA)is str and re.fullmatch('[a-f0-9]{64}',CAS_SHA)
        and type(OPS_P)is str and re.fullmatch('[a-f0-9]{40}',OPS_P)
        and type(CAS_SOURCE_PATH)is str and Path(CAS_SOURCE_PATH).is_absolute()
        and type(MANIFEST_SHA)is str and re.fullmatch('[a-f0-9]{64}',MANIFEST_SHA)
        and all(type(r)is dict and set(r)=={'path','sha256'} and type(r['path'])is str
            and Path(r['path']).is_absolute() and type(r['sha256'])is str and re.fullmatch('[a-f0-9]{64}',r['sha256'])
            for r in(CAS_RETURN_REF,SWAP_RETURN_REF,ROOT94_REF,ROOT95_REF,ROOT96_REF,CAS_CONFIG_REF))
        and type(CORE14)is dict and len(CORE14)==14,
        'INERT_ACTUAL_CAS_CORE14_G15_SWAP_AND_ROOT94_ROOT95_ROOT96_REQUIRED_BEFORE_IO')


def schema96(V,C,cut,run,cfg):
    # Revalidate immutable SAVED pre-PATCH inputs only. R7 may immediately
    # resume S8, so no live retirement, policy, slot or business ledger query.
    c,_,_=V.maintenance_inputs(C)
    need(c['acceptance_refs']['Root_Goose94_acceptance']==ROOT94_REF
        and c['acceptance_refs']['Root_Goose95_acceptance']==ROOT95_REF
        and c['acceptance_refs']['Root_Goose96_acceptance']==ROOT96_REF
        and all(c[key]==cfg[key] for key in ('prior93_history_ref','prior94_history_ref','prior95_history_ref',
            'schema94_catalog_ref','schema95_catalog_ref','schema96_catalog_ref','legacy_catalog_sql_ref')),
        'EXACT_ACTUAL_CAS_HISTORICAL94_95_ROOT96_AND_STABLE_CATALOG_INPUTS')
    legacy=ref(C,cfg['legacy_catalog_sql_ref']).decode()
    need(sha(legacy.encode())==LEGACY_CATALOG_SHA,'EXACT_IMMUTABLE_C9_QUERY')
    # Historical catalog94 names retain the full seven-key catalog at96.
    whole=V.catalog94_select(legacy)
    need(whole.count(BUSINESS_LEDGER_PROJECTION)==1,'EXACT_SHARED_QUERY_REMOVAL_ONLY_BUSINESS_LEDGER_PROJECTION')
    stable=whole.replace(BUSINESS_LEDGER_PROJECTION,'',1)
    sql="WITH stable(v) AS ("+stable+") SELECT jsonb_build_object('catalog',(SELECT v FROM stable),'index89_valid',"+INDEX89_SQL+",'rows92',(SELECT count(*) FROM public.goose_db_version WHERE version_id=92),'history_max_version',(SELECT max(version_id) FROM public.goose_db_version))"
    # Same RR/RO3s, lock .5s, process8: catalogs/history/index metadata only.
    result=V.query(cut,run,'CURRENT-STABLE-SCHEMA96-CATALOG-AND-HISTORY',sql)
    actual=result['catalog'];v=actual['legacy'];supplement=actual['supplement']
    facts={**v,'rows92':result['rows92'],'history_max_version':result['history_max_version']}
    old={'schema_facts':facts,'index89_valid':result['index89_valid'],
        'index92_valid':supplement['index92_valid'],'index92_definition':supplement['index92_definition']}
    V.schema96_facts(c,old,actual,C)
    out={'schema_version':96,'history96_sha256':C.sha(v['complete_history_wire'].encode()),
        'catalog96_sha256':C.sha(C.wire(V.catalog94_projection(actual))),
        'prior95_sha256':C.sha(ref(C,cfg['prior95_history_ref'])),
        'Root94_ref':ROOT94_REF,'Root95_ref':ROOT95_REF,'Root96_ref':ROOT96_REF,
        'business_ledger_rows_compared':False,'business_ledger_rows_queried':False}
    C.once(run/'SCHEMA96-CATALOG-ONLY.PUBLIC.json',C.wire(out));return out


def actual_process(cut,C,run,pod):
    # Exact accepted c99 kernel PID/executable/hostname read. Container start is
    # an honest lower bound; no exact Go wall-start instant is inferred.
    cmd='set -e\nexe="$(readlink /proc/1/exe)"\n[ "$exe" = /app/yggdrasil-core ]\npid="$(awk \'$1=="Pid:" {print $2; n++} END {if(n!=1) exit 1}\' /proc/1/status)"\n[ "$pid" -gt 0 ]\nhost="$(cat /proc/sys/kernel/hostname)"\ncase "$host" in \'\'|*[!A-Za-z0-9.-]*) exit 1;; esac\n[ "$(readlink /proc/1/exe)" = "$exe" ]\nprintf \'{"pid":%s,"hostname":"%s","executable":"/app/yggdrasil-core"}\\n\' "$pid" "$host"\n'
    result=subprocess.run(cut.KUBE+['-n','dakasa','exec',pod['metadata']['name'],'-c','core','--','/bin/sh','-ec',cmd],
        capture_output=True,timeout=12)
    C.once(run/'ACTUAL-PROCESS.stdout',result.stdout);C.once(run/'ACTUAL-PROCESS.stderr',result.stderr)
    need(result.returncode==0 and not result.stderr,'ACTUAL_KERNEL_PROCESS_READ_ZERO')
    proc=C.loads(result.stdout)
    need(set(proc)=={'pid','hostname','executable'} and type(proc['pid'])is int and proc['pid']>0
        and proc['hostname']==pod['metadata']['name'] and proc['executable']=='/app/yggdrasil-core',
        'ACTUAL_ACCEPTED_KERNEL_PID_HOSTNAME_EXECUTABLE')
    return {**proc,'started_at_lower_bound':pod['status']['containerStatuses'][0]['state']['running']['startedAt'],
        'exact_Go_wall_start_inferred':False}


def main():
    require_bound()
    parser=argparse.ArgumentParser(description=__doc__)
    for name in('config','evidence-dir'):parser.add_argument('--'+name,type=Path,required=True)
    for name in('expected-config-sha256','expected-script-sha256'):parser.add_argument('--'+name,required=True)
    a=parser.parse_args()
    def stop(sig,_):raise Hold('SIGNAL_'+str(sig)+'_READONLY_HOLD')
    for sig in(signal.SIGALRM,signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,stop)
    signal.alarm(210)
    need(os.geteuid()==0 and sys.platform=='linux' and sys.flags.optimize==0 and os.cpu_count()==4,'ROOT_LINUX_UNOPTIMIZED_SAME_FOUR_CPUS')
    need(sha(read_private(__file__))==a.expected_script_sha256,'EXACT_ROOT_REVIEWED_READER')
    raw=read_private(a.config);need(sha(raw)==a.expected_config_sha256,'EXACT_LATE_ROOT_CONFIG')
    V=load(Path(CAS_SOURCE_PATH),CAS_SHA,'readonly_actual_G15_CAS_definitions')
    V.CONFIG_REF=V.validated_config_ref(CAS_CONFIG_REF['path'],CAS_CONFIG_REF['sha256']);V.require_bound()
    package_path=ROOT.parent/('g15pair-package-'+MANIFEST_SHA)
    cut=V.load_tools(package_path);C=cut.C;cfg=C.loads(raw)
    closed(cfg,'schema ops_P cas_source_path manifest_sha256 cas_return swap_return Root94 Root95 Root96 cas_config_ref core14 metadata_before legacy_catalog_sql_ref prior93_history_ref prior94_history_ref prior95_history_ref schema94_catalog_ref schema95_catalog_ref schema96_catalog_ref','CLOSED_POST_CORE_R7_G15_SCHEMA96_CONFIG')
    need(cfg['schema']=='root_post_CoreR7_G15_schema96_readonly_config_v1' and cfg['ops_P']==OPS_P
        and cfg['cas_source_path']==CAS_SOURCE_PATH and cfg['manifest_sha256']==MANIFEST_SHA
        and cfg['cas_return']==CAS_RETURN_REF and cfg['swap_return']==SWAP_RETURN_REF and cfg['Root94']==ROOT94_REF and cfg['Root95']==ROOT95_REF and cfg['Root96']==ROOT96_REF
        and cfg['cas_config_ref']==CAS_CONFIG_REF and cfg['core14']==CORE14,'EXACT_LITERAL_ACTUAL_ROLLOUT_CONFIG')
    package,manifest=C.package(package_path,MANIFEST_SHA)
    need(manifest['source_commit']==OPS_P and manifest['files']['source/network_guardian.py']==V.SOURCE_PIN
        and manifest['tools']==V.TOOL_PINS and V.CORE_R==CORE_R==C.SOURCE_R and C.NEW_DIGEST==CORE_D,
        'ACTUAL_SEPARATELY_QUALIFIED_G15_PACKAGE_AND_CORE_R7')
    expected=cfg['core14']
    closed(expected,'deployment_uid generation replicaset_uid replicaset_name pod_uid pod_name container_id container_started_at node_name deployment_metadata_sha256 replicaset_spec_sha256 replicaset_metadata_sha256 pod_spec_sha256 deployment_spec_sha256','CLOSED_GENUINE_ACTUAL_CORE14')
    need(expected['deployment_uid']==V.UID and type(expected['generation'])is int and expected['generation']==V.GENERATION+1
        and V.full_id(expected['pod_uid']) and expected['pod_uid']!=V.OLD_POD,'ACTUAL_ROLLED_OUT_CORE_NOT_ASSUMED_GENERATION_OR_POD')
    rb=ref(C,CAS_RETURN_REF);returned=C.loads(rb);cas=Path(CAS_RETURN_REF['path']).parent
    need(Path(CAS_RETURN_REF['path']).name=='RETURN.PUBLIC.json' and cas.parent==ROOT
        and re.fullmatch('core-image-cas-[A-Za-z0-9_-]{1,96}',cas.name) and not(cas/'HOLD.PUBLIC.json').exists(),
        'ACTUAL_ACK_CAS_DIRECTORY_NO_HOLD_SUBSTITUTION')
    need(returned['schema']=='g15_core_image_cas_return_v1' and returned['status']=='PATCH_ACKNOWLEDGED_ACCEPTANCE_PENDING'
        and returned['deployment_uid']==V.UID and returned['generation']==expected['generation']
        and returned['Core_source']==CORE_R and returned['image']==C.IMAGE_PREFIX+CORE_D
        and returned['manifest_sha256']==MANIFEST_SHA and returned['G15_return_sha256']==SWAP_RETURN_REF['sha256']
        and returned['automatic_retry']is False and returned['new_pod_readiness_proven']is False
        and returned['post_rollout_G15_and_E2E_acceptance_proven']is False,'GENUINE_CAS_ACK_NOT_ROLLOUT_ACCEPTANCE')
    before=C.loads(C.read(cas/'DEPLOYMENT-BEFORE.json',16<<20,0o600))
    oldpods=C.loads(C.read(cas/'PODS-BEFORE.json',16<<20,0o600));V.core_before(before,oldpods,C)
    patch=C.read(cas/'PATCH.json',16<<20,0o600);ack=C.read(cas/'PATCH-ACTUAL-RETURN.json',16<<20,0o600)
    ah=C.loads(C.read(cas/'PATCH-ACTUAL-RETURN.HTTP.json',32768,0o600))
    need(ah['status']==200 and C.sha(patch)==returned['patch_sha256'] and C.loads(patch)==V.build_patch(before,C),
        'ORIGINAL_SINGLE_PATCH_200_EXACT_EIGHT_OPERATION_WIRE')
    V.result_shape(before,C.loads(ack),C)
    marker=C.loads(C.read(V.global_marker(C),32768,0o600))
    need(C.loads(C.read(cas/'POSSIBLE-SEND.json',32768,0o600))==marker
        and marker['script_sha256']==CAS_SHA and marker['patch_sha256']==C.sha(patch)
        and marker['manifest_sha256']==MANIFEST_SHA and marker['G15_return_sha256']==SWAP_RETURN_REF['sha256']
        and marker['evidence_dir']==str(cas) and marker['deployment_uid']==V.UID and marker['generation']==V.GENERATION
        and marker['resourceVersion']==before['metadata']['resourceVersion'],'ORIGINAL_GLOBAL_AND_RUN_MARKERS_NO_REPLAY')
    swap_path=Path(SWAP_RETURN_REF['path'])
    V.closed_g15_return_path(swap_path,C.STATE)
    swap_raw=ref(C,SWAP_RETURN_REF);swap=C.loads(swap_raw)
    need(swap_path.parent.parent==ROOT
        and re.fullmatch('swap-once-[A-Za-z0-9_-]{1,96}',swap_path.parent.name)
        and not(swap_path.parent/'HOLD.json').exists()
        and set(swap)=={'schema','status','result','automatic_replay','Guest_or_Core_business_authority'}
        and swap['schema']=='g15_pair_swap_return_v1' and swap['status']=='CONFIG_SWAP_OK'
        and swap['automatic_replay']is False and swap['Guest_or_Core_business_authority']is False,
        'REAL_CURRENT_G15_ORDINARY_SWAP_NOT_HISTORICAL_M6_REPAIR')
    lineage=C.loads(C.read(swap_path.parent/'BEFORE.json',32<<20,0o600))
    need(lineage['protected_refs']==V.required_protected_refs() and len(lineage['protected_refs'])==43,
        'EXACT_ORIGINAL43_REFS_AND_BUDGET_ONE_OF_THREE')
    M=load(M_PATH,M_SHA,'accepted_HTTP_metadata_readonly_definitions')
    mc=read_private(M_CONFIG);need(sha(mc)==M_CONFIG_SHA,'UNCHANGED_ACTUAL_HTTP_SERVICE_BASELINE');baseline=C.loads(mc)
    closed(cfg['metadata_before'],'ready oidc saml','CLOSED_ACCEPTED_ORIGINAL_METADATA_REFS')
    bm={key:original_http(C,cfg['metadata_before'][key])for key in('ready','oidc','saml')}
    run=a.evidence_dir.absolute()
    need(run.parent==ROOT and re.fullmatch('post-core-r7-readonly-[A-Za-z0-9_-]{1,80}',run.name),'NEW_EXCLUSIVE_READONLY_EVIDENCE_LEAF')
    C.private_dir(ROOT);C.private_dir(run,create=True)
    try:
        with V.operation_lock():
            sequence=0
            class API(V.API):
                def request(self,method,uri,body=None):
                    nonlocal sequence
                    need(method=='GET' and body is None and(uri in(V.DEP_URI,V.PODS_URI,SERVICE,ENDPOINTS,V.INVENTORY_DEP_URI,V.INVENTORY_SVC_URI,V.INVENTORY_PODS_URI)
                        or re.fullmatch(re.escape(RS_BASE)+'yggdrasil-[a-z0-9]{1,63}',uri)),
                        'FIXED_GET_ONLY_K3S_SCOPE_NO_MUTATION')
                    status,data,meta=super().request(method,uri,None);sequence+=1
                    # Full Core objects stay in RAM; never export env or secrets.
                    C.once(run/('K3S-GET-%03d.PUBLIC.json'%sequence),C.wire({'method':method,'uri':uri,'status':status,
                        'bytes':len(data),'sha256':C.sha(data),**meta,'raw_Kubernetes_objects_exported':False}))
                    return status,data,meta
                def get(self,uri):
                    status,data,meta=self.request('GET',uri);need(status==200,'COMPLETE_CURRENT_K3S_GET_200');return C.loads(data)
            api=API(cut)
            C.once(run/'INPUTS.PUBLIC.json',C.wire({'reader_sha256':a.expected_script_sha256,'config_sha256':a.expected_config_sha256,
                'CAS_ref':CAS_RETURN_REF,'G15_ref':SWAP_RETURN_REF,'Root94_ref':ROOT94_REF,'Root95_ref':ROOT95_REF,'Root96_ref':ROOT96_REF,'manifest_sha256':MANIFEST_SHA,'core14':expected}))
            initial_oneshots=oneshots(cut)
            d,pod,identity=current_core(V,api,C,before,expected)
            dbrefs=db_reference_projection(before,d);address=service_binding(api,M,C,baseline,pod)
            status,health=M.endpoint(api,cut,run,'CURRENT-DIRECT-HEALTH','/healthz',direct=address)
            need(status==200 and health==b'ok','ACTUAL_DIRECT_HEALTH_OK')
            metadata=M.metadata(api,cut,run,'CURRENT',address)
            need(metadata['ready']==C.loads(bm['ready']) and metadata['oidc']==C.loads(bm['oidc'])
                and metadata['saml_identity']==saml_identity(M,bm['saml']),
                'EXISTING_READY_OIDC_SAML_METADATA_IDENTITIES_PRESERVED')
            database=schema96(V,C,cut,run,cfg)
            saved_maintenance,_,_=V.maintenance_inputs(C)
            reader_receipt=V.deployment_ready_inputs(C,saved_maintenance)
            inventory=V.inventory_reader(api,C,run,'POST-CORE7',reader_receipt)
            process=actual_process(cut,C,run,pod)
            gd=run/'G15';C.private_dir(gd,create=True)
            backend,protected,ctrl,guard,observed=V.g15_acceptance(cut,package,manifest,swap,gd)
            need(protected==lineage['protected_refs'] and len(protected)==43,'SAME43_ORIGINAL_REFS_AND_BUDGET1')
            lastd,lastpod,lastidentity=current_core(V,api,C,before,expected)
            need(lastidentity==identity and db_reference_projection(before,lastd)==dbrefs
                and service_binding(api,M,C,baseline,lastpod)==address,'SAME_CORE_LIFETIME_DB_REFERENCES_AND_ENDPOINT_AT_CLOSURE')
            need(V.inventory_reader(api,C,run,'POST-CORE7-CLOSURE',reader_receipt)==inventory,'SAME_READER_INCARNATION_AND_METADATA_AT_CLOSURE')
            need(oneshots(cut)==initial_oneshots,'SAME_COMPLETED_COLD_HUB_LIFETIMES_NO_EXECUTION')
            backend.files(successor=True)
            need(backend.protected()==protected and cut.physical_identity(C.CTRL,cut.controller_argv(C.NEW_CONFIG))==ctrl
                and V.accepted_guardian(cut,swap)==guard,
                'SAME_G15_AUTHORITY_AND_LIFETIMES_AT_CLOSURE')
            need(time.monotonic()-observed<=15 and os.cpu_count()==4,'EXISTING_CURRENT15_FRESH_SAME_FOUR_CPUS')
            result={'schema':'independent_post_CoreR7_G15_schema96_readonly_observation_v1',
                'status':'READONLY_OBSERVATIONS_COMPLETE_ROOT_ACCEPTANCE_PENDING','observed_at':V.now(),
                'ops_P':OPS_P,'Core_source':CORE_R,'Core_image_D':CORE_D,'core14':expected,'core':identity,'core_process':process,
                'database_schema':database,'database_reference_projection':dbrefs,'inventory_readonly_reader':inventory,'direct_healthz_OK':True,
                'direct_ready_broker':metadata['ready'],'public_OIDC_issuer':metadata['oidc']['issuer'],'SAML_OIDC_identity_preserved':True,
                'G15_controller':ctrl,'G15_guardian':guard,'protected_ref_count':43,'recovery_budget_spent':1,
                'original_full120_and_own15_recomputed':True,'fresh_independent_current15_all4':True,'Brain_logical_cpus':4,
                'Cold_Hub_unchanged':True,'S2_or_business_ledger_frozen_or_queried':False,'native_mutations_sent':0,
                'CAS_RETURN_sha256':C.sha(rb),'evidence_dir':str(run),'Root_acceptance_created':False,
                'N1_or_E2E_or_ordinary_cycles_qualified':False}
            output=C.wire(result);need(len(output)<=20000,'BOUNDED_COMPLETE_PUBLIC_OBSERVATION')
            C.once(run/'RETURN.PUBLIC.json',output);print(output.decode(),end='',flush=True)
    except BaseException as error:
        result={'schema':'post_CoreR7_readonly_hold_v1','status':'READONLY_HOLD_NO_MUTATION_OR_RETRY',
            'error_class':type(error).__name__,'guard':str(error)if re.fullmatch('[A-Z0-9_]{1,160}',str(error))else'INCOMPLETE_OR_INCONSISTENT_READ',
            'native_mutations_sent':0}
        C.once(run/'HOLD.PUBLIC.json',C.wire(result));print(C.wire(result).decode(),end='',flush=True);raise SystemExit(20)from None

if __name__=='__main__':main()
