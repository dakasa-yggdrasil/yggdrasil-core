#!/usr/bin/env python3
"""INERT GET-only observation of a distinct pre-action readiness continuation.
Old337 Source/config/clock/HOLD are immutable custody, never renewed or credited.
No provider calls, ACK, dispatch, mutation, Root acceptance or cycle credit.
"""
import argparse,datetime,hashlib,json,os,re,signal,stat,sys,time,types,uuid
from pathlib import Path
SOURCE_BOUND = False
SOURCE_R = None
AMD64_D = None
CONFIG_REF = None
CAP = 8 << 20
SOURCE_CAP = 1 << 20
MAX_WATCH_SECONDS = 600
MAX_SAMPLES = 600
QUERY_PROCESS_BOUND_SECONDS = 8
PARENT = Path('/var/lib/dakasa-core-rollout')
JOB = '37edd909-fd96-46cc-bdc7-710a2573f5bf'
RUN = 'ef7dfb2d-c681-4574-a463-4d4a1c30e126'
OLD_WATCH_UUID = '33770bfe-91b1-4efb-86f5-2cba63d43192'

class Hold(RuntimeError): pass


def need(value,guard):
    if not value: raise Hold(guard)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def wire(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()


def loads(raw):
    def unique(rows):
        value={}
        for key,item in rows:
            need(key not in value,'NO_DUPLICATE_ORIGINAL_JSON_KEY');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(Hold('FINITE_ORIGINAL_JSON')))


def closed(value,names,guard):
    need(type(value)is dict and set(value)==set(names.split()),guard)


def read(path,cap=CAP):
    path=Path(path);need(path.is_absolute()and path.resolve(strict=True)==path,'CANONICAL_ROOT_ORIGINAL')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        a=os.fstat(fd)
        need(stat.S_ISREG(a.st_mode)and a.st_uid==0 and a.st_nlink==1
             and stat.S_IMODE(a.st_mode)==0o600 and a.st_size<=cap,'ROOT0600_FULL_ORIGINAL_CAP')
        parts=[];size=0
        while True:
            block=os.read(fd,min(65536,cap+1-size))
            if not block:break
            parts.append(block);size+=len(block);need(size<=cap,'BOUNDED_WHOLE_ORIGINAL')
        z=os.fstat(fd);n=path.lstat();key=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(key(a)==key(z)==key(n)and size==a.st_size,'STABLE_COMPLETE_ORIGINAL_NO_REENCODE')
        return b''.join(parts)
    finally:os.close(fd)


def ref(value,cap=CAP):
    closed(value,'path sha256','CLOSED_ROOT_BOUND_REFERENCE')
    need(type(value['path'])is str and Path(value['path']).is_absolute()
         and '..'not in Path(value['path']).parts and type(value['sha256'])is str
         and re.fullmatch('[a-f0-9]{64}',value['sha256'])is not None,'TYPED_WHOLE_REFERENCE')
    raw=read(value['path'],cap);need(sha(raw)==value['sha256'],'EXACT_WHOLE_ROOT_SOURCE_OR_DATA')
    return raw


def sync(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def put(path,raw):
    need(type(raw)is bytes and len(raw)<=CAP,'WHOLE_OUTPUT_WITHIN_CONSUMER8M_CAP')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        os.fchmod(fd,0o600);view=memoryview(raw)
        while view:
            n=os.write(fd,view);need(n>0,'FULL_EXCLUSIVE_WRITE');view=view[n:]
        os.fsync(fd)
    finally:os.close(fd)
    sync(path.parent);need(read(path)==raw,'SAME_BYTES_EXCLUSIVE_CUSTODY')
    return {'path':str(path),'sha256':sha(raw)}


def module(value,name):
    raw=ref(value,SOURCE_CAP);m=types.ModuleType(name);m.__file__=value['path']
    exec(compile(raw,m.__file__,'exec'),m.__dict__)
    return m


def old_watch_custody99(values):
    closed(values,'source config clock hold','CLOSED4_PERMANENT_OLD337_CUSTODY')
    pins={
      'source':'26ebc80b25dcdbca16020b37e1009f232c314116d6d0afb95de34830fbff581d',
      'config':'e1c48ada8fb845d0836f4a74acad4fa239ac34260b42c0baa31a3eea4aece6a1',
      'clock':'abd68019d87d959193ef7b093b7fd56f30fe1cf64175fcc388f6999b781c6d39',
      'hold':'ab0f65ec0bd9204c1453e8805b03cdbba2b1fe19a7001363d886f7246fada9f3'}
    raw={key:ref(values[key],SOURCE_CAP if key=='source' else CAP)for key in pins}
    need(all(values[key]['sha256']==pins[key]for key in pins),'PERMANENT_OLD337_ORIGINALS_NOT_REPLACED')
    cfg,clock,hold=(loads(raw[key])for key in('config','clock','hold'))
    need(cfg['watch_uuid']==OLD_WATCH_UUID and cfg['duration_seconds']==600
         and cfg['source_R']=='9f0266de7a2982352b7ff8fd627e73ceba12c896'
         and cfg['amd64_D']=='ed5ee3a2a5e90e54acc3cc2492fcc302a85e1b7adb6f545c605c5bfe2a730b42'
         and clock['duration_seconds']==600 and clock['maximum_samples']==600
         and clock['clock_renewal_or_business_deadline_extension']is False
         and hold['status']=='HOLD_NO_PROMOTION_CREDIT'
         and hold['guard']=='FINITE_SAMPLE_BOUND_WITHOUT_PROMOTION_ORIGINAL'
         and hold['samples']==600,'OLD337_HOLD_HAS_NO_PROMOTION_CREDIT_OR_RENEWAL')
    return raw

def phase99(value,shared,case):
    closed(value,'schema observed_at installed_recovery preaction_dispositions','EXACT99_CONTINUATION_SNAPSHOT4')
    need(value['schema']=='recovered_preaction_plan_continuation_v1','DISTINCT99_CONTINUATION_NOT_OLD337')
    v=value['installed_recovery']
    closed(v,'schema observed_at disposition current_job current_run readiness_job readiness_run current_intent_wire member_grants current_slots predicate_valid','EXACT99_INSTALLED_COMPONENT11')
    need(v['schema']=='recovered_installed_G44_originals_readonly_v1' and v['predicate_valid']is True,
         'AUTHENTIC_M98_HISTORICAL_PROOF')
    d=v['disposition'];need(type(d)is dict and d['id']==case['root_anchor_id'] and d['job_id']==JOB and d['run_id']==RUN,
                           'EXACT99_M98_ROOT_ANCHOR')
    intent=shared.loads(v['current_intent_wire'])
    need(type(intent)is dict and type(intent['generation'])is int and intent['generation']==44,
         'G44_CONTINUATION_CANNOT_INFER_A_LATER_EPOCH')
    marker=intent.get('installed_guest_reconcile');job=v['readiness_job'];run=v['readiness_run']
    return {'phase':intent['phase'],'generation':intent['generation'],'fence':intent['fencing_token'],
            'disposition_id':d['id'],'typed_preaction_receipts':len(value['preaction_dispositions']),
            'readiness_run_id':marker.get('new_run_id')if type(marker)is dict else None,
            'run_status':run.get('status')if type(run)is dict else None,
            'ACK':bool(type(job)is dict and job.get('finalization_ack_at')is not None)}

def complete99(value,observed):
    v=value['installed_recovery'];job,run=v['readiness_job'],v['readiness_run']
    return bool(observed['phase']=='promoted' and type(job)is dict and type(run)is dict
        and job.get('state')=='returned' and job.get('return_status')=='succeeded'
        and job.get('finalization_ack_at')is not None and job.get('returned_at')is not None
        and run.get('status')=='succeeded' and run.get('finished_at')is not None)

def main():
    need(SOURCE_BOUND is True and type(SOURCE_R)is str and re.fullmatch('[a-f0-9]{40}',SOURCE_R)and SOURCE_R!='0'*40
         and type(AMD64_D)is str and re.fullmatch('[a-f0-9]{64}',AMD64_D)and AMD64_D!='0'*64
         and type(CONFIG_REF)is dict,'INERT_BEFORE_ANY_IO_OR_HELPER_LOAD')
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--expected-script-sha256',required=True);a=p.parse_args()
    need(sys.platform=='linux'and os.geteuid()==0,'ROOT_NATIVE_ONLY')
    source=ref({'path':str(Path(__file__).absolute()),'sha256':a.expected_script_sha256},SOURCE_CAP)
    cfgraw=ref(CONFIG_REF);cfg=loads(cfgraw)
    closed(cfg,'schema reviewed_by_root source_R amd64_D query_source_ref query_source_qualification_ref query_config_ref package_manifest_ref shared_source_ref watch_uuid duration_seconds poll_seconds restore99_source_ref catalog99_source_ref preaction_preimage_ref preaction_case old_watch_refs','CLOSED17_OBSERVER99_INPUTS')
    need(cfg['schema']=='root_preaction_readiness_continuation_readonly_watch_v1'and cfg['reviewed_by_root']is True
         and cfg['source_R']==SOURCE_R and cfg['amd64_D']==AMD64_D,'ACTUAL_ROOT99_READONLY_TARGET_BINDING')
    need(type(cfg['watch_uuid'])is str and str(uuid.UUID(cfg['watch_uuid']))==cfg['watch_uuid']
         and uuid.UUID(cfg['watch_uuid']).int!=0 and cfg['watch_uuid']!=OLD_WATCH_UUID,'DISTINCT_NEW99_OBSERVATION_LEAF')
    need(type(cfg['duration_seconds'])is int and 9<=cfg['duration_seconds']<=MAX_WATCH_SECONDS
         and type(cfg['poll_seconds'])in(int,float)and cfg['poll_seconds']in(0.5,1,2),'FINITE_NEW99_ORIGINAL_OBSERVER_CLOCK')
    need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'NO_INHERITED_ALARM')
    old_custody=old_watch_custody99(cfg['old_watch_refs'])
    qualification_raw=ref(cfg['query_source_qualification_ref'])
    query_config_raw=ref(cfg['query_config_ref']);manifest_raw=ref(cfg['package_manifest_ref'])
    V=module(cfg['query_source_ref'],'qualified_Core10_readonly_query_definitions')
    O=module(cfg['shared_source_ref'],'frozen_recovered_M98_original_definitions')
    R=module(cfg['restore99_source_ref'],'frozen_preaction99_continuation_definitions')
    H=module(cfg['catalog99_source_ref'],'qualified_preaction99_catalog_definitions')
    need(V.SOURCE_BOUND is True and V.CORE_R==SOURCE_R and V.NEW_DIGEST==AMD64_D,
         'REVIEWED_CORE10_QUERY_NAMESPACE_NOT_A_MAIN_CALL')
    need(R.SOURCE_BOUND is False and R.QUALIFIED_SOURCE is None
         and H.SOURCE_BOUND is False and H.QUALIFIED_SOURCE is None and R.M99==H.M99
         and O.SOURCE_BOUND is False and O.QUALIFIED_SOURCE is None
         and sha(ref(cfg['shared_source_ref'],SOURCE_CAP))==R.RESTORE98_SHA
         and V.CATALOG99_HELPER_REF==cfg['catalog99_source_ref'],'EXACT_PURE99_AND_OLD98_DEFINITIONS')
    preimage=loads(ref(cfg['preaction_preimage_ref']));H.validate_preaction99(preimage,cfg['preaction_case'])
    manifest=loads(manifest_raw);package=Path(cfg['package_manifest_ref']['path']).parent
    need(Path(cfg['package_manifest_ref']['path']).name=='MANIFEST.json'
         and manifest['source_R']==SOURCE_R and manifest['amd64_D']==AMD64_D,'SAME_QUALIFIED_CORE10_PACKAGE')
    V.CONFIG_REF=V.validated_config_ref(cfg['query_config_ref']['path'],cfg['query_config_ref']['sha256'])
    V.require_bound();cut=V.load_tools(package)
    need(cut.C.sha(cut.C.read(Path(cfg['package_manifest_ref']['path']),CAP,0o600))==sha(manifest_raw),
         'UNCHANGED_WHOLE_PACKAGE_MANIFEST')
    need(PARENT.resolve(strict=True)==PARENT,'CANONICAL_NATIVE_PARENT')
    st=PARENT.lstat();need(st.st_uid==0 and stat.S_ISDIR(st.st_mode)and not stat.S_IMODE(st.st_mode)&0o022,
                           'ROOT_NONWRITABLE_PARENT')
    os.umask(0o077);out=PARENT/('preaction-readiness-readonly-watch-'+cfg['watch_uuid'])
    out.mkdir(mode=0o700,exist_ok=False);sync(PARENT)
    put(out/'INPUTS.original.json',cfgraw);put(out/'WATCH.Source.same-SHA.py',source)
    for key,raw in old_custody.items():put(out/('OLD337-'+key+'.same-SHA.original'),raw)
    put(out/'QUERY-SOURCE-QUALIFICATION.original.json',qualification_raw)
    put(out/'QUERY-CONFIG.original.json',query_config_raw);put(out/'PACKAGE-MANIFEST.original.json',manifest_raw)
    query=R.continuation_sql99(O);put(out/'QUERY.EXACT.Source.sql',query.encode())
    started=datetime.datetime.now(datetime.timezone.utc);start_ns=time.monotonic_ns()
    deadline_ns=start_ns+cfg['duration_seconds']*1_000_000_000
    put(out/'ORIGINAL-WATCH-CLOCK.PUBLIC.json',wire({'schema':'preaction_readiness_observation_original_clock_v1',
        'started_at':started.isoformat(),'started_monotonic_ns':start_ns,'deadline_monotonic_ns':deadline_ns,
        'duration_seconds':cfg['duration_seconds'],'maximum_samples':MAX_SAMPLES,
        'old337_clock_modified':False,'clock_renewal_or_business_deadline_extension':False}))
    previous=signal.getsignal(signal.SIGALRM)
    def expired(_signum,_frame):raise Hold('ORIGINAL_OBSERVER99_DEADLINE_EXPIRED')
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,cfg['duration_seconds'])
    seen=None;transitions=0;samples=0;result=None
    try:
        for sequence in range(1,MAX_SAMPLES+1):
            need(time.monotonic_ns()+QUERY_PROCESS_BOUND_SECONDS*1_000_000_000<deadline_ns,
                 'ORIGINAL_OBSERVER_WINDOW_CANNOT_START_ANOTHER_WHOLE8S_READ')
            label='PREACTION99-READ-'+str(sequence).zfill(6)
            value=V.query(cut,out,label,query);path=out/(label+'.stdout');raw=read(path)
            need(loads(raw)==value,'WHOLE99_QUERY_ORIGINAL_EQUALS_PARSED_SNAPSHOT')
            original={'path':str(path),'sha256':sha(raw)};samples=sequence
            observed=phase99(value,O,cfg['preaction_case'])
            if observed!=seen:
                transitions+=1;put(out/('PHASE-'+str(transitions).zfill(6)+'.PUBLIC.json'),wire({
                    'sequence':sequence,'observed_at_core':value['observed_at'],'state':observed,
                    'whole_original_ref':original,'whole_original_bytes':len(raw),'acceptance':False}))
                seen=observed
            if complete99(value,observed):
                component=R.member_wire99(raw,'installed_recovery')
                component_ref=put(out/'M98-READINESS-COMPONENT.original.json',component)
                validated=R.promotion99(value,cfg['preaction_case'],preimage,O,H,original,component_ref)
                O.saved_recovery(validated['installed_timeout_recovery'],lambda r:ref(r))
                need(time.monotonic_ns()<deadline_ns,'CONTINUATION_ORIGINAL_WITHIN_OWN_ORIGINAL_WINDOW')
                saved=put(out/'FIRST-CONTINUATION-PROMOTION-ACK.original.json',raw)
                expected={'schema':'root_saved_preaction_continuation_originals_v1',
                    'whole_continuation_original_ref':saved,'installed_timeout_recovery':validated['installed_timeout_recovery']}
                result={'schema':'preaction_readiness_continuation_observation_v1',
                    'status':'ORIGINAL_CAPTURED_ROOT_REVIEW_PENDING','watch_uuid':cfg['watch_uuid'],
                    'expected_target_source_R':SOURCE_R,'expected_target_amd64_D':AMD64_D,
                    'old337_original_refs':cfg['old_watch_refs'],'old337_status':'HOLD_NO_PROMOTION_CREDIT',
                    'old337_clock_modified':False,'original_query_ref':original,'saved_continuation_original_ref':saved,
                    'whole_original_bytes':len(raw),'actual_snapshot_observed_at_core':value['observed_at'],
                    'validated_original_join':validated,'candidate_restore99_bindings':expected,
                    'candidate_bindings_reviewed_by_root':False,'samples':samples,'phase_changes':transitions,
                    'elapsed_seconds':(time.monotonic_ns()-start_ns)/1_000_000_000,
                    'Root_acceptance_created':False,'workflow_or_recovery_authority_created':False,
                    'CAS_or_business_API_or_SDK_calls':0,'business_or_guest_or_provider_mutations':0,
                    'original_unknown_failure_or_ACK_rewritten':False,'later_markerfree_success_inferred':False}
                put(out/'RESULT.PUBLIC.json',wire(result));break
            remaining=(deadline_ns-time.monotonic_ns())/1_000_000_000
            need(remaining>cfg['poll_seconds']+QUERY_PROCESS_BOUND_SECONDS,'ORIGINAL_OBSERVER_WINDOW_EXHAUSTED')
            time.sleep(cfg['poll_seconds'])
        need(result is not None,'FINITE_SAMPLE_BOUND_WITHOUT_CONTINUATION_ORIGINAL')
    except BaseException as error:
        signal.setitimer(signal.ITIMER_REAL,0)
        result={'schema':'preaction_readiness_continuation_observation_v1','status':'HOLD_NO_PROMOTION_CREDIT',
                'error_class':type(error).__name__,'guard':str(error)if isinstance(error,(Hold,R.Hold,O.Hold,V.Hold,RuntimeError))else None,
                'samples':samples,'phase_changes':transitions,'last_observed_state':seen,
                'old337_original_refs':cfg['old_watch_refs'],'old337_status':'HOLD_NO_PROMOTION_CREDIT','old337_clock_modified':False,
                'Root_acceptance_created':False,'workflow_or_recovery_authority_created':False,
                'CAS_or_business_API_or_SDK_calls':0,'business_or_guest_or_provider_mutations':0,
                'original_unknown_failure_or_ACK_rewritten':False,'later_markerfree_success_inferred':False}
        put(out/'HOLD.PUBLIC.json',wire(result))
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
    summary=wire({**result,'directory':str(out),'all_query_originals_retained':True})
    need(len(summary)<23000,'BOUNDED_SUMMARY_ONLY_NO_RAW_WIRE_EXPORT')
    sys.stdout.buffer.write(summary);sys.stdout.buffer.flush()
    return 0 if result['status']=='ORIGINAL_CAPTURED_ROOT_REVIEW_PENDING' else 30

if __name__=='__main__': raise SystemExit(main())
