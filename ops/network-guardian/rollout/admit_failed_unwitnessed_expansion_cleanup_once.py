#!/usr/bin/env python3
"""Inert Root-only ONE failed-A3 unwitnessed expansion cleanup admission.

POST supplies only the existing grant/job UUIDs. The server owns every94
eligibility check, finite owner, normal one-send child and native/read proof.
This client sends no SDK, SQL, Guest, workflow, policy or native request.
Unknown POST acknowledgement consumes the local claim forever; GET-only
reconciliation is separate and never relabelled as an original201.
"""
import argparse,base64,copy,datetime,hashlib,http.client,http.cookiejar,json,os,re,signal,stat,time,urllib.parse,urllib.request,uuid
from pathlib import Path

PREP=Path('/Volumes/DaKasa/Users/dakasa/projects/dakasa/yggdrasil/yggdrasil-core/docs/superpowers/elastic-codex-20261102/new-native-pending-continuation-source-20261104/FAILED-A3-M94-CLEANUP-INERT-PREP')
STATE=PREP/'STATE'
ORIGIN='https://yggdrasil.dakasa.me'
AUTH='/api/v1/auth/session'
POST_URI='/api/v1/ops/capacity/failed-unwitnessed-expansion-cleanups'
GRANT='c117f03f-27db-4da2-b990-c2729f98a46f'
JOB='71001a02-6e60-4df1-aef7-b25cf9e07aa5'
RUN='efad3324-4280-4928-b2e0-becc7eda08a9'
PRE='4677b2cf-9cfa-4218-bc3d-930de13591a8'
RESOURCE='i-074579943eddcf392'
BIRTH='2026-11-05T00:20:14Z'
GET_URI=POST_URI+'/'+GRANT
CLAIM_NAME='FAILED-UNWITNESSED-EXPANSION-CLEANUP-'+GRANT+'-'+JOB+'-POSSIBLE.json'
CAP=1<<20
ARTIFACT_CAP=8<<20
SOURCE_BOUND=False
R4_SOURCE=None
R4_IMAGE_D=None
G13_OPS_SOURCE=None
ROOT94_REF=None
CORE_OPERATIONAL_REF=None
G13_OPERATIONAL_REF=None
FOUR_E2ES_REF=None
EXPECTED_OPERATOR_ID=None
FAILURE_REF={'path':str(PREP.parent/'AWS-TRIAL3-CREATE-FAILURE-READONLY/ROOT-FAILED-CLEAN-CYCLE.PUBLIC.json'),'sha256':'e17541b6ae225406625568635ad76c54cedd6d6a0ea22cc73742c44080ac6f87'}
SUMMARY_KEYS=set('schema id grant_id child_grant_id job_id run_id preregistration_id stage event_count slot resource_id resource_created_at original_auxiliary_inventory_complete original_SDK_return_sha256 original_guest_success clean_cycle_credit serving_or_business_or_savings_authority'.split())
STAGES={'requested','claimed','inventory_prepared','inventory_returned','inventory_qualified','issued','possible_send','pending_absence','absence_prepared','absence_returned','absence_complete','terminal'}


class Hold(RuntimeError):
    pass

def need(value, guard):
    if not value:
        raise Hold(guard)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def wire(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def loads(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'NO_DUPLICATE_JSON_KEYS')
            result[key] = value
        return result
    def invalid(_):
        raise Hold('FINITE_JSON_ONLY')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)

def digest(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None

def identifier(value):
    try:
        return type(value) is str and str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0
    except (ValueError, AttributeError):
        return False

def rfc3339_timestamp(value):
    if type(value) is not str:
        return False
    match = re.fullmatch(r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])', value)
    if match is None:
        return False
    base, fraction, zone = match.groups()
    # Normalize only a validation copy: Python3.9 accepts 3/6 fractional digits;
    # Go emits 1..9. Original row strings, bytes, hashes and comparisons stay exact.
    parsed_input = base + ('.' + (fraction + '000000')[:6] if fraction else '') + ('+00:00' if zone == 'Z' else zone)
    try:
        return datetime.datetime.fromisoformat(parsed_input).tzinfo is not None
    except ValueError:
        return False

def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def directory(path, private):
    need(path.resolve(strict=True) == path, 'CANONICAL_DIRECTORY')
    s = path.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == os.geteuid()
         and (stat.S_IMODE(s.st_mode) == 0o700 if private else not stat.S_IMODE(s.st_mode) & 0o022), 'SAFE_OWNED_DIRECTORY')

def read(path, private=True, cap=ARTIFACT_CAP):
    path = Path(path).absolute()
    need(path.resolve(strict=True) == path, 'CANONICAL_EXISTING_FILE')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        a = os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_uid == os.geteuid() and a.st_nlink == 1
             and (stat.S_IMODE(a.st_mode) == 0o600 if private else not stat.S_IMODE(a.st_mode) & 0o022)
             and 0 < a.st_size <= cap, 'SAFE_BOUNDED_OWNED_FILE')
        chunks, size = [], 0
        while True:
            part = os.read(fd, min(65536, cap + 1 - size))
            if not part:
                break
            size += len(part)
            need(size <= cap, 'FILE_CAP')
            chunks.append(part)
        b = os.fstat(fd)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(fields(a) == fields(b) and size == a.st_size, 'STABLE_COMPLETE_FILE')
        return b''.join(chunks)
    finally:
        os.close(fd)

def put(folder, name, raw):
    need('/' not in name and name not in ('', '.', '..'), 'FIXED_EVIDENCE_BASENAME')
    need(type(raw) is bytes and 0 < len(raw) <= ARTIFACT_CAP, 'BOUNDED_LOCAL_ARTIFACT')
    directory(folder, True)
    fd = os.open(folder / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        remaining = memoryview(raw)
        while remaining:
            n = os.write(fd, remaining)
            need(n > 0, 'COMPLETE_EVIDENCE_WRITE')
            remaining = remaining[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    sync(folder)
    need(read(folder / name) == raw, 'EXACT_DURABLE_READBACK')

def new_evidence(path):
    path = Path(path).absolute()
    need(path.parent == PREP and path.name != 'STATE', 'NEW_EVIDENCE_LEAF_UNDER_FIXED_PREP')
    path.mkdir(mode=0o700, exist_ok=False)
    sync(PREP)
    directory(path, True)
    return path

def ref(value,pin=None):
    need(type(value)is dict and set(value)=={'path','sha256'}and digest(value['sha256'])and (pin is None or value['sha256']==pin),'CLOSED_PINNED_ROOT_REFERENCE')
    raw=read(Path(value['path']));need(sha(raw)==value['sha256'],'ACTUAL_ROOT_REFERENCE_BYTES');return raw

def ref_shape(value):
    return type(value)is dict and set(value)=={'path','sha256'} and type(value['path'])is str and value['path'].startswith('/') and digest(value['sha256']) and value['sha256']!='0'*64

def require_bound():
    need(SOURCE_BOUND is True and all(type(v)is str and re.fullmatch('[a-f0-9]{40}',v)is not None and v!='0'*40 for v in (R4_SOURCE,G13_OPS_SOURCE))
         and digest(R4_IMAGE_D) and R4_IMAGE_D!='0'*64 and identifier(EXPECTED_OPERATOR_ID)
         and all(ref_shape(v)for v in(ROOT94_REF,CORE_OPERATIONAL_REF,G13_OPERATIONAL_REF,FOUR_E2ES_REF)),
         'INERT_ACTUAL_R4_D4_G13_ROOT94_CORE_E2E_BINDINGS_REQUIRED_BEFORE_ANY_IO')

def inputs():
    # Existing Root acceptance artifacts are opaque pinned originals. This
    # introduces no new approval schema, DB projection or proof producer.
    refs={'Root94':ROOT94_REF,'Core':CORE_OPERATIONAL_REF,'G13':G13_OPERATIONAL_REF,'four_E2Es':FOUR_E2ES_REF}
    originals={name:ref(value,value['sha256'])for name,value in refs.items()}
    failed_raw=ref(FAILURE_REF,FAILURE_REF['sha256']);failed=loads(failed_raw)
    need(type(failed)is dict and failed.get('schema')=='root_aws_trial3_failed_clean_cycle_record_v1'
         and failed.get('create_grant_id')==GRANT and failed.get('failed_original_job_id')==JOB
         and failed.get('failed_original_run_id')==RUN and failed.get('preregistration_id')==PRE
         and failed.get('resource_id')==RESOURCE and failed.get('resource_created_at')==BIRTH
         and failed.get('original_SDK_return_200_and_settlement_accepted')is True
         and failed.get('original_SDK_auxiliary_inventory')=='unknown_and_preserved'
         and failed.get('clean_cycle_credit')is False,'EXACT_RETAINED_FAILED_A3_SCOPE_NOT_FRESH_ELIGIBILITY')
    return originals,failed_raw

def request_body():
    return wire({'grant_id':GRANT,'job_id':JOB})

def summary(value):
    need(type(value)is dict and set(value)==SUMMARY_KEYS and value['schema']=='failed_unwitnessed_expansion_cleanup_v1'
         and identifier(value['id'])and identifier(value['child_grant_id'])and value['child_grant_id']!=GRANT
         and value['grant_id']==GRANT and value['job_id']==JOB and value['run_id']==RUN and value['preregistration_id']==PRE
         and type(value['slot'])is int and value['slot']==2 and value['resource_id']==RESOURCE and value['resource_created_at']==BIRTH,
         'CLOSED_ACTUAL_FAILED_A3_SUMMARY_IDENTITIES')
    need(type(value['event_count'])is int and value['event_count']>=1 and value['stage']in STAGES
         and digest(value['original_SDK_return_sha256'])and value['original_auxiliary_inventory_complete']is False
         and all(value[k]is False for k in('original_guest_success','clean_cycle_credit','serving_or_business_or_savings_authority')),
         'NO_ORIGINAL_AUX_UPGRADE_GUEST_SUCCESS_CYCLE_OR_BUSINESS_CREDIT')
    return value

def same_admission(acknowledged,observed):
    summary(acknowledged);summary(observed)
    stable=lambda v:{k:x for k,x in v.items()if k not in('stage','event_count')}
    need(stable(acknowledged)==stable(observed)and observed['event_count']>=acknowledged['event_count']
         and (observed['event_count']!=acknowledged['event_count']or observed['stage']==acknowledged['stage']),
         'ACK_IDENTITY_PRESERVED_WITH_ONLY_REAL_ASYNC_STAGE_PROGRESSION')
    return observed


class Client:
    def __init__(self, folder, token_config, expected_body_sha256):
        config = read(token_config, cap=65536).decode()
        tokens = re.findall(r'^\s*token:\s*(\S+)\s*$', config, re.M)
        need(len(tokens) == 1 and not any(c in tokens[0] for c in '\r\n\"\''), 'ONE_EXISTING_LOCAL_SESSION_TOKEN_RAM_ONLY')
        self.token, self.csrf, self.jar = tokens[0], '', http.cookiejar.CookieJar()
        self.folder, self.body_sha256, self.seq, self.writes, self.armed = folder, expected_body_sha256, 0, 0, None

    def call(self, method, uri, body=None):
        auth = method == 'GET' and uri == AUTH and body is None
        allowed_get = method == 'GET' and body is None and uri == GET_URI
        if method != 'GET':
            need(method == 'POST' and uri == POST_URI and type(body) is bytes and 0 < len(body) <= 8192 and sha(body) == self.body_sha256 and self.armed == (method, uri, sha(body))
                 and self.writes == 0 and self.csrf, 'ONE_DURABLY_ARMED_CLOSED_WRITE')
            self.writes += 1  # Consumed before the sole possible send, including uncertain sends.
        else:
            need(auth or allowed_get, 'CLOSED_READ_ROUTES')
        request = urllib.request.Request(ORIGIN + uri, data=body, method=method, headers={
            'Authorization': 'Bearer ' + self.token, 'Accept': 'application/json', 'Accept-Encoding': 'identity',
            **({'Content-Type': 'application/json', 'X-CSRF-Token': self.csrf} if method != 'GET' else {})})
        self.jar.add_cookie_header(request)
        conn = http.client.HTTPSConnection('yggdrasil.dakasa.me', timeout=25 if method == 'POST' else 10)
        prior, _ = signal.getitimer(signal.ITIMER_REAL)
        need(prior > 0, 'OPERATION_DEADLINE_REQUIRED')
        started = time.monotonic()
        signal.setitimer(signal.ITIMER_REAL, min(30 if method == 'POST' else 15, prior))
        status, raw, meta = None, b'', {'framing_valid': False, 'error_class': None}
        try:
            conn.request(method, uri, body=body, headers=dict(request.header_items()))
            response = conn.getresponse()
            status = response.status
            self.jar.extract_cookies(response, request)  # In-memory jar; never an opener or redirect.
            lengths = response.headers.get_all('Content-Length', [])
            encodings = response.headers.get_all('Transfer-Encoding', [])
            meta.update({'content_lengths': lengths, 'transfer_encodings': encodings,
                         'date': response.getheader('Date'), 'request_id': response.getheader('X-Request-Id')})
            try:
                raw = response.read(CAP + 1)
            except http.client.IncompleteRead as error:
                raw, meta['error_class'] = error.partial[:CAP + 1], 'IncompleteRead'
            if meta['error_class'] is None:
                length_ok = len(lengths) == 1 and re.fullmatch('[0-9]+', lengths[0]) is not None
                framed = (length_ok and not encodings and int(lengths[0]) == len(raw)) or (
                    not lengths and len(encodings) == 1 and encodings[0].strip().lower() == 'chunked'
                    and response.chunked and response.isclosed())
                meta['framing_valid'] = len(raw) <= CAP and bool(framed) and response.getheader('Content-Encoding', 'identity') == 'identity'
                if not meta['framing_valid']:
                    meta['error_class'] = 'InvalidOrIncompleteHTTPFraming'
        except BaseException as error:
            meta['error_class'] = type(error).__name__
        finally:
            try:
                conn.close()
            except Exception as error:
                meta.update({'framing_valid': False, 'error_class': type(error).__name__})
            finally:
                signal.setitimer(signal.ITIMER_REAL, max(.001, prior - (time.monotonic() - started)))
        if auth:
            return status, raw, meta  # No auth body, cookie/header, CSRF or auth-body hash is persisted.
        self.seq += 1
        secrets = [self.token, self.csrf, *(cookie.value for cookie in self.jar)]
        secret_echo = any(secret and (secret.encode() in raw or secret.encode() in wire(meta)) for secret in secrets)
        receipt = {'schema': 'failed_unwitnessed_expansion_cleanup_original_http_v1', 'at': now(), 'method': method, 'uri': uri,
                   'status': status, 'raw_bytes': len(raw), **meta}
        if secret_echo:
            receipt = {k: v for k, v in receipt.items() if k not in ('date', 'request_id', 'content_lengths', 'transfer_encodings')}
            receipt.update({'framing_valid': False, 'error_class': 'SecretEchoWithheld', 'body_withheld': True})
        else:
            receipt.update({'raw_sha256': sha(raw), 'body_base64': base64.b64encode(raw).decode()})
        name = 'HTTP-%03d.json' % self.seq
        put(self.folder, name, wire(receipt))
        need(not secret_echo and receipt['error_class'] is None and receipt['framing_valid'], 'COMPLETE_SAFE_ORIGINAL_HTTP_REQUIRED')
        return status, raw, {'file': name, 'sha256': sha(wire(receipt)), 'receipt': receipt}

    def login(self):
        status, raw, meta = self.call('GET', AUTH)
        need(status == 200 and meta['error_class'] is None and meta['framing_valid'], 'HUMAN_SESSION_GET_200')
        session = loads(raw)
        need(type(session) is dict and session.get('authenticated') is True
             and type(session.get('csrf_token')) is str and session['csrf_token']
             and not any(c in session['csrf_token'] for c in '\r\n'), 'VERIFIED_LOCAL_HUMAN_SESSION_CSRF_RAM_ONLY')
        self.csrf = session['csrf_token']

        collaborator=session.get('collaborator');permissions=session.get('permissions')
        need(type(collaborator)is dict and collaborator.get('id')==EXPECTED_OPERATOR_ID and type(collaborator.get('display_name'))is str and bool(collaborator['display_name'].strip())
             and type(permissions)is list and all(type(p)is str for p in permissions)and 'yggdrasil:*'in permissions,'CURRENT_NAMED_AUTHENTICATED_HUMAN_GODMODE_REQUIRED')

    def receipt(self):
        status,raw,reference=self.call('GET',GET_URI);value=loads(raw)
        if status==404:
            # Current Core §14 envelope includes the legacy error extension.
            need(type(value)is dict and value.get('status')==404 and value.get('code')=='integration.not_found'
                 and value.get('type')==ORIGIN+'/errors/integration.not_found'
                 and value.get('title')=='Not Found'and value.get('detail')=='failed_unwitnessed_expansion_cleanup_not_found'
                 and value.get('error')==value.get('detail'),'ONLY_EXACT_CURRENT_ROUTE_NOT_FOUND_IS_ABSENT')
            return None,reference
        need(status==200,'ORIGINAL_RECEIPT_GET_200_OR_EXACT404_REQUIRED')
        return summary(value),reference


def compact(ref):
    return {k:ref[k]for k in('file','sha256')}

def run(a,folder,source_sha):
    originals,failure_raw=inputs();writing=a.mode=='admit-once'
    need(a.execute_cleanup_admission_once is writing,'ONCE_OPT_IN_ONLY_IN_ADMISSION_MODE')
    if writing:need(not os.path.lexists(STATE/CLAIM_NAME),'ONE_C117_ADMISSION_ALREADY_CLAIMED_GET_ONLY_NEVER_RESEND')
    body=request_body();need(0<len(body)<=8192,'EXACT_TWO_UUID_BODY_BOUND')
    binding={'schema':'failed_unwitnessed_expansion_cleanup_client_binding_v1','client_source_sha256':source_sha,
             'source':R4_SOURCE,'amd64_D':R4_IMAGE_D,'ops_source':G13_OPS_SOURCE,'grant_id':GRANT,'job_id':JOB,'run_id':RUN,
             'preregistration_id':PRE,'resource_id':RESOURCE,'resource_created_at':BIRTH,
             'existing_Root_refs':{'Root94':ROOT94_REF,'Core':CORE_OPERATIONAL_REF,'G13':G13_OPERATIONAL_REF,'four_E2Es':FOUR_E2ES_REF},
             'historical_failure_ref':FAILURE_REF,'evidence_dir':str(folder),'request_body_sha256':sha(body)}
    put(folder,'BINDING.json',wire(binding))
    api=Client(folder,a.token_config,sha(body));api.login()
    existing,getref=api.receipt()
    if not writing:
        put(folder,'OBSERVATION.json',wire({'schema':'failed_unwitnessed_expansion_cleanup_get_observation_v1','mode':a.mode,
             'receipt':existing,'readback':compact(getref),'writes':0,'global_possible_exists':os.path.lexists(STATE/CLAIM_NAME),
             'observed_receipt_is_not_original_POST_201_ACK':True,'observation_confers_no_replay_or_provider_authority':True,**binding}))
        return
    need(existing is None,'SERVER_ADMISSION_ALREADY_EXISTS_GET_ONLY_NO_NEW_POST')
    again,again_failure=inputs();need(again==originals and again_failure==failure_raw,'ROOT_ORIGINALS_UNCHANGED_BEFORE_ONE_CLAIM')
    if not STATE.exists():STATE.mkdir(mode=0o700,exist_ok=False);sync(PREP)
    directory(STATE,True)
    claim={**binding,'method':'POST','uri':POST_URI,'body_sha256':sha(body),'at':now(),'automatic_retry':False}
    for name,raw in originals.items():put(folder,'ROOT-'+name+'.original.json',raw)
    put(folder,'HISTORICAL-FAILED-A3.original.json',failure_raw);put(folder,'REQUEST.json',body)
    put(STATE,CLAIM_NAME,wire(claim));put(folder,'POSSIBLE-SEND.json',wire(claim))
    api.armed=('POST',POST_URI,sha(body))
    status,returned,postref=api.call('POST',POST_URI,body)
    need(status==201,'ORIGINAL_201_REQUIRED_ERROR_UNKNOWN_OR_409_IS_GET_ONLY_NEVER_RESEND')
    acknowledged=summary(loads(returned));readback,getref=api.receipt()
    need(readback is not None,'ACKED_ADMISSION_REQUIRES_SEPARATE_GET_200')
    same_admission(acknowledged,readback)
    put(folder,'RETURN.PUBLIC.json',wire({'schema':'failed_unwitnessed_expansion_cleanup_admission_once_return_v1',
         'status':'ORIGINAL_201_AND_SAME_ADMISSION_GET_200','acknowledged_admission':acknowledged,'observed_receipt':readback,
         'writes':api.writes,'post':compact(postref),'readback':compact(getref),'possible_sha256':sha(wire(claim)),
         'automatic_retry':False,'admission_only':True,'manual_native_or_claim_authority':False,
         'original_guest_success':False,'clean_cycle_credit':False,'serving_or_business_or_savings_authority':False,**binding}))

def main():
    require_bound() # False/None stops before argument, file, token, session or API I/O.
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('observe','admit-once','reconcile'))
    p.add_argument('--token-config',type=Path,default=Path('/Users/giovanniriosmartins/.yggdrasil/config.yaml'))
    p.add_argument('--evidence-dir',type=Path,required=True);p.add_argument('--expected-script-sha256',required=True)
    p.add_argument('--execute-cleanup-admission-once',action='store_true');a=p.parse_args();os.umask(0o077)
    need(Path(__file__).absolute()==PREP/'admit_failed_unwitnessed_expansion_cleanup_once.py','FIXED_REVIEWED_CLIENT_AND_GLOBAL_ONCE_LOCATION')
    directory(PREP,False);source_sha=sha(read(__file__,private=False));need(a.expected_script_sha256==source_sha,'ACTUAL_REVIEWED_BOUND_CLIENT_SHA')
    need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'NO_INHERITED_ALARM');previous=signal.getsignal(signal.SIGALRM)
    def expired(_signal,_frame):raise Hold('ORIGINAL_LOCAL_OPERATION_DEADLINE')
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,120);folder=None
    try:
        inputs();folder=new_evidence(a.evidence_dir);run(a,folder,source_sha)
        print(json.dumps({'status':'LOCAL_ORIGINALS_RETAINED','mode':a.mode,'evidence_dir':str(folder),'no_replay':True}));return 0
    except BaseException as error:
        if folder is not None:
            try:
                signal.setitimer(signal.ITIMER_REAL,2) # Custody only, no second request.
                put(folder,'HOLD.json',wire({'status':'HOLD_GET_ONLY_RECONCILE_NEVER_RESEND','at':now(),'mode':a.mode,
                     'error_class':type(error).__name__,'guard':str(error)if isinstance(error,Hold)else None,
                     'global_possible_exists':os.path.lexists(STATE/CLAIM_NAME),'possible_send_marker_exists':os.path.lexists(folder/'POSSIBLE-SEND.json'),'automatic_retry':False}))
            except BaseException:pass
        print(json.dumps({'status':'HOLD_NO_REPLAY','error_class':type(error).__name__}));return 30
    finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)

if __name__=='__main__':
    try:raise SystemExit(main())
    except SystemExit:raise
    except BaseException as error:
        print(json.dumps({'status':'INERT_OR_HOLD_BEFORE_AUTH','error_class':type(error).__name__,'automatic_retry':False}));raise SystemExit(30)
