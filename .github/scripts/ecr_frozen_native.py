"""Local private one-attempt journal and owned bounded native process I/O.

No operation runs on import. AWS credentials remain RAM/environment only. Native
CLI JSON parameters use an owned private bounded file until the SAME child joins.
Only original public-recipe SSH diagnostics may be retained privately. A killed
local client is not proof of remote absence.
"""
import base64,fcntl,hashlib,json,os,re,selectors,signal,stat,subprocess,time
from pathlib import Path

SAFE={'PATH':'/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin','HOME':str(Path.home()),'LANG':'C','AWS_CONFIG_FILE':'/dev/null','AWS_SHARED_CREDENTIALS_FILE':'/dev/null','AWS_EC2_METADATA_DISABLED':'true','AWS_MAX_ATTEMPTS':'1','AWS_PAGER':'','AWS_CLI_AUTO_PROMPT':'off'}


class Held(Exception):pass


def require(ok,reason):
    if not ok:raise Held(reason)


def canonical(value):return(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()


def digest(raw):return hashlib.sha256(raw).hexdigest()


def private(path,directory=False):
    s=path.lstat();require(s.st_uid==os.getuid()and not path.is_symlink()and not stat.S_IMODE(s.st_mode)&0o077,'PRIVATE_ORIGINAL_LOCAL_PATH')
    require(stat.S_ISDIR(s.st_mode)if directory else stat.S_ISREG(s.st_mode)and s.st_nlink==1,'PRIVATE_ORIGINAL_PATH_TYPE')

def original_private_bytes(path,cap=262144):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb')as source:
        st=os.fstat(source.fileno());require(stat.S_ISREG(st.st_mode)and st.st_uid==os.getuid()and st.st_nlink==1 and not stat.S_IMODE(st.st_mode)&0o077,'PRIVATE_ORIGINAL_OPENED_FILE')
        raw=source.read(cap+1)
    require(0<len(raw)<=cap,'BOUNDED_ORIGINAL_PRIVATE_FILE');return raw


def once(path,value):
    raw=canonical(value);fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as f:os.fchmod(f.fileno(),0o600);f.write(raw);f.flush();os.fsync(f.fileno())
    directory=os.open(path.parent,os.O_RDONLY)
    try:os.fsync(directory)
    finally:os.close(directory)


def boot_session():
    r=subprocess.run(['/usr/sbin/sysctl','-n','kern.bootsessionuuid'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=2,check=False,env=SAFE)
    require(r.returncode==0 and re.fullmatch(b'[a-fA-F0-9-]{36}\n?',r.stdout),'ACTUAL_MAC_BOOT_SESSION_REQUIRED');return r.stdout.decode().strip().lower()


def stop_wait(process):
    try:
        if process.poll()is None:process.terminate()
        try:code=process.wait(timeout=1)
        except subprocess.TimeoutExpired:process.kill();code=process.wait(timeout=1)
        return{'pid':process.pid,'joined':True,'exit_code':code}
    except BaseException:return{'pid':process.pid,'joined':False,'exit_code':None}


def native(argv,*,deadline,stdin=b'',env=None,cap=4*1024**2,custody=None,diagnostic_path=None,track_input=False):
    """Own same stdin/stdout/stderr pipes and actual Wait under one deadline."""
    facts=custody if custody is not None else{}
    facts.update(native_started=False,local_child_joined=True,all_local_FDs_closed=True)
    input_digest=hashlib.sha256() if track_input else None
    if track_input:facts.update(stdin_written_bytes=0,stdin_written_sha256=input_digest.hexdigest(),stdin_closed_after_all_input=False)
    native.last_custody=dict(facts)
    require(time.monotonic()<deadline,'ORIGINAL_NATIVE_DEADLINE')
    if diagnostic_path is not None:private(diagnostic_path.parent,True);require(not diagnostic_path.exists(),'NEW_PRIVATE_SSH_DIAGNOSTIC_ONLY')
    process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env or SAFE,close_fds=True)
    streams=(process.stdin,process.stdout,process.stderr);selector=selectors.DefaultSelector();out=bytearray();err=bytearray();pending=b'';offset=0;exhausted=False;facts.update(pid=process.pid,native_started=True,wait_zero=False,stdout_EOF=False,stderr_EOF=False,all_local_FDs_closed=False,local_child_joined=False,captured_output_truncated=False)
    try:
        for stream in streams:os.set_blocking(stream.fileno(),False)
        selector.register(process.stdin,selectors.EVENT_WRITE,'input');selector.register(process.stdout,selectors.EVENT_READ,'output');selector.register(process.stderr,selectors.EVENT_READ,'error')
        while selector.get_map():
            require(time.monotonic()<deadline,'ORIGINAL_NATIVE_PIPE_DEADLINE')
            for key,events in selector.select(min(.1,max(.001,deadline-time.monotonic()))):
                if key.data=='input':
                    if not pending and not exhausted:
                        if hasattr(stdin,'read'):pending=stdin.read(65536);exhausted=not pending
                        else:pending=stdin[offset:offset+65536];offset+=len(pending);exhausted=not pending
                    require(time.monotonic()<deadline,'ORIGINAL_NATIVE_INPUT_DEADLINE')
                    if pending:
                        try:
                            count=os.write(key.fileobj.fileno(),pending)
                            if track_input:
                                input_digest.update(pending[:count]);facts['stdin_written_bytes']+=count;facts['stdin_written_sha256']=input_digest.hexdigest()
                            pending=pending[count:]
                        except BlockingIOError:pass
                    elif exhausted:
                        selector.unregister(key.fileobj);key.fileobj.close()
                        if track_input:facts['stdin_closed_after_all_input']=True
                else:
                    try:chunk=os.read(key.fileobj.fileno(),65536)
                    except BlockingIOError:continue
                    if not chunk:
                        facts['stdout_EOF'if key.data=='output'else'stderr_EOF']=True;selector.unregister(key.fileobj);key.fileobj.close();continue
                    target=out if key.data=='output'else err
                    if len(target)+len(chunk)>cap:facts['captured_output_truncated']=True;raise Held('BOUNDED_NATIVE_OUTPUT')
                    target.extend(chunk)
        code=process.wait(timeout=max(.001,deadline-time.monotonic()));facts.update(local_child_joined=True,exit_code=code,wait_zero=code==0)
        require(time.monotonic()<deadline,'ORIGINAL_NATIVE_WAIT_DEADLINE')
        errorcode=None
        match=re.search(rb'An error occurred \(([A-Za-z0-9_.-]{1,100})\)',err)
        if match:errorcode=match.group(1).decode('ascii')
        return bytes(out),{'error_code':errorcode,'stderr_sha256':digest(err),'stderr_bytes':len(err),**facts,'all_local_FDs_closed':True}
    finally:
        selector.close()
        for stream in streams:
            try:stream.close()
            except BaseException:pass
        joined=stop_wait(process);facts['local_child_joined']=joined['joined'];facts['all_local_FDs_closed']=all(v.closed for v in streams)
        # These local facts never imply a remote API/SSH unit did not start.
        native.last_custody={**facts,**joined}
        if diagnostic_path is not None:
            diagnostic={'schema':'private_original_baker_SSH_diagnostic_v1','success_authority':False,'original_local_transport':native.last_custody,'stdout_base64':base64.b64encode(out).decode(),'stdout_sha256':digest(out),'stdout_bytes':len(out),'stderr_base64':base64.b64encode(err).decode(),'stderr_sha256':digest(err),'stderr_bytes':len(err),'never_replay_or_adopt':True}
            once(diagnostic_path,diagnostic);native.last_custody={**native.last_custody,'private_diagnostic_name':diagnostic_path.name,'private_diagnostic_sha256':digest(canonical(diagnostic))}
            if facts.get('wait_zero'):require(time.monotonic()<deadline,'ORIGINAL_NATIVE_DIAGNOSTIC_FSYNC_DEADLINE')


class Attempt:
    def __init__(self,path,seal,*,new=False,read_only=False):
        self.path=path;self.seal=seal;self.read_only=read_only
        require(re.fullmatch('native-bake-[a-f0-9]{20}',seal['run_id'])and path.name==seal['run_id'],'EXACT_NEW_ATTEMPT_DIRECTORY')
        if new:path.mkdir(mode=0o700)
        private(path,True);self.lock=os.open(path/'owner.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600);fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if new:
            once(path/'START.json',{'schema':'one_original_native_baker_owner_v1','run_id':seal['run_id'],'provider':seal['provider'],'seal_sha256':digest(canonical(seal)),'Mac_boot_session':boot_session(),'started_monotonic':time.monotonic(),'maximum_overall_seconds':1200,'useful_work_maximum_seconds':1080,'cleanup_reserve_seconds':120,'implicit_mutation_replay':False})
        private(path/'START.json');self.start=json.loads((path/'START.json').read_text());require(self.start['run_id']==seal['run_id']and self.start['seal_sha256']==digest(canonical(seal)),'SAME_ORIGINAL_ATTEMPT_SEAL')
        require(read_only or self.start['Mac_boot_session']==boot_session(),'MAC_REBOOT_DISALLOWS_MUTATING_RESUME')
        self.hard=self.start['started_monotonic']+1200;self.useful=self.start['started_monotonic']+1080
        self.observe_deadline=time.monotonic()+60 if read_only else None
    def deadline(self,seconds=30,cleanup=False):
        limit=self.observe_deadline if self.read_only else(self.hard if cleanup else self.useful);require(time.monotonic()<limit,'ORIGINAL_BAKER_OVERALL_BUDGET');return min(limit,time.monotonic()+seconds)
    def mutate(self,name,operation,request,invoke,project):
        require(not self.read_only and not(self.path/(name+'-INTENT.json')).exists()and not(self.path/(name+'-RETURN.json')).exists(),'NO_MUTATING_REPLAY_OR_READONLY_EFFECT')
        limit=self.hard if name in('VM-DELETE','FIREWALL-DELETE')else self.useful
        require(time.monotonic()<limit,'ORIGINAL_BAKER_PRE_INTENT_DEADLINE')
        once(self.path/(name+'-INTENT.json'),{'schema':'one_original_native_baker_possible_send_v1','run_id':self.seal['run_id'],'provider':self.seal['provider'],'operation':operation,'request_sha256':digest(canonical(request)),'possible_native_effect':True,'implicit_retry':False,'started_monotonic':time.monotonic()})
        try:
            require(time.monotonic()<limit,'ORIGINAL_BAKER_POST_INTENT_FSYNC_DEADLINE')
            value,facts=invoke();require(facts['wait_zero']and facts['stdout_EOF']and facts['stderr_EOF']and facts['all_local_FDs_closed']and facts['local_child_joined'],'NATIVE_RETURN_NOT_CLOSED_ZERO')
            require(time.monotonic()<limit,'ORIGINAL_BAKER_NATIVE_RETURN_DEADLINE');safe=project(value);require(time.monotonic()<limit,'ORIGINAL_BAKER_PRE_RETURN_DEADLINE')
            once(self.path/(name+'-RETURN.json'),{'schema':'one_original_native_baker_actual_return_v1','operation':operation,'run_id':self.seal['run_id'],'request_sha256':digest(canonical(request)),'actual_return':safe,'local_native_transport':facts,'requires_same_original_owner_zero_before_deadline':True});require(time.monotonic()<limit,'ORIGINAL_BAKER_POST_RETURN_FSYNC_DEADLINE');return safe
        except BaseException as error:
            reason=str(error)if isinstance(error,Held)and re.fullmatch('[A-Z0-9_]{1,160}',str(error))else None
            once(self.path/(name+'-HOLD.json'),{'schema':'native_baker_possible_send_requires_reconcile_v1','run_id':self.seal['run_id'],'operation':operation,'error_class':type(error).__name__,'closed_failure_guard':reason,'remote_effect_or_owner_absence_proved':False,'local_native_custody':getattr(native,'last_custody',None),'never_resend':True})
            raise Held('POSSIBLE_SEND_HOLD_RECONCILE_WITHOUT_REPLAY')from None


def aws_auth(deadline,prod):
    raw,facts=native([str(prod/'tooling/kubectl'),'--context','dakasa-brain','--request-timeout=5s','-n','dakasa','get','secret','integration-aws-creds','-o','json'],deadline=deadline,env=dict(SAFE,KUBECONFIG=str(prod/'kubeconfig')),cap=65536)
    require(facts['wait_zero'],'EXISTING_BRAIN_AWS_CREDENTIAL_GET');secret=json.loads(raw);require(secret['metadata']['uid']=='973023bf-bab1-4c1e-9aa8-1b8c05acb5f7','SAME_EXISTING_AWS_CREDENTIAL_SOURCE')
    import base64
    env=dict(SAFE,AWS_ACCESS_KEY_ID=base64.b64decode(secret['data']['access_key_id'],validate=True).decode(),AWS_SECRET_ACCESS_KEY=base64.b64decode(secret['data']['secret_access_key'],validate=True).decode());secret=raw=None
    body,facts=native(['/usr/local/bin/aws','--region','us-east-1','sts','get-caller-identity','--output','json'],deadline=deadline,env=env);identity=json.loads(body);require(facts['wait_zero']and identity['Account']=='153828470928'and identity['Arn']=='arn:aws:iam::153828470928:user/Yggdrasil','SAME_EXISTING_IAM_PRINCIPAL');return env


def curl_quote(value):
    require('\x00'not in value,'NO_CURL_CONFIG_NUL');return'"'+value.replace('\\','\\\\').replace('"','\\"').replace('\r','\\r').replace('\n','\\n')+'"'


class Cloud:
    def __init__(self,attempt,prod):
        self.a=attempt;self.env=aws_auth(attempt.deadline(30),prod)if attempt.seal['provider']=='aws'else None;self.token=None
        if self.env is None:
            source=Path('/Users/giovanniriosmartins/.config/dakasa/credentials/hetzner-cloud-token');private(source);require(source.stat().st_size<=4096,'BOUNDED_EXISTING_HCLOUD_TOKEN');self.token=source.read_text().strip();require(32<=len(self.token)<=256 and not any(v.isspace()for v in self.token),'EXISTING_HCLOUD_TOKEN_SHAPE')
    def aws(self,operation,request,*,cleanup=False,deadline_cap=None):
        deadline=self.a.deadline(30,cleanup)
        if deadline_cap is not None:deadline=min(deadline,deadline_cap)
        body=canonical(request);require(len(body)<=65536,'BOUNDED_PRIVATE_AWS_JSON_PARAMETERS')
        private(self.a.path,True);path=self.a.path/('AWS-PARAMETERS-'+os.urandom(16).hex()+'.json');fd=None;identity=None;custody={};removed=False;facts=None
        try:
            require(time.monotonic()<deadline,'ORIGINAL_AWS_PARAMETER_PREWRITE_DEADLINE')
            fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600);os.fchmod(fd,0o600)
            with os.fdopen(fd,'wb')as f:
                fd=None;f.write(body);f.flush();os.fsync(f.fileno());st=os.fstat(f.fileno());identity=(st.st_dev,st.st_ino)
            private(path);require(path.stat().st_size==len(body),'ORIGINAL_PRIVATE_AWS_PARAMETER_EXTENT')
            directory=os.open(path.parent,os.O_RDONLY)
            try:os.fsync(directory)
            finally:os.close(directory)
            require(time.monotonic()<deadline,'ORIGINAL_AWS_PARAMETER_POST_FSYNC_DEADLINE')
            raw,facts=native(['/usr/local/bin/aws','--region','us-east-1','--cli-connect-timeout','3','--cli-read-timeout','15','ec2',operation,'--cli-input-json','file://'+str(path.resolve()),'--output','json'],deadline=deadline,env=self.env,custody=custody)
            return(json.loads(raw)if raw else{}),facts
        finally:
            if fd is not None:os.close(fd)
            # A not-started client has no live file reader. An uncertain started
            # child retains its original private input; never unlink underneath it.
            joined=custody.get('local_child_joined',not custody.get('native_started',False))
            if identity is not None and joined:
                private(path);st=path.lstat();require((st.st_dev,st.st_ino)==identity and st.st_size==len(body),'SAME_ORIGINAL_AWS_PARAMETER_INODE')
                with path.open('rb')as source:require(digest(source.read(65537))==digest(body),'SAME_ORIGINAL_AWS_PARAMETER_SHA')
                path.unlink();directory=os.open(path.parent,os.O_RDONLY)
                try:os.fsync(directory)
                finally:os.close(directory)
                removed=True
            if identity is not None:once(path.with_name(path.stem+'-CUSTODY.json'),{'schema':'original_private_AWS_CLI_parameter_custody_v1','request_sha256':digest(body),'request_bytes':len(body),'parameter_file_device':identity[0],'parameter_file_inode':identity[1],'parameter_file_mode':'0600','original_local_child_joined':joined,'parameter_file_unlinked_after_join':removed,'production_credentials_written':False,'possible_native_effect_or_absence_proved':False})
            if facts is not None and facts.get('wait_zero'):require(time.monotonic()<deadline,'ORIGINAL_AWS_PARAMETER_CLEANUP_FSYNC_DEADLINE')
    def hcloud(self,method,path,body=None,*,cleanup=False):
        require(re.fullmatch(r'/(?:servers|firewalls|images|primary_ips|actions)(?:/[0-9]+)?(?:/actions/(?:shutdown|create_image))?(?:\?[A-Za-z0-9_=%.,-]+)?',path),'CLOSED_BAKER_HCLOUD_PATH')
        deadline=self.a.deadline(25,cleanup);remaining=max(.001,deadline-time.monotonic());cfg=['url = '+curl_quote('https://api.hetzner.cloud/v1'+path),'request = '+curl_quote(method),'header = '+curl_quote('Authorization: Bearer '+self.token),'header = '+curl_quote('Content-Type: application/json'),'header = '+curl_quote('Expect:')]
        if body is not None:cfg.append('data-binary = '+curl_quote(canonical(body).decode()))
        raw,facts=native(['/usr/bin/curl','--disable','--config','-','--include','--http1.1','--proto','=https','--noproxy','*','--max-time',str(remaining),'--connect-timeout',str(min(3,remaining)),'--retry','0','--silent','--max-filesize',str(4*1024**2)],deadline=deadline,stdin=('\n'.join(cfg)+'\n').encode(),env=SAFE)
        require(facts['wait_zero'],'HCLOUD_NATIVE_CLIENT_FAILED');header,body=raw.split(b'\r\n\r\n',1);status=re.fullmatch(rb'HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?',header.split(b'\r\n')[0]);require(status is not None,'NATIVE_HTTP_STATUS_REQUIRED');code=int(status.group(1));facts['http_status']=code
        require(code in(200,201,204,404),'HCLOUD_RESPONSE_REQUIRES_RECONCILE');return(json.loads(body)if body else{}),facts
