"""Original bounded local native process, adapted from frozen 2c6.

Each caller owns its capture dictionary, populated in finally after original
pipes/Wait joins. Linux pidfd exit readiness shares the pipe selector: the
success path never enters Popen.wait(timeout)'s POSIX polling/sleep loop.
No deadline is extended and a late exit/EOF/Wait is still an unknown failure.
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


def stop_wait(process):
    try:
        if process.poll()is None:process.terminate()
        try:code=process.wait(timeout=1)
        except subprocess.TimeoutExpired:process.kill();code=process.wait(timeout=1)
        return{'pid':process.pid,'joined':True,'exit_code':code}
    except BaseException:return{'pid':process.pid,'joined':False,'exit_code':None}


def native(argv,*,deadline,stdin=b'',env=None,cap=4*1024**2,custody=None,capture=None,writer_lease=None):
    """Own same stdin/stdout/stderr pipes and actual Wait under one deadline."""
    facts=custody if custody is not None else{}
    facts.update(native_started=False,local_child_joined=True,all_local_FDs_closed=True,
                 pidfd_opened=False,pidfd_readable=False,pidfd_closed=True)
    if capture is not None:capture.update(stdout=b'',stderr=b'',transport=dict(facts))
    require(time.monotonic()<deadline,'ORIGINAL_NATIVE_DEADLINE')
    require(callable(getattr(os,'pidfd_open',None)),'ORIGINAL_LINUX_PIDFD_REQUIRED_BEFORE_CHILD')
    is_nft_apply=(bool(argv) and argv[0]=='/usr/sbin/nft' and '-f' in argv and '-c' not in argv)
    require((writer_lease is not None)==is_nft_apply,'WRITER_LEASE_EXACTLY_FOR_NFT_APPLY')
    inherited=()
    if writer_lease is not None:
        import writer_lease_v3_DRAFT as lease_module
        require(type(writer_lease) is lease_module.WriterLease,'TYPED_WRITER_LEASE_REQUIRED')
        inherited=(writer_lease.validate(),)
    process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                             env=env or SAFE,close_fds=True,pass_fds=inherited)
    streams=(process.stdin,process.stdout,process.stderr);selector=None;pidfd=None;out=bytearray();err=bytearray();pending=b'';offset=0;exhausted=False;facts.update(pid=process.pid,native_started=True,wait_zero=False,stdout_EOF=False,stderr_EOF=False,all_local_FDs_closed=False,local_child_joined=False,captured_output_truncated=False)
    try:
        selector=selectors.DefaultSelector()
        pidfd=os.pidfd_open(process.pid,0)
        facts.update(pidfd_opened=True,pidfd_closed=False)
        selector.register(pidfd,selectors.EVENT_READ,'exit')
        for stream in streams:os.set_blocking(stream.fileno(),False)
        selector.register(process.stdin,selectors.EVENT_WRITE,'input');selector.register(process.stdout,selectors.EVENT_READ,'output');selector.register(process.stderr,selectors.EVENT_READ,'error')
        while selector.get_map():
            require(time.monotonic()<deadline,'ORIGINAL_NATIVE_PIPE_DEADLINE')
            for key,events in selector.select(min(.1,max(.001,deadline-time.monotonic()))):
                if key.data=='exit':
                    # Readability belongs to THIS unreaped child pidfd. An
                    # immediate Wait reaps it without a timed busy-loop tail.
                    facts['pidfd_readable']=True
                    code=process.wait(timeout=0)
                    facts.update(local_child_joined=True,exit_code=code,wait_zero=code==0)
                    selector.unregister(pidfd);os.close(pidfd);pidfd=None
                    facts['pidfd_closed']=True
                elif key.data=='input':
                    if not pending and not exhausted:
                        if hasattr(stdin,'read'):pending=stdin.read(65536);exhausted=not pending
                        else:pending=stdin[offset:offset+65536];offset+=len(pending);exhausted=not pending
                    require(time.monotonic()<deadline,'ORIGINAL_NATIVE_INPUT_DEADLINE')
                    if pending:
                        try:count=os.write(key.fileobj.fileno(),pending);pending=pending[count:]
                        except BlockingIOError:pass
                    elif exhausted:selector.unregister(key.fileobj);key.fileobj.close()
                else:
                    try:chunk=os.read(key.fileobj.fileno(),65536)
                    except BlockingIOError:continue
                    if not chunk:
                        facts['stdout_EOF'if key.data=='output'else'stderr_EOF']=True;selector.unregister(key.fileobj);key.fileobj.close();continue
                    target=out if key.data=='output'else err
                    if len(target)+len(chunk)>cap:facts['captured_output_truncated']=True;raise Held('BOUNDED_NATIVE_OUTPUT')
                    target.extend(chunk)
        require(facts['local_child_joined'] and type(facts.get('exit_code'))is int,'ORIGINAL_PIDFD_EXIT_AND_WAIT_REQUIRED')
        require(time.monotonic()<deadline,'ORIGINAL_NATIVE_WAIT_DEADLINE')
        errorcode=None
        match=re.search(rb'An error occurred \(([A-Za-z0-9_.-]{1,100})\)',err)
        if match:errorcode=match.group(1).decode('ascii')
        return bytes(out),{'error_code':errorcode,'stderr_sha256':digest(err),'stderr_bytes':len(err),**facts,'all_local_FDs_closed':True}
    finally:
        if selector is not None:selector.close()
        if pidfd is not None:os.close(pidfd);pidfd=None;facts['pidfd_closed']=True
        for stream in streams:
            try:stream.close()
            except BaseException:pass
        joined=stop_wait(process);facts['local_child_joined']=joined['joined'];facts['all_local_FDs_closed']=all(v.closed for v in streams)and pidfd is None
        # These local facts never imply a remote API/SSH unit did not start.
        facts.update(joined)
        if capture is not None:capture.update(stdout=bytes(out),stderr=bytes(err),transport=dict(facts))
