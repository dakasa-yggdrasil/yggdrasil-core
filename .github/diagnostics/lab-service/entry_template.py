"""Generated LAB-only bounded rehearsal entrypoint. Not a production service."""
import hashlib,importlib.util,json,os,re,shutil,stat,subprocess,sys,urllib.request
from pathlib import Path

SPEC=json.loads(__SPEC_LITERAL__)
BASE=Path(__file__).resolve().parent
class Held(RuntimeError):pass

def need(value,reason):
    if not value:raise Held(reason)

def validate_identity(document,boot):
    need(type(document) is dict and document.get('accountId')=='153828470928'
         and document.get('region')=='us-east-1' and document.get('instanceId')==SPEC['instance_id']
         and SPEC['instance_id']=='i-0cb486ae31a45d15e' and boot==SPEC['boot_id'],
         'EXACT_PINNED_DISPOSABLE_LAB_IDENTITY_REQUIRED')

def imds_identity():
    token_req=urllib.request.Request('http://169.254.169.254/latest/api/token',method='PUT',
            headers={'X-aws-ec2-metadata-token-ttl-seconds':'60'})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(token_req,timeout=2) as response:token=response.read(4097)
    need(0<len(token)<=4096,'IMDSV2_TOKEN_REQUIRED')
    request=urllib.request.Request('http://169.254.169.254/latest/dynamic/instance-identity/document',
            headers={'X-aws-ec2-metadata-token':token.decode('ascii')})
    with opener.open(request,timeout=2) as response:raw=response.read(65537)
    need(0<len(raw)<=65536,'BOUNDED_IMDS_IDENTITY_REQUIRED')
    return json.loads(raw)

def _private_root(path,directory):
    st=os.lstat(path)
    need(st.st_uid==0 and not st.st_mode&0o022
         and (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode) and st.st_nlink==1),
         'ROOT_OWNED_NONWRITABLE_SOURCE_REQUIRED')
    return st

def verify_source(base=BASE):
    # Every ancestor must be root controlled; sticky world-writable test
    # directories are permitted only because their children remain root-owned.
    for parent in (base,*base.parents):
        st=os.lstat(parent)
        need(stat.S_ISDIR(st.st_mode) and st.st_uid==0
             and (not st.st_mode&0o022 or bool(st.st_mode&stat.S_ISVTX)),
             'ROOT_CONTROLLED_SOURCE_ANCESTORS_REQUIRED')
    _private_root(base,True)
    _private_root(base/'manifest.json',False)
    raw=(base/'manifest.json').read_bytes()
    need(hashlib.sha256(raw).hexdigest()==SPEC['manifest_sha256'],'EXACT_SEALED_MANIFEST_REQUIRED')
    manifest=json.loads(raw);source=base/'sources';_private_root(source,True)
    expected=manifest['files'];need(type(expected) is dict and expected,'EXACT_SOURCE_MANIFEST_REQUIRED')
    observed={}
    for directory,dirs,files in os.walk(source,followlinks=False):
        d=Path(directory);_private_root(d,True)
        for name in dirs:_private_root(d/name,True)
        for name in files:
            path=d/name;before=_private_root(path,False);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                h=hashlib.sha256()
                while True:
                    part=os.read(fd,65536)
                    if not part:break
                    h.update(part)
                after=os.fstat(fd);named=os.lstat(path)
            finally:os.close(fd)
            stamp=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
            need(stamp(before)==stamp(after)==stamp(named),'SOURCE_CHANGED_DURING_SEAL')
            observed[str(path.relative_to(source))]=h.hexdigest()
    need(observed==expected,'EXACT_SOURCE_FILE_SET_AND_HASHES_REQUIRED')
    return source

def validate_systemd():
    unit=SPEC['unit'];inv=os.environ.get('INVOCATION_ID','')
    need(re.fullmatch('[0-9a-f]{32}',inv) is not None,'SYSTEMD_INVOCATION_REQUIRED')
    result=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=MainPID,InvocationID,ActiveState,ControlGroup,FragmentPath'],
        capture_output=True,text=True,timeout=3,check=True)
    rows=dict(row.split('=',1) for row in result.stdout.splitlines())
    need(len(rows)==5 and rows['MainPID']==str(os.getpid()) and rows['InvocationID']==inv
         and rows['ActiveState']=='active' and rows['FragmentPath']==SPEC['unit_path']
         and Path('/proc/self/cgroup').read_text().splitlines()==['0::'+rows['ControlGroup']],
         'EXACT_LAB_SYSTEMD_UNIT_REQUIRED')
    unit_path=Path(SPEC['unit_path']);cleanup=BASE/'cleanup.py'
    for path,digest in ((unit_path,SPEC['unit_sha256']),(cleanup,SPEC['cleanup_sha256'])):
        _private_root(path,False)
        need(hashlib.sha256(path.read_bytes()).hexdigest()==digest,'SEALED_UNIT_AND_CLEANUP_REQUIRED')
    return inv

def validate_empty_slice():
    # Reuse the exact sealed cleanup inventory; a randomized slice must not
    # already contain any unit or cgroup before this one-shot run begins.
    spec=importlib.util.spec_from_file_location('lab_cleanup_preflight',BASE/'cleanup.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    need(not module.services() and module.slice_cgroup() is None,'EMPTY_UNIQUE_LAB_SLICE_REQUIRED')
    for directory in ('/run/systemd/system','/etc/systemd/system','/usr/lib/systemd/system'):
        need(not os.path.lexists(str(Path(directory)/SPEC['slice'])),'NO_EXISTING_LAB_SLICE_FRAGMENT')

def reserve_run(invocation):
    # A nonce is permanently consumed, including after a partial or failed run.
    directory=Path('/var/lib/dakasa-elastic-lab-rehearsal-runs')
    _private_root(directory.parent,True)
    directory.mkdir(mode=0o700,exist_ok=True);_private_root(directory,True)
    fd=os.open(directory/SPEC['nonce'],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        os.write(fd,(json.dumps({'unit':SPEC['unit'],'boot_id':SPEC['boot_id'],'invocation_id':invocation},sort_keys=True)+'\n').encode())
        os.fsync(fd)
    finally:os.close(fd)
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)

def main():
    need(os.geteuid()==0,'ROOT_LAB_ONLY')
    validate_identity(imds_identity(),Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    invocation=validate_systemd();source=verify_source()
    need(Path('/sys/module/xt_bpf').is_dir(),'LAB_XT_BPF_MUST_ALREADY_BE_LOADED')
    runtime=Path('/run')/SPEC['runtime_directory'];_private_root(runtime,True)
    need(not any(runtime.iterdir()),'EMPTY_PRIVATE_RUNTIME_REQUIRED')
    need(shutil.disk_usage(runtime).free>=256*1024*1024,'LAB_RUNTIME_DISK_SPACE_REQUIRED')
    # Reuse of a bundle is forbidden even if the previous run failed.
    validate_empty_slice()
    reserve_run(invocation)
    stage=runtime/'source';shutil.copytree(source,stage,symlinks=False)
    # Verify the copied tree again before executing any source.
    manifest=json.loads((BASE/'manifest.json').read_bytes());expected=manifest['files'];actual={}
    for directory,dirs,files in os.walk(stage,followlinks=False):
        d=Path(directory);_private_root(d,True)
        for name in dirs:_private_root(d/name,True)
        for name in files:
            path=d/name;_private_root(path,False)
            actual[str(path.relative_to(stage))]=hashlib.sha256(path.read_bytes()).hexdigest()
    need(actual==expected,'COPIED_RUNTIME_HASH_MISMATCH')
    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','INVOCATION_ID':invocation,
         'CI_CONTROLLER_UNIT':SPEC['unit'],'CI_AUXILIARY_SLICE':SPEC['slice'],
         'CI_GUARDED_FIXTURE':'1','CI_HOLDER_TEST':'1','CI_FAILURE_ORDER':'positive-first',
         'CI_DENY_ACK_UNCERTAIN':'1','CI_HOST_NETNS':os.readlink('/proc/self/ns/net')}
    os.execve('/usr/bin/unshare',['/usr/bin/unshare','--net','--','/usr/bin/python3','-B',
                str(stage/'verify_controller_guardian.py')],env)

if __name__=='__main__':main()
