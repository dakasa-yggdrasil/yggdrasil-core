"""Generated LAB-only cleanup; refuses foreign units and uncertain termination."""
import ctypes,json,os,re,stat,subprocess,time,urllib.request
from pathlib import Path
SPEC=json.loads(__SPEC_LITERAL__)
class Held(RuntimeError):pass

def need(value,reason):
    if not value:raise Held(reason)

def validate_identity(document,boot):
    need(type(document) is dict and document.get('accountId')=='153828470928'
         and document.get('region')=='us-east-1' and document.get('instanceId')==SPEC['instance_id']
         and SPEC['instance_id']=='i-0cb486ae31a45d15e' and boot==SPEC['boot_id'],
         'EXACT_PINNED_DISPOSABLE_LAB_IDENTITY_REQUIRED')

def imds_identity():
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request=urllib.request.Request('http://169.254.169.254/latest/api/token',method='PUT',
            headers={'X-aws-ec2-metadata-token-ttl-seconds':'60'})
    with opener.open(request,timeout=2) as response:token=response.read(4097)
    need(0<len(token)<=4096,'IMDSV2_TOKEN_REQUIRED')
    request=urllib.request.Request('http://169.254.169.254/latest/dynamic/instance-identity/document',
            headers={'X-aws-ec2-metadata-token':token.decode('ascii')})
    with opener.open(request,timeout=2) as response:raw=response.read(65537)
    need(0<len(raw)<=65536,'BOUNDED_IMDS_IDENTITY_REQUIRED')
    return json.loads(raw)

def confirmed_run():
    inv=os.environ.get('INVOCATION_ID','')
    need(re.fullmatch('[0-9a-f]{32}',inv) is not None,'SYSTEMD_INVOCATION_REQUIRED')
    result=command('/usr/bin/systemctl','show',SPEC['unit'],'--property=Id,InvocationID,ControlGroup')
    rows=[row.split('=',1) for row in result.stdout.splitlines()]
    need(len(rows)==3 and len({k for k,v in rows})==3,'EXACT_SYSTEMD_CLEANUP_PROPERTIES_REQUIRED')
    props=dict(rows)
    need(props['Id']==SPEC['unit'] and props['InvocationID']==inv and props['ControlGroup']
         and Path('/proc/self/cgroup').read_text().splitlines()==['0::'+props['ControlGroup']],
         'EXACT_LAB_SYSTEMD_CLEANUP_INVOCATION_REQUIRED')
    path=Path('/var/lib/dakasa-elastic-lab-rehearsal-runs')/SPEC['nonce']
    try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    except FileNotFoundError:return False
    try:
        before=os.fstat(fd);raw=os.read(fd,4097);after=os.fstat(fd);named=os.lstat(path)
        stamp=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(stat.S_ISREG(before.st_mode) and before.st_uid==0 and stat.S_IMODE(before.st_mode)==0o600
             and before.st_nlink==1 and stamp(before)==stamp(after)==stamp(named) and len(raw)<=4096,
             'EXACT_ROOT_PRIVATE_RUN_RESERVATION_REQUIRED')
        need(json.loads(raw)=={'unit':SPEC['unit'],'boot_id':SPEC['boot_id'],'invocation_id':inv},
             'EXACT_ONE_SHOT_INVOCATION_REQUIRED')
    finally:os.close(fd)
    return True

def command(*args,check=True):
    result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=10)
    if check and result.returncode:raise Held('SYSTEMD_COMMAND_FAILED')
    return result

def props(unit):
    result=command('/usr/bin/systemctl','show',unit,'--all','--property=Id,Slice,MainPID,ActiveState,SubState,Job,ControlGroup')
    rows=[line.split('=',1) for line in result.stdout.splitlines()]
    need(len(rows)==7 and len({k for k,v in rows})==7,'EXACT_SYSTEMD_PROPERTIES_REQUIRED')
    return dict(rows)

def services():
    data=command('/usr/bin/systemctl','list-units','--all','--type=service','--plain','--no-legend','--no-pager').stdout
    out=[];start=time.monotonic()
    for line in data.splitlines():
        parts=line.split()
        if not parts:continue
        name=parts[1] if parts[0]=='●' else parts[0]
        need(name.endswith('.service'),'EXACT_SERVICE_INVENTORY_REQUIRED')
        if time.monotonic()-start>20:raise Held('BOUNDED_SERVICE_INVENTORY_REQUIRED')
        row=props(name)
        if row['Slice']==SPEC['slice'] or row['Slice'].startswith(SPEC['slice'][:-6]+'-'):out.append(row)
    return out

def allowed(name):
    nonce=SPEC['nonce']
    return re.fullmatch(r'ci-(?:guarded-precommit|rotation-holder)-'+nonce+r'-[0-9a-f]{32}\.service',name) is not None

def slice_cgroup():
    result=command('/usr/bin/systemctl','show',SPEC['slice'],'--all','--property=ControlGroup',check=False)
    need(result.returncode==0,'SLICE_STATE_UNAVAILABLE')
    parts=result.stdout.strip().split('=',1)
    need(len(parts)==2 and parts[0]=='ControlGroup','EXACT_SLICE_CGROUP_REQUIRED')
    if not parts[1]:return None
    path=parts[1]
    need(path.startswith('/system.slice/') and path.split('/')[-1]==SPEC['slice'] and '..' not in path.split('/'),
         'EXPECTED_LAB_SLICE_CGROUP_REQUIRED')
    return Path('/sys/fs/cgroup')/path.lstrip('/')

def no_foreign_tasks(group,rows):
    if group is None:return
    allowed_groups=[row['ControlGroup'] for row in rows if row['ControlGroup']]
    for directory,dirs,files in os.walk(group,followlinks=False):
        current=Path(directory)
        for name in dirs:need(not (current/name).is_symlink(),'CGROUP_SYMLINK_FORBIDDEN')
        if 'cgroup.procs' not in files:continue
        pids=(current/'cgroup.procs').read_text().strip()
        rel='/'+str(current.relative_to('/sys/fs/cgroup'))
        if pids:need(any(rel==g or rel.startswith(g+'/') for g in allowed_groups),'FOREIGN_TASK_IN_LAB_SLICE')

def cgroup_mount():
    matches=[]
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        parts=line.split(' - ',1)
        if len(parts)!=2:continue
        left=parts[0].split();right=parts[1].split()
        if len(left)>=6 and right and left[4]=='/sys/fs/cgroup':matches.append((left[0],left[2],left[3],right[0]))
    need(len(matches)==1 and matches[0][2]=='/' and matches[0][3]=='cgroup2','EXACT_CGROUP2_MOUNT_REQUIRED')
    fd=os.open('/sys/fs/cgroup',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd);data=ctypes.create_string_buffer(256);libc=ctypes.CDLL(None,use_errno=True)
        need(libc.fstatfs(fd,ctypes.byref(data))==0 and ctypes.c_long.from_buffer(data).value==0x63677270,'CGROUP2_STATFS_REQUIRED')
        return (matches[0],st.st_dev,st.st_ino,os.readlink('/proc/self/ns/mnt'),os.readlink('/proc/self/ns/cgroup'))
    finally:os.close(fd)

def main():
    need(os.geteuid()==0,'ROOT_LAB_CLEANUP_REQUIRED')
    validate_identity(imds_identity(),Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    if not confirmed_run():
        print('NO_LAB_RUN_RESERVED_NO_CLEANUP',flush=True);return
    mount=cgroup_mount()
    rows=services();need(all(allowed(row['Id']) for row in rows),'FOREIGN_UNIT_IN_LAB_SLICE')
    group=slice_cgroup();no_foreign_tasks(group,rows)
    if rows or group is not None:
        command('/usr/bin/systemctl','stop',SPEC['slice'])
    end=time.monotonic()+10
    while True:
        need(cgroup_mount()==mount,'CGROUP_MOUNT_CHANGED')
        remaining=[row for row in services() if row['MainPID']!='0' or row['Job'] or row['ActiveState'] not in ('inactive','failed')]
        group=slice_cgroup()
        if not remaining and (group is None or not group.exists() or 'populated 0' in (group/'cgroup.events').read_text()):break
        if time.monotonic()>=end:raise Held('LAB_AUXILIARY_SLICE_NOT_TERMINAL')
        time.sleep(.05)
    # A persistent holder unit can remain after a SIGKILL. Remove only the
    # exact nonce-bearing fixture unit once its systemd state is terminal and
    # its root-owned contents match the fixed slice and runtime script path.
    need(cgroup_mount()==mount,'CGROUP_MOUNT_CHANGED')
    changed=False
    pattern='ci-rotation-holder-'+SPEC['nonce']+'-*.service'
    for path in Path('/run/systemd/system').glob(pattern):
        need(allowed(path.name),'FOREIGN_HOLDER_UNIT_FILENAME')
        before=os.lstat(path);need(stat.S_ISREG(before.st_mode) and before.st_uid==0
            and before.st_nlink==1 and not before.st_mode&0o022,'ROOT_OWNED_HOLDER_UNIT_REQUIRED')
        raw=path.read_text();runtime='/run/'+SPEC['runtime_directory']+'/source'
        expected=(r'\[Service\]\nType=simple\nSlice='+re.escape(SPEC['slice'])+
             r'\nRuntimeMaxSec=20s\nExecStart=/usr/bin/nsenter --net=/proc/[0-9]+/ns/net /usr/bin/python3 -B '+
             re.escape(runtime)+r'/runtime/ci_holder_process\.py '+re.escape(runtime)+r'/guardian47\.sock '+
             re.escape(runtime)+r'/holder-go '+re.escape(runtime)+r'/holder-acquired '+re.escape(runtime)+r'/holder-revoked\n')
        need(re.fullmatch(expected,raw) is not None,'EXACT_RUN_HOLDER_UNIT_CONTENT_REQUIRED')
        state=props(path.name)
        need(state['Id']==path.name and state['MainPID']=='0' and state['Job']==''
             and state['ActiveState'] in ('inactive','failed'),'HOLDER_UNIT_NOT_TERMINAL')
        after=os.lstat(path)
        need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==
             (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'HOLDER_UNIT_CHANGED_DURING_CLEANUP')
        path.unlink();changed=True
    if changed:command('/usr/bin/systemctl','daemon-reload')
    print('LAB_AUXILIARY_CLEANUP_CONFIRMED',flush=True)

if __name__=='__main__':main()
