"""CI/LAB-only building block: pin live systemd sender, later prove terminal.

Not a recovery permit. Assumes a separate trusted custodian remains alive and
retains pidfd from before exit. Does not prove kernel effects, socket transfer,
marker integrity, netlink quiescence, safe namespace or permission to send.
"""
import ctypes,os,select,subprocess,time
from pathlib import Path
import guarded_unit_identity as identity

_CAPABILITY=object()
class Held(RuntimeError):pass

def need(value,reason):
    if not value:raise Held(reason)

def _systemd(unit):
    properties='Id,MainPID,ExecMainPID,InvocationID,ActiveState,SubState,ControlGroup,Job'
    out=subprocess.run(['/usr/bin/systemctl','show','--all',unit,'--property='+properties],
                       stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3,check=True).stdout.decode()
    rows=[line.split('=',1) for line in out.splitlines()]
    need(len(rows)==8 and len({k for k,v in rows})==8,'EXACT_SYSTEMD_TERMINAL_PROPERTIES')
    return dict(rows)

class SenderAnchor:
    def __init__(self,verified,boot,netns,cgroup_root,capability):
        need(capability is _CAPABILITY,'ONLY_AUTHENTICATED_LIVE_SENDER')
        self.verified=verified;self.boot=boot;self.netns=netns;self.cgroup_root=cgroup_root;self.pid=os.getpid()
        self.capability=capability;self.closed=False
    def close(self):
        if not self.closed:
            self.closed=True;os.close(self.verified['pidfd']);self.cgroup_root.close()

def capture_authenticated(channel,*,unit,invocation,argv,source_sha256):
    """Real peer credentials/systemd/source validation while the peer is live."""
    peer=identity.authenticate(channel,unit=unit,expected_invocation=invocation,
              expected_argv=argv,source_sha256=source_sha256)
    try:
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        netns=os.readlink('/proc/%d/ns/net'%peer['pid'])
        again=identity._properties(unit)
        need(again['ActiveState']=='active' and again['MainPID']==str(peer['pid'])
             and again['InvocationID']==invocation and again['ControlGroup']==peer['control_group'],
             'SAME_LIVE_SENDER_AFTER_CAPTURE')
        return SenderAnchor(peer,boot,netns,_CgroupRoot(peer['control_group']),_CAPABILITY)
    except BaseException:
        os.close(peer['pidfd']);raise

class _CgroupRoot:
    """Pin exact cgroup2 mount and system.slice while authenticated peer lives."""
    def __init__(self,cgroup):
        parts=cgroup.split('/')
        need(len(parts)==3 and parts[0]=='' and parts[1]=='system.slice'
             and parts[2] and parts[2] not in ('.','..'),'EXACT_SYSTEMD_CGROUP')
        self.name=parts[2]
        self.mount_ns=os.readlink('/proc/self/ns/mnt')
        self.cgroup_ns=os.readlink('/proc/self/ns/cgroup')
        self.mount=self._mountinfo()
        self.root=os.open('/sys/fs/cgroup',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
        try:
            self.slice=os.open('system.slice',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=self.root)
            self.root_stat=self._key(os.fstat(self.root));self.slice_stat=self._key(os.fstat(self.slice))
            self._validate()
        except BaseException:
            if hasattr(self,'slice'):os.close(self.slice)
            os.close(self.root);raise
    @staticmethod
    def _key(st):return (st.st_dev,st.st_ino)
    @staticmethod
    def _mountinfo():
        matches=[]
        for line in Path('/proc/self/mountinfo').read_text().splitlines():
            fields=line.split(' - ',1)
            if len(fields)!=2:continue
            left=fields[0].split();right=fields[1].split()
            if len(left)>=6 and len(right)>=1 and left[4]=='/sys/fs/cgroup':
                matches.append((left[0],left[1],left[2],left[3],left[4],right[0]))
        need(len(matches)==1 and matches[0][3]=='/' and matches[0][5]=='cgroup2',
             'EXACT_UNIFIED_CGROUP_MOUNT_REQUIRED')
        return matches[0]
    def _validate(self):
        need(os.readlink('/proc/self/ns/mnt')==self.mount_ns
             and os.readlink('/proc/self/ns/cgroup')==self.cgroup_ns
             and self._mountinfo()==self.mount,'CGROUP_MOUNT_OR_NAMESPACE_CHANGED')
        st=os.stat('/sys/fs/cgroup',follow_symlinks=False)
        need(self._key(st)==self.root_stat==self._key(os.fstat(self.root)),
             'CGROUP_ROOT_CHANGED')
        need(self._key(os.stat('system.slice',dir_fd=self.root,follow_symlinks=False))
             ==self.slice_stat==self._key(os.fstat(self.slice)),'CGROUP_SLICE_CHANGED')
        data=ctypes.create_string_buffer(256)
        libc=ctypes.CDLL(None,use_errno=True)
        need(libc.fstatfs(self.root,ctypes.byref(data))==0
             and ctypes.c_long.from_buffer(data).value==0x63677270,'CGROUP2_STATFS_REQUIRED')
    def populated(self):
        self._validate()
        try:
            directory=os.open(self.name,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=self.slice)
        except FileNotFoundError:
            # Absence only counts after checking the same real mount/slice twice.
            self._validate()
            try:os.stat(self.name,dir_fd=self.slice,follow_symlinks=False)
            except FileNotFoundError:return False
            raise Held('CGROUP_APPEARED_DURING_ABSENCE_CHECK')
        try:
            fd=os.open('cgroup.events',os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=directory)
            try:rows=os.read(fd,4096).decode().splitlines()
            finally:os.close(fd)
            values=dict(row.split(' ',1) for row in rows)
            need(values.get('populated') in ('0','1'),'EXACT_CGROUP_POPULATED_EVENT')
            self._validate()
            return values['populated']=='1'
        finally:os.close(directory)
    def close(self):os.close(self.slice);os.close(self.root)

def _pidfd_terminal(pidfd):
    poll=select.poll();poll.register(pidfd,select.POLLIN|select.POLLHUP|select.POLLERR)
    events=poll.poll(0)
    need(all(not (mask & (select.POLLNVAL|select.POLLERR)) for _,mask in events),
         'PIDFD_ERROR_IS_NOT_TERMINAL_PROOF')
    return len(events)==1 and bool(events[0][1] & (select.POLLIN|select.POLLHUP))

def prove_terminal(anchor):
    """Read-only proof for this anchor; never mints any write authority."""
    need(type(anchor) is SenderAnchor and anchor.capability is _CAPABILITY and not anchor.closed
         and anchor.pid==os.getpid(),'LIVE_SAME_CUSTODIAN_ANCHOR_REQUIRED')
    v=anchor.verified
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==anchor.boot,'SAME_BOOT_REQUIRED')
    need(_pidfd_terminal(v['pidfd']),'ORIGINAL_SENDER_STILL_ALIVE')
    first=_systemd(v['unit'])
    need(first['Id']==v['unit'] and first['InvocationID']==v['invocation_id']
         and first['MainPID']=='0' and first['ActiveState'] in ('inactive','failed')
         and first['SubState'] in ('dead','failed') and first['Job'] in ('','0'),
         'SAME_TERMINAL_INVOCATION_WITHOUT_JOB_REQUIRED')
    need(not anchor.cgroup_root.populated(),'SENDER_CGROUP_OR_DESCENDANTS_STILL_POPULATED')
    second=_systemd(v['unit'])
    need(second==first and not anchor.cgroup_root.populated() and _pidfd_terminal(v['pidfd']),
         'TERMINAL_STATE_MUST_REMAIN_STABLE')
    return {'schema':'ci_original_sender_terminality_v1','unit':v['unit'],'pid':v['pid'],
            'start_ticks':v['start_ticks'],'invocation_id':v['invocation_id'],
            'control_group':v['control_group'],'boot_id':anchor.boot,'netns':anchor.netns,
            'pidfd_dead':True,'cgroup_unpopulated':True,'effect_or_send_authority':False}

class MarkerAnchor:
    """Read-only marker snapshot held by the same live pidfd custodian."""
    def __init__(self,sender,coordinator,key,capability):
        need(capability is _CAPABILITY,'MARKER_ANCHOR_MUST_BE_AUTHENTICATED')
        self.sender,self.coordinator,self.key=sender,coordinator,key
        self.capability=capability;self.pid=os.getpid()

def capture_marker(sender,coordinator):
    """Pin exact durable marker while its authenticated owner is still alive.

    Assumes trusted v3 implementation, directory and all participating writers.
    The snapshot is evidence only, never an authorization to send or clear it.
    """
    import drain_marker_v3_DRAFT as v3
    need(type(sender) is SenderAnchor and sender.capability is _CAPABILITY
         and sender.pid==os.getpid() and not sender.closed,'LIVE_SENDER_ANCHOR_REQUIRED')
    need(type(coordinator) is v3.CoordinatorV3,'EXACT_V3_COORDINATOR_REQUIRED')
    need(not _pidfd_terminal(sender.verified['pidfd']),'SENDER_ALREADY_TERMINAL')
    marker=v3._durable_marker_identity(coordinator);record=marker[3];v=sender.verified
    need(all(record.get(k)==v[k] for k in ('pid','start_ticks','unit','invocation_id','control_group'))
         and record.get('boot_id')==sender.boot and record.get('netns')==sender.netns,
         'MARKER_OWNER_DIFFERS_FROM_ANCHORED_SENDER')
    props=identity._properties(v['unit'])
    need(props['MainPID']==str(v['pid']) and props['InvocationID']==v['invocation_id']
         and props['ControlGroup']==v['control_group'] and props['ActiveState']=='active'
         and not _pidfd_terminal(v['pidfd']),'SAME_LIVE_SENDER_REQUIRED')
    return MarkerAnchor(sender,coordinator,marker[:3],_CAPABILITY)

def prove_terminal_for_marker(anchor):
    """Momentary read-only proof; callers must keep writers/restarts fenced."""
    import drain_marker_v3_DRAFT as v3
    need(type(anchor) is MarkerAnchor and anchor.capability is _CAPABILITY
         and anchor.pid==os.getpid(),'SAME_CUSTODIAN_MARKER_ANCHOR_REQUIRED')
    need(v3._marker_identity(anchor.coordinator)[:3]==anchor.key,'ORIGINAL_MARKER_CHANGED')
    proof=prove_terminal(anchor.sender)
    need(v3._marker_identity(anchor.coordinator)[:3]==anchor.key,'ORIGINAL_MARKER_CHANGED')
    proof.update({'marker_device':anchor.key[0],'marker_inode':anchor.key[1],
                  'marker_sha256':anchor.key[2], 'durable_authority':False})
    return proof
