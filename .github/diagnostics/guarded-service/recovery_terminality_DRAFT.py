"""CI/LAB-only building block: pin live systemd sender, later prove terminal.

Not a recovery permit. Assumes a separate trusted custodian remains alive and
retains pidfd from before exit. Does not prove kernel effects, socket transfer,
marker integrity, netlink quiescence, safe namespace or permission to send.
"""
import os,select,subprocess,time
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
    def __init__(self,verified,boot,netns,capability):
        need(capability is _CAPABILITY,'ONLY_AUTHENTICATED_LIVE_SENDER')
        self.verified=verified;self.boot=boot;self.netns=netns;self.pid=os.getpid()
        self.capability=capability;self.closed=False
    def close(self):
        if not self.closed:self.closed=True;os.close(self.verified['pidfd'])

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
        return SenderAnchor(peer,boot,netns,_CAPABILITY)
    except BaseException:
        os.close(peer['pidfd']);raise

def _populated(cgroup):
    need(cgroup.startswith('/system.slice/') and '..' not in cgroup.split('/'),'EXACT_SYSTEMD_CGROUP')
    directory=Path('/sys/fs/cgroup')/cgroup.lstrip('/')
    try:
        fd=os.open(directory/'cgroup.events',os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    except FileNotFoundError:return False
    try:
        rows=os.read(fd,4096).decode().splitlines()
    finally:os.close(fd)
    values=dict(row.split(' ',1) for row in rows)
    need(values.get('populated') in ('0','1'),'EXACT_CGROUP_POPULATED_EVENT')
    return values['populated']=='1'

def prove_terminal(anchor):
    """Read-only proof for this anchor; never mints any write authority."""
    need(type(anchor) is SenderAnchor and anchor.capability is _CAPABILITY and not anchor.closed
         and anchor.pid==os.getpid(),'LIVE_SAME_CUSTODIAN_ANCHOR_REQUIRED')
    v=anchor.verified
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==anchor.boot,'SAME_BOOT_REQUIRED')
    poll=select.poll();poll.register(v['pidfd'],select.POLLIN|select.POLLHUP|select.POLLERR)
    need(bool(poll.poll(0)),'ORIGINAL_SENDER_STILL_ALIVE')
    first=_systemd(v['unit'])
    need(first['Id']==v['unit'] and first['InvocationID']==v['invocation_id']
         and first['MainPID']=='0' and first['ActiveState'] in ('inactive','failed')
         and first['SubState'] in ('dead','failed') and first['Job'] in ('','0'),
         'SAME_TERMINAL_INVOCATION_WITHOUT_JOB_REQUIRED')
    need(not _populated(v['control_group']),'SENDER_CGROUP_OR_DESCENDANTS_STILL_POPULATED')
    second=_systemd(v['unit'])
    need(second==first and not _populated(v['control_group']) and bool(poll.poll(0)),
         'TERMINAL_STATE_MUST_REMAIN_STABLE')
    return {'schema':'ci_original_sender_terminality_v1','unit':v['unit'],'pid':v['pid'],
            'start_ticks':v['start_ticks'],'invocation_id':v['invocation_id'],
            'control_group':v['control_group'],'boot_id':anchor.boot,'netns':anchor.netns,
            'pidfd_dead':True,'cgroup_unpopulated':True,'effect_or_send_authority':False}
