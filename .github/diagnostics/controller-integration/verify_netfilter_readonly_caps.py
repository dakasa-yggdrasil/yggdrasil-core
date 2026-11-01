"""Measure GETGEN and a rejected mutation without CAP_NET_ADMIN in private CI netns."""
import json,os,socket,struct,subprocess,sys
from pathlib import Path
root=Path(__file__).resolve().parent;sys.path.insert(0,str(root/'runtime'))
import guarded_nl as nl

def caps():
    rows=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    return {k:rows[k].strip() for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs')}

def netlink():
    sock=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12);sock.bind((0,0));sock.settimeout(3);return sock

if len(sys.argv)>1 and sys.argv[1]=='child':
    state=caps();mask=1<<12
    assert state['NoNewPrivs']=='1' and all(not int(state[k],16)&mask for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
    sock=netlink()
    try:
        sock.send(nl.msg((10<<8)|16,1,10,struct.pack('>BBH',0,0,0)))
        rows=nl.packets(sock.recv(8192));assert len(rows)==1
        if rows[0][0]==2:
            code=struct.unpack_from('<i',rows[0][2],0)[0];assert code<0
            readable=False;read_error=-code
        else:
            assert rows[0][0]==((10<<8)|15) and rows[0][1]==10
            readable=True;read_error=None
    finally:sock.close()
    attempt=subprocess.run(['/usr/sbin/nft','add','table','ip','ci_unprivileged_mutation_probe'],capture_output=True,timeout=5)
    assert attempt.returncode!=0,'UNPRIVILEGED_NFT_MUTATION_SUCCEEDED'
    print(json.dumps({'readable_getgen':readable,'read_errno':read_error,'mutation_denied':True,
                      'cap_net_admin_absent_all_sets':True,'no_new_privs':True},sort_keys=True),flush=True)
    sys.exit(0)

assert os.geteuid()==0 and os.environ.get('CI_HOST_NETNS') and os.readlink('/proc/self/ns/net')!=os.environ['CI_HOST_NETNS']
sock=netlink()
try:
    before=nl.genid(sock)
    result=subprocess.run(['/usr/bin/setpriv','--bounding-set=-net_admin','--inh-caps=-all','--ambient-caps=-all',
        '--no-new-privs','/usr/bin/python3','-B',str(Path(__file__).resolve()),'child'],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=True,text=True)
    observed=json.loads(result.stdout);assert observed['mutation_denied'] and nl.genid(sock)==before
    print('PASS unprivileged mutation rejected; kernel genid unchanged',flush=True)
    print('GETGEN_CAPABILITY_RESULT '+json.dumps(observed,sort_keys=True),flush=True)
    print('KERNEL_RELEASE '+os.uname().release,flush=True)
    if not observed['readable_getgen']:print('HOLD GETGEN cannot use a process stripped of CAP_NET_ADMIN on this kernel',flush=True)
finally:sock.close()
