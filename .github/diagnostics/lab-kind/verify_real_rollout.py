"""Run bounded isolated-namespace real Kind reader rollout; never production.

Imports the exact local lab_kind_core_source. Uses only one freshly generated
namespace; cleanup sends one UID-preconditioned namespace DELETE and reconciles.
The test does not exercise Guardian, drain fence, nft or controller.main.
"""
import json,os,re,subprocess,sys,time,urllib.request
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'controller-integration'/'runtime'))
import lab_kind_core_source as source

INSTANCE='i-0cb486ae31a45d15e';BOOT='fc2c144a-7ea5-45a9-b6e5-180bb07166f2'
CLUSTER_UID='5c93e9ce-67a5-4250-ab96-eea2be78322d'
NODE='dakasa-lab-control-plane';OLD='python:3.12-alpine';NEW='python:3.13-alpine'
nonce=os.environ.get('LAB_TRIAL_NONCE','')
if re.fullmatch('[0-9a-f]{12}',nonce) is None:raise RuntimeError('EXACT_RANDOM_LAB_TRIAL_NONCE_REQUIRED')
namespace='lab-elastic-'+nonce
kubectl=['/usr/bin/docker','exec','-i',NODE,'kubectl','--request-timeout=5s']

def checked(args,*,data=None,timeout=10):
    p=subprocess.run(args,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
    if p.returncode:raise RuntimeError('LAB_COMMAND_FAILED:'+str(args[-3:])+':'+p.stderr.decode(errors='replace')[-500:])
    return p.stdout

def kube(*args,data=None,timeout=10):return checked(kubectl+list(args),data=data,timeout=timeout)
def get(*args):return json.loads(kube('get',*args,'-o','json'))
def create(obj):return json.loads(kube('create','-f','-','-o','json',data=json.dumps(obj).encode()))
def wait_for(fn,seconds,reason):
    end=time.monotonic()+seconds;last=None
    while time.monotonic()<end:
        try:
            result=fn()
            if result:return result
        except (source.Held,RuntimeError,KeyError,ValueError,subprocess.TimeoutExpired) as error:last=str(error)
        time.sleep(.5)
    raise RuntimeError(reason+':'+str(last))

def exact_lab():
    if os.geteuid()!=0 or Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=BOOT:raise RuntimeError('EXACT_LAB_BOOT_REQUIRED')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req=urllib.request.Request('http://169.254.169.254/latest/api/token',method='PUT',headers={'X-aws-ec2-metadata-token-ttl-seconds':'60'})
    with opener.open(req,timeout=2) as r:token=r.read(4097)
    if not 0<len(token)<=4096:raise RuntimeError('IMDS_TOKEN_REQUIRED')
    req=urllib.request.Request('http://169.254.169.254/latest/dynamic/instance-identity/document',headers={'X-aws-ec2-metadata-token':token.decode('ascii')})
    with opener.open(req,timeout=2) as r:doc=json.loads(r.read(65537))
    if (doc.get('accountId'),doc.get('region'),doc.get('instanceId'))!=('153828470928','us-east-1',INSTANCE):raise RuntimeError('EXACT_LAB_INSTANCE_REQUIRED')
    if get('namespace','kube-system')['metadata']['uid']!=CLUSTER_UID:raise RuntimeError('EXACT_LAB_CLUSTER_UID_REQUIRED')
    if get('validatingwebhookconfigurations').get('items'):raise RuntimeError('UNEXPECTED_LAB_VALIDATING_WEBHOOK')
    return checked(['/usr/bin/docker','inspect','-f','{{.Id}}',NODE]).decode().strip()

def pod_obj(name,image):
    return {'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':namespace},
            'spec':{'nodeName':NODE,'restartPolicy':'Never','containers':[{'name':'core','image':image,
                    'imagePullPolicy':'IfNotPresent','command':['python3','-c','import time; time.sleep(600)']}]}}

def pin_image(name,image):
    create(pod_obj(name,image))
    def ready_probe():
        value=get('pod',name,'-n',namespace)
        states=value.get('status',{}).get('containerStatuses',[])
        return value if len(states)==1 and states[0].get('ready') and states[0].get('imageID') else None
    pod=wait_for(ready_probe,100,'IMAGE_PROBE_NOT_READY_'+name);state=pod['status']['containerStatuses'][0]
    if pod['spec']['containers'][0]['image']!=image or not state.get('ready') or not state.get('imageID'):
        raise RuntimeError('EXACT_IMAGE_PROBE_REQUIRED')
    return state['imageID']

def deployment():
    labels={'app':'lab-core','trial':nonce}
    return {'apiVersion':'apps/v1','kind':'Deployment','metadata':{'name':'lab-core','namespace':namespace},
        'spec':{'replicas':1,'strategy':{'type':'RollingUpdate','rollingUpdate':{'maxSurge':1,'maxUnavailable':0}},
            'selector':{'matchLabels':labels},'template':{'metadata':{'labels':labels},'spec':{'nodeName':NODE,
             'containers':[{'name':'core','image':OLD,'imagePullPolicy':'IfNotPresent',
                 'command':['sh','-c','sleep 12; exec python3 -m http.server 9443 --bind 0.0.0.0'],
                 'ports':[{'name':'core-http','containerPort':9443,'protocol':'TCP'}],
                 'readinessProbe':{'tcpSocket':{'port':9443},'periodSeconds':1}}]}}}}

def service():
    return {'apiVersion':'v1','kind':'Service','metadata':{'name':'lab-core','namespace':namespace},
        'spec':{'clusterIP':'None','selector':{'app':'lab-core','trial':nonce},
                'ports':[{'name':'core','protocol':'TCP','port':9000,'targetPort':'core-http'}]}}

def cleanup(expected_uid):
    # Exact UID precondition in the API server closes name-reuse races.
    if expected_uid is None:return
    current=get('namespace',namespace)
    if current['metadata']['uid']!=expected_uid or current['metadata'].get('annotations',{}).get('lab.dakasa.invalid/run')!=nonce:
        raise RuntimeError('OWN_NAMESPACE_IDENTITY_CHANGED_NO_DELETE')
    opts={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':expected_uid},'propagationPolicy':'Foreground'}
    try:kube('delete','--raw=/api/v1/namespaces/'+namespace,'-f','-',data=json.dumps(opts).encode(),timeout=12)
    except (RuntimeError,subprocess.TimeoutExpired):
        # Do not replay an uncertain deletion. Reconcile by reading the same UID.
        current=get('namespace',namespace)
        if current['metadata']['uid']!=expected_uid or not current['metadata'].get('deletionTimestamp'):
            raise RuntimeError('NAMESPACE_DELETE_OUTCOME_UNKNOWN_NO_REPLAY')
    print('OWN_NAMESPACE_UID_PRECONDITIONED_DELETE_ACCEPTED',flush=True)
    end=time.monotonic()+60
    while time.monotonic()<end:
        raw=kube('get','namespace',namespace,'--ignore-not-found=true','-o','json')
        if not raw.strip():
            print('OWN_NAMESPACE_ABSENCE_CONFIRMED',flush=True);return
        current=json.loads(raw)
        if current['metadata']['uid']!=expected_uid:raise RuntimeError('NAMESPACE_REPLACED_DURING_CLEANUP')
        time.sleep(1)
    raise RuntimeError('OWN_NAMESPACE_TERMINATION_NOT_CONFIRMED')

ns_uid=None
try:
    node_container_id=exact_lab()
    print('RUN_NAMESPACE '+namespace,flush=True)
    nsobj={'apiVersion':'v1','kind':'Namespace','metadata':{'name':namespace,'annotations':{'lab.dakasa.invalid/run':nonce}}}
    try:ns=create(nsobj)
    except (RuntimeError,subprocess.TimeoutExpired):
        # An uncertain create may be reconciled, never repeated.
        ns=get('namespace',namespace)
        if ns['metadata'].get('annotations',{}).get('lab.dakasa.invalid/run')!=nonce:raise
    ns_uid=ns['metadata']['uid']
    old_id=pin_image('old-probe',OLD);new_id=pin_image('new-probe',NEW)
    if old_id==new_id:raise RuntimeError('DISTINCT_IMAGE_IDS_REQUIRED')
    svc=create(service());dep=create(deployment());node=get('node',NODE)
    spec=source.Spec(container_id=node_container_id,container_name=NODE,namespace=namespace,cluster_uid=CLUSTER_UID,
        namespace_uid=ns_uid,service='lab-core',service_uid=svc['metadata']['uid'],selector=tuple(sorted(svc['spec']['selector'].items())),
        deployment='lab-core',owner_uid=dep['metadata']['uid'],pod_container_name='core',image_pairs=((OLD,old_id),(NEW,new_id)),
        service_port=9000,endpoint_port=9443,protocol='TCP',node=NODE,node_uid=node['metadata']['uid'],pod_network='10.244.0.0/16')
    reader=source.Source(spec)
    first=wait_for(lambda:(r if (r:=reader.observe())['desired_ready'] and r['desired_image']==OLD else None),90,'OLD_NOT_READY')
    old_uid=first['desired_ready_endpoints'][0]['pod_uid']
    print('PASS initial old Ready; actual Service port 9000 maps to Pod port 9443',flush=True)
    def rotate(image,old_anchor,label):
        kube('set','image','deployment/lab-core','core='+image,'-n',namespace)
        pending=wait_for(lambda:(r if (r:=reader.observe())['desired_image']==image and not r['desired_ready']
                    and any(x['pod_uid']==old_anchor for x in r['ready_endpoints']) else None),30,'OLD_ANCHOR_NOT_OBSERVED_WHILE_PENDING_'+label)
        assert not pending['transactional_witness'] and not pending['effect_or_production_authority']
        print('PASS '+label+' desired not Ready, prior qualified endpoint still visible',flush=True)
        ready=wait_for(lambda:(r if (r:=reader.observe())['desired_image']==image and r['desired_ready'] else None),90,'DESIRED_NOT_READY_'+label)
        selected=ready['desired_ready_endpoints'][0]
        assert selected['pod_uid']!=old_anchor
        print('PASS '+label+' desired actual Pod/ReplicaSet/imageID becomes Ready',flush=True)
        return selected['pod_uid']
    new_uid=rotate(NEW,old_uid,'FORWARD')
    rotate(OLD,new_uid,'ROLLBACK')
    print('BOUNDARY real Kind API+route observations only; no Guardian, fence, traffic or controller.main',flush=True)
finally:
    cleanup(ns_uid)
