"""Read-only actual Kind Kubernetes/route Core source; no mutation authority.

The caller must supply an independently reviewed, root-sealed LAB identity.
This module neither discovers authority nor connects itself to controller.main.
"""
import ipaddress,json,os,re,subprocess,time
from dataclasses import dataclass

class Held(RuntimeError):pass

def need(value,guard):
    if not value:raise Held(guard)

def uid(value):
    return isinstance(value,str) and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value) is not None

def name(value):
    return isinstance(value,str) and re.fullmatch(r'[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?',value) is not None

@dataclass(frozen=True)
class Spec:
    container_id:str
    container_name:str
    namespace:str
    cluster_uid:str
    namespace_uid:str
    service:str
    service_uid:str
    selector:tuple
    deployment:str
    owner_uid:str
    pod_container_name:str
    image_pairs:tuple
    service_port:int
    endpoint_port:int
    protocol:str
    node:str
    node_uid:str
    pod_network:str
    def validate(self):
        need(re.fullmatch('[a-f0-9]{64}',self.container_id) is not None,'EXACT_KIND_CONTAINER_ID_REQUIRED')
        need(self.container_name=='dakasa-lab-control-plane','ONLY_EXACT_LAB_KIND_NODE')
        need(all(name(x) for x in (self.namespace,self.service,self.deployment,self.pod_container_name,self.node)) and
             all(uid(x) for x in (self.cluster_uid,self.namespace_uid,self.service_uid,self.owner_uid,self.node_uid)),
             'EXACT_KUBERNETES_NAMES_AND_UIDS_REQUIRED')
        need(type(self.selector) is tuple and self.selector and all(type(k) is str and type(v) is str and k and v
             for k,v in self.selector) and len(dict(self.selector))==len(self.selector),'EXACT_SELECTOR_REQUIRED')
        need(type(self.image_pairs) is tuple and 1<=len(self.image_pairs)<=2
             and all(type(x) is tuple and len(x)==2 and all(type(v) is str and v for v in x) for x in self.image_pairs)
             and len(dict(self.image_pairs))==len(self.image_pairs)
             and type(self.service_port) is int and 0<self.service_port<65536
             and type(self.endpoint_port) is int and 0<self.endpoint_port<65536
             and self.protocol in ('TCP','UDP'),'EXACT_IMAGE_AND_SERVICE_PORT_REQUIRED')
        network=ipaddress.ip_network(self.pod_network,strict=True)
        need(network.version==4 and network.is_private,'PRIVATE_LAB_POD_NETWORK_REQUIRED')

class Source:
    def __init__(self,spec):
        need(type(spec) is Spec,'SEALED_KIND_SPEC_REQUIRED');spec.validate();self.spec=spec
    def _command(self,argv,*,deadline,cap=2*1024*1024):
        left=deadline-time.monotonic();need(left>0,'ORIGINAL_READ_DEADLINE_EXPIRED')
        p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=min(4,left),check=False)
        need(p.returncode==0 and 0<len(p.stdout)<=cap and time.monotonic()<deadline,'BOUNDED_ORIGINAL_KIND_READ_REQUIRED')
        return p.stdout
    def _container(self,deadline):
        raw=self._command(['/usr/bin/docker','inspect','-f','{{.Id}} {{.State.Pid}} {{.State.Running}}',self.spec.container_name],deadline=deadline,cap=1024).decode().strip().split()
        need(len(raw)==3 and raw[0]==self.spec.container_id and raw[2]=='true' and raw[1].isdigit() and int(raw[1])>1,
             'SAME_LIVE_KIND_CONTAINER_REQUIRED')
        pid=int(raw[1]);text=open('/proc/%d/stat'%pid,'rb').read();ticks=int(text[text.rfind(b')')+1:].split()[19])
        return (raw[0],pid,ticks,os.readlink('/proc/%d/ns/net'%pid))
    def _get(self,deadline,*args):
        argv=['/usr/bin/docker','exec',self.spec.container_name,'kubectl','--request-timeout=3s','get',*args,'-o','json']
        return json.loads(self._command(argv,deadline=deadline))
    def observe(self):
        start=time.monotonic();deadline=start+8.0;s=self.spec
        before=self._container(deadline)
        cluster=self._get(deadline,'namespace','kube-system')
        need(cluster['metadata']['uid']==s.cluster_uid,'SAME_KIND_CLUSTER_UID_REQUIRED')
        ns=self._get(deadline,'namespace',s.namespace)
        need(ns['metadata']['uid']==s.namespace_uid and ns['metadata'].get('deletionTimestamp') is None,
             'SAME_LIVE_NAMESPACE_REQUIRED')
        svc=self._get(deadline,'service',s.service,'-n',s.namespace)
        service_ports=[x for x in svc['spec'].get('ports',[]) if x.get('port')==s.service_port and x.get('protocol','TCP')==s.protocol]
        need(svc['metadata']['uid']==s.service_uid and svc['metadata'].get('deletionTimestamp') is None and
             svc['spec'].get('selector')==dict(s.selector) and len(service_ports)==1,
             'SAME_SERVICE_UID_SELECTOR_AND_PORT_REQUIRED')
        target=service_ports[0].get('targetPort',s.service_port)
        need((type(target) is int and target==s.endpoint_port) or (type(target) is str and name(target)),
             'SERVICE_TARGET_PORT_MAPPING_REQUIRED')
        deployment=self._get(deadline,'deployment',s.deployment,'-n',s.namespace)
        desired=[x for x in deployment['spec']['template']['spec']['containers'] if x.get('name')==s.pod_container_name]
        need(deployment['metadata']['uid']==s.owner_uid and deployment['metadata'].get('deletionTimestamp') is None
             and len(desired)==1 and desired[0].get('image') in dict(s.image_pairs),
             'EXACT_DEPLOYMENT_AND_DESIRED_IMAGE_REQUIRED')
        desired_image=desired[0]['image']
        slices=self._get(deadline,'endpointslices','-n',s.namespace,'-l','kubernetes.io/service-name='+s.service)
        need(not slices.get('metadata',{}).get('continue') and len(slices.get('items',[]))<=32,'COMPLETE_BOUNDED_ENDPOINT_SLICES_REQUIRED')
        candidates=[]
        for obj in slices.get('items',[]):
            need(obj.get('addressType')=='IPv4','IPV4_ENDPOINT_SLICE_REQUIRED')
            owners=obj['metadata'].get('ownerReferences',[])
            need(any(x.get('kind')=='Service' and x.get('uid')==s.service_uid for x in owners),'ENDPOINT_SLICE_SERVICE_UID_REQUIRED')
            if not any(x.get('port')==s.endpoint_port and x.get('protocol','TCP')==s.protocol for x in obj.get('ports',[])):continue
            for ep in obj.get('endpoints',[]):
                cond=ep.get('conditions',{});ref=ep.get('targetRef',{});addresses=ep.get('addresses',[])
                if cond.get('ready') is not True or cond.get('serving') is not True or cond.get('terminating') is True:continue
                need(ref.get('kind')=='Pod' and ref.get('namespace')==s.namespace and uid(ref.get('uid'))
                     and name(ref.get('name')) and len(addresses)==1 and ep.get('nodeName')==s.node,
                     'EXACT_READY_ENDPOINT_POD_REQUIRED')
                address=str(ipaddress.IPv4Address(addresses[0]));need(ipaddress.IPv4Address(address) in ipaddress.IPv4Network(s.pod_network),'LAB_POD_CIDR_REQUIRED')
                candidates.append((ref['name'],ref['uid'],address))
        need(0<len(candidates)<=8 and len(set(candidates))==len(candidates),'UNIQUE_READY_ENDPOINTS_REQUIRED')
        observations=[]
        for pod_name,pod_uid,address in sorted(candidates):
            pod=self._get(deadline,'pod',pod_name,'-n',s.namespace);meta=pod['metadata'];status=pod['status']
            need(meta['uid']==pod_uid and meta.get('deletionTimestamp') is None and status.get('podIP')==address
                 and pod['spec'].get('nodeName')==s.node and all(meta.get('labels',{}).get(k)==v for k,v in s.selector)
                 and any(x.get('type')=='Ready' and x.get('status')=='True' for x in status.get('conditions',[])),
                 'EXACT_READY_POD_REQUIRED')
            owners=[x for x in meta.get('ownerReferences',[]) if x.get('kind')=='ReplicaSet' and x.get('controller') is True]
            need(len(owners)==1 and uid(owners[0].get('uid')) and name(owners[0].get('name')),'ONE_REPLICASET_OWNER_REQUIRED')
            rs=self._get(deadline,'replicaset',owners[0]['name'],'-n',s.namespace)
            need(rs['metadata']['uid']==owners[0]['uid'] and any(x.get('kind')=='Deployment' and x.get('uid')==s.owner_uid
                 and x.get('controller') is True for x in rs['metadata'].get('ownerReferences',[])),
                 'EXACT_DEPLOYMENT_OWNER_CHAIN_REQUIRED')
            containers=[x for x in pod['spec']['containers'] if x.get('name')==s.pod_container_name]
            states=[x for x in status.get('containerStatuses',[]) if x.get('name')==s.pod_container_name]
            need(len(containers)==len(states)==1 and containers[0].get('image') in dict(s.image_pairs)
                 and states[0].get('ready') is True and states[0].get('imageID')==dict(s.image_pairs)[containers[0]['image']]
                 and isinstance(states[0].get('containerID'),str) and states[0]['containerID'],
                 'EXACT_LIVE_CONTAINER_IMAGE_PAIR_REQUIRED')
            if type(target) is str:
                need(any(x.get('name')==target and x.get('containerPort')==s.endpoint_port
                         and x.get('protocol','TCP')==s.protocol for x in containers[0].get('ports',[])),
                     'NAMED_CONTAINER_TARGET_PORT_REQUIRED')
            route=json.loads(self._command(['/usr/bin/nsenter','-t',str(before[1]),'-n','--','/usr/sbin/ip','-j','-4','route','get',address],deadline=deadline))
            need(len(route)==1 and route[0].get('type','unicast')=='unicast' and isinstance(route[0].get('dev'),str),
                 'ORIGINAL_KIND_POD_ROUTE_REQUIRED')
            observations.append({'pod':pod_name,'pod_uid':pod_uid,'address':address,'image':containers[0]['image'],
                'image_id':states[0]['imageID'],'route_device':route[0]['dev'],'resource_version':meta['resourceVersion'],
                'native_identity':pod_uid+'/'+states[0]['containerID']})
        desired_endpoints=[x for x in observations if x['image']==desired_image]
        node=self._get(deadline,'node',s.node)
        need(node['metadata']['uid']==s.node_uid and any(x.get('type')=='Ready' and x.get('status')=='True' for x in node['status'].get('conditions',[])),
             'SAME_READY_NODE_UID_REQUIRED')
        after_svc=self._get(deadline,'service',s.service,'-n',s.namespace)
        after_slices=self._get(deadline,'endpointslices','-n',s.namespace,'-l','kubernetes.io/service-name='+s.service)
        after_deployment=self._get(deadline,'deployment',s.deployment,'-n',s.namespace)
        def versions(value):
            return sorted((x['metadata']['uid'],x['metadata']['resourceVersion']) for x in value.get('items',[]))
        for row in observations:
            pod=self._get(deadline,'pod',row['pod'],'-n',s.namespace)
            need(pod['metadata']['uid']==row['pod_uid'] and pod['metadata']['resourceVersion']==row['resource_version']
                 and pod['metadata'].get('deletionTimestamp') is None and pod['status'].get('podIP')==row['address']
                 and any(x.get('type')=='Ready' and x.get('status')=='True' for x in pod['status'].get('conditions',[])),
                 'SAME_READY_POD_AFTER_READ')
        need(self._container(deadline)==before and self._get(deadline,'namespace','kube-system')['metadata']['uid']==s.cluster_uid
             and self._get(deadline,'namespace',s.namespace)['metadata']['uid']==s.namespace_uid
             and after_svc['metadata']['uid']==s.service_uid
             and after_svc['metadata']['resourceVersion']==svc['metadata']['resourceVersion']
             and after_deployment['metadata']['uid']==s.owner_uid
             and after_deployment['metadata']['resourceVersion']==deployment['metadata']['resourceVersion']
             and versions(after_slices)==versions(slices),'SAME_KIND_CLUSTER_SERVICE_AND_ENDPOINTS_AFTER_READ')
        returned=time.monotonic();need(returned<deadline,'ORIGINAL_READ_DEADLINE_EXPIRED')
        return {'schema':'lab_kind_real_core_observation_v1','cluster_uid':s.cluster_uid,'namespace_uid':s.namespace_uid,
                'service_uid':s.service_uid,'deployment_uid':s.owner_uid,'desired_image':desired_image,
                'desired_ready_endpoints':desired_endpoints,'ready_endpoints':observations,
                'desired_ready':bool(desired_endpoints),'node_uid':s.node_uid,
                'observed_started':start,'observed_returned':returned,'expires':deadline,
                'lab_only':True,'transactional_witness':False,'effect_or_production_authority':False}
