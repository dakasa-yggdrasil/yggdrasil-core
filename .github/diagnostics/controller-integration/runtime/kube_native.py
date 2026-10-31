"""Original GET-only Brain/EKS endpoint readers. Credentials stay in memory."""
import base64
import ipaddress
import json
import os
import re
import ssl
import subprocess
import time
import urllib.parse
import urllib.request

from brain_https import Brain
import eks_https

from nft_owner import Backend, PrometheusSource, BRAIN, Held, MAX_FRESH_SECONDS, require

NS = 'dakasa'
CORE_SERVICE = 'yggdrasil-capacity-tls'
BROKER_SERVICE = 'rabbitmq-capacity-edge'
BROKER_UID = 'c8269dcb-9b03-48a7-824b-261fa40f9cc8'
BROKER_STS_UID = 'f427f832-8bdb-4e61-a5f1-fda98aaa93ac'
CORE_DEPLOYMENT_UID = 'fe633e07-9612-458a-b6ff-3fa8a403924f'
AWS_SECRET_UID = 'bdbd35fe-2b80-4654-958d-5e9087dead0c'
CORE_LABELS = {'app': 'yggdrasil', 'app.kubernetes.io/part-of': 'dakasa', 'dakasa.io/component': 'yggdrasil', 'dakasa.io/capacity-tls': 'overlay-v1'}
PROMETHEUS_STS_UID = 'b5c5eb57-31fe-4120-bb39-684663de4b60'
PROMETHEUS_CR_UID = 'df8028b3-7724-4d5d-ba35-2e40ccb874a9'
PROMETHEUS_SERVICE_UID = '238bb3ea-93a9-4c3e-9b67-439637b88827'
BRAIN_NODE_UID = '2795f56d-ae84-4d57-b142-2467ea68e50d'
PROMETHEUS_SELECTOR = {'app.kubernetes.io/instance':'dakasa', 'app.kubernetes.io/managed-by':'prometheus-operator', 'app.kubernetes.io/name':'prometheus', 'operator.prometheus.io/name':'dakasa', 'operator.prometheus.io/shard':'0', 'prometheus':'dakasa'}
PROMETHEUS_TEMPLATE_LABELS = {**PROMETHEUS_SELECTOR, 'app.kubernetes.io/version':'2.53.0'}
PROMETHEUS_IMAGES = {'config-reloader': '127.0.0.1:5000/lab/reloader@sha256:f5094ebf74f3e5fc1a4377debedca47fd1bd43610819a3574d2a5879a597669a', 'prometheus': '127.0.0.1:5000/lab/prometheus@sha256:546fd0981693fd4fdab42200e8951943839a85797f503b26bc9016469f5724db'}
PROMETHEUS_IMAGE_IDS = {'config-reloader': '127.0.0.1:5000/lab/reloader@sha256:f5094ebf74f3e5fc1a4377debedca47fd1bd43610819a3574d2a5879a597669a', 'prometheus': '127.0.0.1:5000/lab/prometheus@sha256:546fd0981693fd4fdab42200e8951943839a85797f503b26bc9016469f5724db'}
SAFE_ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'HOME': '/root', 'AWS_CONFIG_FILE': '/dev/null', 'AWS_SHARED_CREDENTIALS_FILE': '/dev/null', 'AWS_EC2_METADATA_DISABLED': 'true', 'AWS_MAX_ATTEMPTS': '1', 'AWS_PAGER': '', 'AWS_CLI_AUTO_PROMPT': 'off'}
KUBE = ['/usr/local/bin/k3s', 'kubectl', '--kubeconfig=/var/tmp/dakasa-two-cluster-b5c117ab7f94221f3de4/brain-kubeconfig', '--request-timeout=3s']
_BRAIN_CLIENT = None


def command_json(args, *, env=None, timeout=5, cap=6 * 1024**2):
    try:
        result = subprocess.run(args, env=env or SAFE_ENV, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise Held('NATIVE_GET_TIMEOUT') from None
    require(result.returncode == 0 and 0 < len(result.stdout) <= cap, 'NATIVE_GET_FAILED_OR_OVERSIZE')
    return json.loads(result.stdout)


def brain(*args):
    # Every caller below supplies literal GET operands, no arbitrary command.
    require(_BRAIN_CLIENT is not None, 'ORIGINAL_BRAIN_CLIENT_STARTUP_REQUIRED')
    return _BRAIN_CLIENT.get(*args)


def initialize_brain_client():
    global _BRAIN_CLIENT
    require(_BRAIN_CLIENT is None, 'ONE_ORIGINAL_BRAIN_TLS_CLIENT')
    def original_config_view(deadline):
        remaining=deadline-time.monotonic()
        require(remaining>0,'ORIGINAL_CONFIG_VIEW_BUDGET')
        return command_json(KUBE+['config','view','--raw','--minify','-o','json'],timeout=min(5,remaining),cap=262144)
    # Startup authentication is not endpoint observation. Rotation reloads use
    # the same request's original three seconds, without renewing its budget.
    _BRAIN_CLIENT=Brain(original_config_view,initial_deadline=time.monotonic()+5)


def ready(value):
    return value['metadata'].get('deletionTimestamp') is None and [x['status'] for x in value.get('status', {}).get('conditions', []) if x['type'] == 'Ready'] == ['True']


def parent(value, kind, uid=None):
    refs = [x for x in value['metadata'].get('ownerReferences', []) if x.get('controller') is True]
    require(len(refs) == 1 and refs[0]['kind'] == kind and (uid is None or refs[0]['uid'] == uid), 'NATIVE_CONTROLLER_OWNER')
    return refs[0]


def service(value, name, uid, selector, port, nodeport=None):
    m, s = value['metadata'], value['spec']
    require(m['name'] == name and m['namespace'] == NS and m['uid'] == uid and m.get('deletionTimestamp') is None and s['selector'] == selector, 'EXACT_SERVICE_UID_SELECTOR')
    require(len(s['ports']) == 1 and s['ports'][0]['protocol'] == 'TCP' and s['ports'][0]['port'] == port and s['ports'][0]['targetPort'] == port, 'EXACT_SERVICE_PORT')
    if nodeport is None:
        require(s['type'] == 'ClusterIP' and s['clusterIP'] == 'None' and 'nodePort' not in s['ports'][0], 'CORE_HEADLESS_DISCOVERY_ONLY')
    else:
        require(s['type'] == 'NodePort' and s['externalTrafficPolicy'] == 'Local' and s['ports'][0]['nodePort'] == nodeport, 'BROKER_LOCAL_ENDPOINT_NODEPORT')


def endpoints(slices, name, uid, port):
    result = []
    require(len(slices['items']) <= 16 and not slices.get('metadata', {}).get('continue'), 'COMPLETE_SLICE_CENSUS')
    for value in slices['items']:
        m = value['metadata']
        require(m['namespace'] == NS and m.get('labels', {}).get('kubernetes.io/service-name') == name and value['addressType'] == 'IPv4', 'EXACT_NATIVE_SLICE_SCOPE')
        parent(value, 'Service', uid)
        require(len(value['ports']) == 1 and value['ports'][0]['protocol'] == 'TCP' and value['ports'][0]['port'] == port, 'EXACT_NATIVE_ENDPOINT_PORT')
        for ep in value['endpoints']:
            if ep.get('conditions') != {'ready': True, 'serving': True, 'terminating': False}:
                continue
            ref = ep.get('targetRef', {})
            require(ref.get('kind') == 'Pod' and ref.get('namespace') == NS and len(ep['addresses']) == 1, 'NATIVE_ENDPOINT_POD_REF')
            result.append(ep)
    require(len(result) <= 16 and len({v['targetRef']['uid'] for v in result}) == len(result), 'UNIQUE_ENDPOINT_CENSUS')
    return result


def collision_snapshot():
    started = time.monotonic()
    values = brain('services', '--all-namespaces')
    require(not values.get('metadata', {}).get('continue') and len(values['items']) <= 512, 'COMPLETE_CLUSTER_IP_CENSUS')
    result = set()
    for value in values['items']:
        for address in value['spec'].get('clusterIPs', [value['spec'].get('clusterIP')]):
            if address in (None, 'None'):
                continue
            parsed = ipaddress.ip_address(address)
            if parsed.version == 4:
                result.add(str(parsed))
    return result, started + MAX_FRESH_SECONDS


def approved_core_images(config):
    """Closed Root-reviewed OCI/runtime pairs; no independent allowlist join."""
    pairs = config['core_container_images']
    require(type(pairs) is list and 1 <= len(pairs) <= 2, 'ONE_OR_TWO_REVIEWED_CORE_IMAGE_PAIRS')
    repository = r'127\.0\.0\.1:5000/lab/core'
    approved = {}
    image_digests, runtime_digests = set(), set()
    for pair in pairs:
        require(type(pair) is dict and set(pair) == {'image', 'image_id'}, 'CLOSED_CORE_IMAGE_RUNTIME_PAIR')
        image, image_id = pair['image'], pair['image_id']
        require(isinstance(image, str) and re.fullmatch(repository + r'@sha256:[a-f0-9]{64}', image), 'APPROVED_CORE_IMMUTABLE_IMAGE')
        require(isinstance(image_id, str) and re.fullmatch(r'(?:docker-pullable://|containerd://)?(?:' + repository + r'@)?sha256:[a-f0-9]{64}', image_id), 'ACTUAL_APPROVED_CORE_IMAGE_ID')
        image_digest, runtime_digest = image.rsplit(':', 1)[1], image_id.rsplit(':', 1)[1]
        require(image_digest not in image_digests and runtime_digest not in runtime_digests, 'UNIQUE_CORE_IMAGE_AND_RUNTIME_DIGESTS')
        image_digests.add(image_digest)
        runtime_digests.add(runtime_digest)
        approved[image] = image_id
    return approved


def core(config, collisions, collision_expires):
    approved = approved_core_images(config)
    require(config['core_service_uid'], 'CORE_NOT_YET_SOURCE_ADMITTED')
    started = time.monotonic()
    deployment = brain('deployment/yggdrasil', '-n', NS)
    require(deployment['metadata']['uid'] == CORE_DEPLOYMENT_UID and deployment['metadata'].get('deletionTimestamp') is None, 'EXACT_CORE_DEPLOYMENT')
    template = deployment['spec']['template']
    require(all(template['metadata']['labels'].get(k) == v for k, v in CORE_LABELS.items()), 'NEW_CORE_TLS_TEMPLATE_ONLY')
    image = [v['image'] for v in template['spec']['containers'] if v['name'] == 'core']
    require(len(image) == 1 and image[0] in approved, 'EXACT_CORE_SOURCE_IMAGE')
    svc = brain('service/' + CORE_SERVICE, '-n', NS)
    service(svc, CORE_SERVICE, config['core_service_uid'], CORE_LABELS, 9443)
    slices = brain('endpointslices', '-n', NS, '-l', 'kubernetes.io/service-name=' + CORE_SERVICE)
    candidates = []
    for ep in endpoints(slices, CORE_SERVICE, config['core_service_uid'], 9443):
        ref = ep['targetRef']
        require(re.fullmatch(r'[a-z0-9][-a-z0-9.]{0,252}', ref['name']), 'CORE_NATIVE_POD_NAME')
        pod = brain('pod/' + ref['name'], '-n', NS)
        require(pod['metadata']['uid'] == ref['uid'] and ready(pod) and not pod['spec'].get('hostNetwork') and all(pod['metadata']['labels'].get(k) == v for k, v in CORE_LABELS.items()), 'EXACT_READY_NEW_CORE_POD')
        require(pod['status']['podIP'] == ep['addresses'][0] and pod['spec']['nodeName'] == ep['nodeName'], 'ACTUAL_CORE_POD_ADDRESS_NODE')
        pod_image = [v['image'] for v in pod['spec']['containers'] if v['name'] == 'core']
        require(len(pod_image) == 1 and pod_image[0] in approved, 'EXACT_APPROVED_CORE_POD_SPEC_IMAGE')
        states = [v for v in pod['status']['containerStatuses'] if v['name'] == 'core']
        require(len(states) == 1 and states[0]['ready'] is True and 'running' in states[0]['state'] and states[0]['imageID'] == approved[pod_image[0]], 'ACTUAL_CORE_CONTAINER_IMAGE_ID')
        rs = parent(pod, 'ReplicaSet')
        actual_rs = brain('replicaset/' + rs['name'], '-n', NS)
        require(actual_rs['metadata']['uid'] == rs['uid'], 'CORE_NATIVE_RS_UID')
        parent(actual_rs, 'Deployment', CORE_DEPLOYMENT_UID)
        node = brain('node/' + ep['nodeName'])
        require(ready(node) and [v['address'] for v in node['status']['addresses'] if v['type'] == 'InternalIP'] == [BRAIN], 'CORE_IS_ON_ACTUAL_BRAIN')
        address = ep['addresses'][0]
        require(address not in collisions, 'CORE_SERVICE_ADDRESS_COLLISION')
        item = Backend('core', address, 9443, started, min(started + MAX_FRESH_SECONDS, collision_expires), pod['metadata']['uid'] + '/' + states[0]['containerID'])
        item.validate()
        candidates.append(item)
    require(1 <= len(candidates) <= 2, 'ONE_OR_TWO_READY_APPROVED_CORE_PODS')
    candidates.sort(key=lambda v: v.native_identity)
    return candidates[0], tuple(candidates)


def prometheus(collisions, collision_expires):
    """Same original Brain mTLS GETs; transport identity, never scrape authority."""
    started = time.monotonic()
    sts = brain('statefulset/prometheus-dakasa', '-n', 'observability')
    m, s, state = sts['metadata'], sts['spec'], sts['status']
    require(m['uid'] == PROMETHEUS_STS_UID and m['name'] == 'prometheus-dakasa' and m['namespace'] == 'observability'
            and m.get('deletionTimestamp') is None, 'ORIGINAL_PROMETHEUS_STATEFULSET_UID')
    parent(sts, 'Prometheus', PROMETHEUS_CR_UID)
    require(s['selector'] == {'matchLabels':PROMETHEUS_SELECTOR} and s['template']['metadata']['labels'] == PROMETHEUS_TEMPLATE_LABELS
            and len(s['template']['spec']['containers']) == 2
            and {x['name']:x['image'] for x in s['template']['spec']['containers']} == PROMETHEUS_IMAGES,
            'ORIGINAL_PROMETHEUS_SELECTOR_TEMPLATE_AND_TWO_IMAGES')
    require(s['replicas'] == 1 and state.get('observedGeneration') == m['generation']
            and all(state.get(k) == 1 for k in ('replicas','currentReplicas','readyReplicas','updatedReplicas'))
            and state.get('currentRevision') == state.get('updateRevision') and bool(state.get('currentRevision')),
            'SOLE_CURRENT_READY_PROMETHEUS_STATEFULSET')
    svc = brain('service/prometheus', '-n', 'observability')
    sm, ss = svc['metadata'], svc['spec']
    require(sm['uid'] == PROMETHEUS_SERVICE_UID and sm['name'] == 'prometheus' and sm['namespace'] == 'observability'
            and sm.get('deletionTimestamp') is None and ss['selector'] == {'prometheus':'dakasa'}
            and ss['type'] == 'ClusterIP' and ss['clusterIP'] == '10.245.41.50'
            and ss['ports'] == [{'name':'web','port':9090,'protocol':'TCP','targetPort':9090}],
            'ORIGINAL_PROMETHEUS_SERVICE_UID_SELECTOR_PORT')
    pods = brain('pods', '-n', 'observability', '-l', 'prometheus=dakasa')
    require(not pods.get('metadata',{}).get('continue') and len(pods['items']) == 1, 'COMPLETE_SOLE_PROMETHEUS_POD_CENSUS')
    pod = pods['items'][0];pm, ps, status = pod['metadata'], pod['spec'], pod['status']
    require(pm['namespace'] == 'observability' and pm['name'] == 'prometheus-dakasa-0'
            and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',str(pm['uid']))
            and ready(pod) and status['phase'] == 'Running' and not ps.get('hostNetwork')
            and all(pm['labels'].get(k) == v for k,v in PROMETHEUS_TEMPLATE_LABELS.items())
            and pm['labels'].get('controller-revision-hash') == state['currentRevision'], 'ORIGINAL_READY_PROMETHEUS_POD_AND_REVISION')
    parent(pod, 'StatefulSet', PROMETHEUS_STS_UID)
    require(len(ps['containers']) == 2 and {x['name']:x['image'] for x in ps['containers']} == PROMETHEUS_IMAGES,
            'ORIGINAL_PROMETHEUS_POD_DECLARED_IMAGES')
    states = status['containerStatuses']
    require(len(states) == 2 and {x['name'] for x in states} == set(PROMETHEUS_IMAGES)
            and all(x['ready'] is True and x['imageID'] == PROMETHEUS_IMAGE_IDS[x['name']]
                    and isinstance(x.get('containerID'),str) and re.fullmatch('containerd://[a-f0-9]{64}',x['containerID'])
                    and x.get('state',{}).get('running',{}).get('startedAt')
                    and type(x.get('restartCount')) is int and x['restartCount'] >= 0 for x in states), 'ORIGINAL_RUNNING_PROMETHEUS_NATIVE_IMAGES_AND_LIFETIMES')
    require(re.fullmatch('[a-z0-9][-a-z0-9.]{0,252}',ps['nodeName']), 'PROMETHEUS_NATIVE_NODE_NAME')
    node = brain('node/' + ps['nodeName'])
    require(node['metadata']['uid'] == BRAIN_NODE_UID and ready(node)
            and [x['address'] for x in node['status']['addresses'] if x['type'] == 'InternalIP'] == [BRAIN],
            'ORIGINAL_READY_BRAIN_NODE_ONLY_FOR_PROMETHEUS')
    address = status['podIP'];require(address not in collisions, 'PROMETHEUS_POD_SERVICE_IP_COLLISION')
    lifetime = pm['uid'] + '/' + '/'.join(x['name'] + ':' + x['containerID'] + ':' + x['state']['running']['startedAt'] for x in sorted(states,key=lambda x:x['name']))
    item = PrometheusSource(address, started, min(started + MAX_FRESH_SECONDS, collision_expires), lifetime)
    item.validate()
    return (item,)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise Held('NATIVE_API_REDIRECT_REFUSED')


class EKS:
    def __init__(self, config):
        endpoint = config['eks_endpoint']
        u = urllib.parse.urlsplit(endpoint)
        require(u.scheme == 'https' and u.hostname == '127.0.0.1' and u.port in (None, 443) and not u.username and not u.password and u.path in ('', '/') and not u.query and not u.fragment, 'EXACT_NATIVE_EKS_ENDPOINT')
        ca = base64.b64decode(config['eks_public_ca_base64'], validate=True)
        require(len(ca) <= 16384 and ca.startswith(b'-----BEGIN CERTIFICATE-----'), 'PUBLIC_EKS_CA')
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tls.load_verify_locations(cadata=ca.decode('ascii'))
        self.context, self.host = tls, u.hostname
        self.endpoint, self.token, self.expires = endpoint.rstrip('/'), None, 0

    def credential(self):
        return 'k8s-aws-v1.LAB_SYNTHETIC_NO_AWS_AUTH'

    def get(self, path, selector=None):
        allowed = {'/api/v1/nodes', '/api/v1/namespaces/dakasa/services/' + BROKER_SERVICE, '/api/v1/namespaces/dakasa/pods', '/apis/discovery.k8s.io/v1/namespaces/dakasa/endpointslices'}
        require(path in allowed and selector in (None, 'app=rabbitmq', 'kubernetes.io/service-name=' + BROKER_SERVICE), 'CLOSED_NATIVE_GET_PATH')
        # Authentication is not native endpoint freshness; credential() is
        # unchanged and its RAM token never enters logs or a child environment.
        token = self.credential()
        deadline = time.monotonic() + 3
        return eks_https.original_get(self.context,self.host,path,selector,token,deadline)


    def broker(self, collisions, collision_expires):
        self.credential()  # Authentication work is not fresh endpoint evidence.
        started = time.monotonic()
        svc = self.get('/api/v1/namespaces/dakasa/services/' + BROKER_SERVICE)
        service(svc, BROKER_SERVICE, BROKER_UID, {'app': 'rabbitmq'}, 5671, 32674)
        slices = self.get('/apis/discovery.k8s.io/v1/namespaces/dakasa/endpointslices', 'kubernetes.io/service-name=' + BROKER_SERVICE)
        pods = self.get('/api/v1/namespaces/dakasa/pods', 'app=rabbitmq')
        nodes = self.get('/api/v1/nodes')
        require(not pods.get('metadata', {}).get('continue') and not nodes.get('metadata', {}).get('continue') and len(pods['items']) <= 16 and len(nodes['items']) <= 128, 'COMPLETE_NATIVE_BROKER_CENSUS')
        by_uid = {v['metadata']['uid']: v for v in pods['items']}
        by_name = {v['metadata']['name']: v for v in nodes['items']}
        found = []
        for ep in endpoints(slices, BROKER_SERVICE, BROKER_UID, 5671):
            pod = by_uid[ep['targetRef']['uid']]
            require(ready(pod) and pod['metadata']['name'] == ep['targetRef']['name'] and pod['status']['podIP'] == ep['addresses'][0] and pod['spec']['nodeName'] == ep['nodeName'], 'BROKER_ACTUAL_LOCAL_READY_POD')
            parent(pod, 'StatefulSet', BROKER_STS_UID)
            node = by_name[ep['nodeName']]
            require(ready(node), 'BROKER_NODE_NOT_READY')
            ips = [v['address'] for v in node['status']['addresses'] if v['type'] == 'InternalIP']
            require(len(ips) == 1 and ips[0] not in collisions, 'BROKER_NODE_IP_COLLISION')
            item = Backend('broker', ips[0], 32674, started, min(started + MAX_FRESH_SECONDS, collision_expires), node['metadata']['uid'] + '/' + pod['metadata']['uid'])
            item.validate()
            found.append(item)
        require(found, 'BROKER_NO_LOCAL_READY_ENDPOINT')
        return sorted(found, key=lambda x: (x.address, x.native_identity))[0]
