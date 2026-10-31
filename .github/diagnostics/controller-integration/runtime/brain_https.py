"""Fixed original K3s mTLS GET client; TLS identity RAM/sealed memfd only.

No network/config access on import. No proxy, redirect, token, new principal or
observation cache. One original socket/watchdog owns connect/TLS/HTTP/EOF/Close.
"""
import base64
import fcntl
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import threading
import time
import urllib.parse

from nft_owner import Held, require

KUBECONFIG=Path('/var/tmp/dakasa-two-cluster-b5c117ab7f94221f3de4/brain-kubeconfig')
HOST='127.0.0.1'
PORT=6443
CAP=6*1024**2
CORE_SERVICE='yggdrasil-capacity-tls'


def fingerprint(path=KUBECONFIG):
    s=path.lstat()
    require(stat.S_ISREG(s.st_mode)and not path.is_symlink()and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=262144,'EXACT_PRIVATE_K3S_KUBECONFIG')
    return(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink,s.st_uid,s.st_mode)


def request_scope(args):
    """Exact existing source-owned kubectl GET operands, no generic API access."""
    args=tuple(args)
    if args==('services','--all-namespaces'):return'/api/v1/services',None
    if args==('deployment/yggdrasil','-n','dakasa'):return'/apis/apps/v1/namespaces/dakasa/deployments/yggdrasil',None
    if args==('service/'+CORE_SERVICE,'-n','dakasa'):return'/api/v1/namespaces/dakasa/services/'+CORE_SERVICE,None
    if args==('endpointslices','-n','dakasa','-l','kubernetes.io/service-name='+CORE_SERVICE):return'/apis/discovery.k8s.io/v1/namespaces/dakasa/endpointslices','kubernetes.io/service-name='+CORE_SERVICE
    if args==('secret/integration-aws-creds','-n','dakasa'):return'/api/v1/namespaces/dakasa/secrets/integration-aws-creds',None
    if args==('statefulset/prometheus-dakasa','-n','observability'):return'/apis/apps/v1/namespaces/observability/statefulsets/prometheus-dakasa',None
    if args==('service/prometheus','-n','observability'):return'/api/v1/namespaces/observability/services/prometheus',None
    if args==('pods','-n','observability','-l','prometheus=dakasa'):return'/api/v1/namespaces/observability/pods','prometheus=dakasa'
    if len(args)==3 and args[1:]==('-n','dakasa'):
        for singular,plural in(('pod','pods'),('replicaset','replicasets')):
            prefix=singular+'/'
            if args[0].startswith(prefix):
                name=args[0][len(prefix):];require(re.fullmatch('[a-z0-9][-a-z0-9.]{0,252}',name),'NATIVE_OBJECT_NAME')
                group='/api/v1'if singular=='pod'else'/apis/apps/v1'
                return group+'/namespaces/dakasa/'+plural+'/'+name,None
    if len(args)==1 and args[0].startswith('node/'):
        name=args[0][5:];require(re.fullmatch('[a-z0-9][-a-z0-9.]{0,252}',name),'NATIVE_NODE_NAME');return'/api/v1/nodes/'+name,None
    raise Held('CLOSED_ORIGINAL_BRAIN_GET_ALLOWLIST')


def inline_credentials(value):
    require(value.get('kind')=='Config'and value.get('apiVersion')=='v1'and len(value.get('clusters',[]))==len(value.get('users',[]))==len(value.get('contexts',[]))==1,'SINGLE_ORIGINAL_K3S_CONTEXT')
    cluster,user,context=value['clusters'][0],value['users'][0],value['contexts'][0]
    require(value.get('current-context')==context['name']and context['context']['cluster']==cluster['name']and context['context']['user']==user['name'],'EXACT_CURRENT_K3S_CONTEXT_JOIN')
    c,u=cluster['cluster'],user['user']
    require(set(c)=={'server','certificate-authority-data'}and c['server']=='https://127.0.0.1:6443'and set(u)=={'client-certificate-data','client-key-data'},'ORIGINAL_FIXED_K3S_INLINE_MTLS_ONLY')
    ca,certificate,key=(base64.b64decode(x,validate=True)for x in(c['certificate-authority-data'],u['client-certificate-data'],u['client-key-data']))
    require(0<len(ca)<=65536 and 0<len(certificate)<=65536 and 0<len(key)<=65536 and ca.startswith(b'-----BEGIN CERTIFICATE-----')and certificate.startswith(b'-----BEGIN CERTIFICATE-----')and b'PRIVATE KEY-----'in key[:100],'BOUNDED_INLINE_NATIVE_MTLS_DATA')
    return ca,certificate,key


def sealed_memfd(name,raw):
    fd=os.memfd_create(name,os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        os.fchmod(fd,0o600);offset=0
        while offset<len(raw):offset+=os.write(fd,raw[offset:])
        os.lseek(fd,0,os.SEEK_SET)
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
        return fd
    except BaseException:os.close(fd);raise


def tls_context(value):
    ca,certificate,key=inline_credentials(value);fds=[]
    try:
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.verify_mode=ssl.CERT_REQUIRED;context.check_hostname=True;context.load_verify_locations(cadata=ca.decode('ascii'))
        fds.append(sealed_memfd('dakasa-brain-client-cert',certificate));fds.append(sealed_memfd('dakasa-brain-client-key',key))
        context.load_cert_chain('/proc/self/fd/'+str(fds[0]),'/proc/self/fd/'+str(fds[1]))
        return context
    finally:
        for fd in reversed(fds):os.close(fd)
        ca=certificate=key=None


def original_get(context,path,selector,deadline,*,host=HOST,port=PORT):
    # host/port keyword parameters are solely for the isolated benign TLS fixture;
    # production Brain.get always supplies the two literal original constants.
    require(time.monotonic()<deadline,'ORIGINAL_K3S_GET_DEADLINE')
    wire=socket.socket(socket.AF_INET,socket.SOCK_STREAM);owner={'socket':wire};gate=threading.Lock();done=threading.Event();response=None;connection=None
    facts={'http200':False,'body_EOF':False,'body_close':False,'same_socket_closed':False,'watchdog_joined':False}
    def watchdog():
        if not done.wait(max(0,deadline-time.monotonic())):
            with gate:
                current=owner['socket']
                try:current.shutdown(socket.SHUT_RDWR)
                except OSError:pass
                finally:current.close()
    thread=threading.Thread(target=watchdog,name='original-brain-get-deadline',daemon=True);thread.start()
    try:
        wire.settimeout(max(.001,deadline-time.monotonic()));wire.connect((host,port))
        require(time.monotonic()<deadline,'ORIGINAL_K3S_CONNECT_DEADLINE')
        with gate:
            wire=context.wrap_socket(wire,server_hostname=host,do_handshake_on_connect=False);owner['socket']=wire
        wire.settimeout(max(.001,deadline-time.monotonic()));wire.do_handshake();require(time.monotonic()<deadline,'ORIGINAL_K3S_TLS_DEADLINE')
        connection=http.client.HTTPConnection(host,port,timeout=max(.001,deadline-time.monotonic()));connection.auto_open=0;connection.sock=wire
        target=path+('?' +urllib.parse.urlencode({'labelSelector':selector})if selector else'')
        connection.request('GET',target,headers={'Accept':'application/json','Host':host+':'+str(port),'Connection':'close'})
        response=connection.getresponse();require(response.status==200 and sum(len(k)+len(v)for k,v in response.getheaders())<=65536,'NATIVE_K3S_HTTP_STATUS_HEADERS');facts['http200']=True
        # HTTPResponse.read(amt) may return a SHORT declared-length body without
        # IncompleteRead. A valid JSON prefix plus transport EOF is insufficient.
        expected_length=response.length
        declared=response.msg.get_all('Content-Length',[])
        if declared:
            require(len(declared)==1 and re.fullmatch('[0-9]{1,20}',declared[0].strip())and not response.chunked and expected_length==int(declared[0].strip()),'UNAMBIGUOUS_ORIGINAL_CONTENT_LENGTH')
        require(expected_length is None or(type(expected_length)is int and 0<expected_length<=CAP),'BOUNDED_ORIGINAL_CONTENT_LENGTH')
        raw=response.read(CAP+1);require(0<len(raw)<=CAP and(expected_length is None or len(raw)==expected_length)and response.read(1)==b'','NATIVE_K3S_BODY_EXACT_LENGTH_CAP_AND_EOF');facts['body_EOF']=True
        require(time.monotonic()<deadline,'ORIGINAL_K3S_BODY_DEADLINE')
        value=json.loads(raw)
    finally:
        try:
            if response is not None:response.close();facts['body_close']=True
            if connection is not None:connection.close()
        finally:
            with gate:
                current=owner['socket']
                try:current.shutdown(socket.SHUT_RDWR)
                except OSError:pass
                finally:current.close();facts['same_socket_closed']=True
            done.set();thread.join(timeout=max(.001,min(.2,deadline-time.monotonic())))
            facts['watchdog_joined']=not thread.is_alive();original_get.last_facts=facts
    require(facts['watchdog_joined']and facts['body_close']and facts['same_socket_closed']and time.monotonic()<deadline,'ORIGINAL_K3S_CLOSE_JOIN_DEADLINE')
    return value


class Brain:
    def __init__(self,config_view,*,initial_deadline):
        self.config_view=config_view;self.identity=None;self.context=None;self.refresh(initial_deadline)
    def refresh(self,deadline):
        require(time.monotonic()<deadline,'ORIGINAL_K3S_SETUP_DEADLINE');before=fingerprint()
        if self.context is not None and self.identity==before:return
        self.context=None;self.identity=None
        value=self.config_view(deadline);require(time.monotonic()<deadline,'ORIGINAL_CONFIG_VIEW_DEADLINE')
        context=tls_context(value);value=None
        require(fingerprint()==before and time.monotonic()<deadline,'UNCHANGED_ORIGINAL_K3S_CREDENTIAL_FILE')
        self.context=context;self.identity=before
    def get(self,*args):
        started=time.monotonic();deadline=started+3
        path,selector=request_scope(args);self.refresh(deadline)
        result=original_get(self.context,path,selector,deadline,host=HOST,port=PORT)
        require(fingerprint()==self.identity and time.monotonic()<deadline,'ORIGINAL_K3S_CREDENTIAL_AND_GET_FENCE')
        return result
