"""Fixed EKS GET transport with one original3s DNS/TCP/TLS/HTTP/close owner.

Pattern copied from the reviewed Brain strict socket client. Authentication is
RAM only and precedes this original HTTP owner. No proxy, redirect or retry.
DNS resolution runs in one credential-free original child under the SAME
request deadline; it cannot block a synchronous getaddrinfo beyond that owner.
"""
import http.client
import hashlib
import ipaddress
import json
import re
import socket
import subprocess
import threading
import time
import urllib.parse

from nft_owner import Held, require
import original_process

CAP=6*1024**2
PATHS=frozenset(('/api/v1/nodes','/api/v1/namespaces/dakasa/services/rabbitmq-capacity-edge','/api/v1/namespaces/dakasa/pods','/apis/discovery.k8s.io/v1/namespaces/dakasa/endpointslices'))
SELECTORS=frozenset((None,'app=rabbitmq','kubernetes.io/service-name=rabbitmq-capacity-edge'))
DNS_PROGRAM="import socket,sys,json;print(json.dumps(sorted({x[4][0] for x in socket.getaddrinfo(sys.argv[1],443,socket.AF_INET,socket.SOCK_STREAM)}),separators=(',',':')))"
SAFE={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C'}


def scope(host,path,selector,token,port):
    require(type(host)is str and 0<len(host)<=253 and (re.fullmatch('[a-z0-9.-]+\\.eks\\.amazonaws\\.com',host)is not None or host=='127.0.0.1'),'FIXED_ORIGINAL_EKS_TLS_HOST')
    require(path in PATHS and selector in SELECTORS,'CLOSED_ORIGINAL_EKS_GET')
    require(type(port)is int and 0<port<65536 and (port==443 or host=='127.0.0.1'),'ORIGINAL_EKS_TLS_PORT')
    require(type(token)is str and token.startswith('k8s-aws-v1.')and 0<len(token)<=8192 and not any(c.isspace()for c in token),'ORIGINAL_EKS_BEARER_RAM_SHAPE')


def resolve(host,deadline):
    if host=='127.0.0.1':return host,None
    require(time.monotonic()<deadline,'ORIGINAL_EKS_DNS_DEADLINE')
    capture,facts={},{}
    try:
        raw,_=original_process.native(['/usr/bin/python3','-I','-B','-c',DNS_PROGRAM,host],deadline=deadline,env=SAFE,cap=16384,custody=facts,capture=capture)
    except original_process.Held as error:raise Held(str(error))from None
    finally:
        resolve.last_facts={'original_transport':dict(capture.get('transport',facts)),
            'stdout_sha256':hashlib.sha256(capture.get('stdout',b'')).hexdigest(),'stdout_bytes':len(capture.get('stdout',b'')),
            'stderr_sha256':hashlib.sha256(capture.get('stderr',b'')).hexdigest(),'stderr_bytes':len(capture.get('stderr',b''))}
    facts=capture['transport']
    require(all(facts.get(k)is True for k in('native_started','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined'))and facts.get('exit_code')==0 and facts.get('captured_output_truncated')is False and time.monotonic()<deadline,'ORIGINAL_EKS_DNS_FULL_JOIN_ZERO')
    values=json.loads(raw)
    require(type(values)is list and 0<len(values)<=16 and len(set(values))==len(values)
            and all(type(x)is str and str(ipaddress.IPv4Address(x))==x for x in values),'BOUNDED_ORIGINAL_EKS_IPV4_RESOLUTION')
    # One connection to one actually returned address; no address fallback or
    # request replay. TLS authenticates the original hostname, not this IP.
    return sorted(values)[0],facts


def original_get(context,host,path,selector,token,deadline,*,port=443):
    original_get.last_facts={'http200':False,'body_EOF':False,'body_close':False,'same_socket_closed':False,'watchdog_joined':False,'original_dns_transport':None}
    scope(host,path,selector,token,port)
    require(time.monotonic()<deadline,'ORIGINAL_EKS_GET_DEADLINE')
    try:address,dns_facts=resolve(host,deadline)
    except BaseException:
        original_get.last_facts['original_dns_failure_facts']=getattr(resolve,'last_facts',None)
        raise
    require(time.monotonic()<deadline,'ORIGINAL_EKS_AFTER_DNS_DEADLINE')
    wire=socket.socket(socket.AF_INET,socket.SOCK_STREAM);owner={'socket':wire};gate=threading.Lock();done=threading.Event();response=None;connection=None
    facts={'http200':False,'body_EOF':False,'body_close':False,'same_socket_closed':False,'watchdog_joined':False,'original_dns_transport':dns_facts}
    def watchdog():
        if not done.wait(max(0,deadline-time.monotonic())):
            with gate:
                current=owner['socket']
                try:current.shutdown(socket.SHUT_RDWR)
                except OSError:pass
                finally:current.close()
    thread=threading.Thread(target=watchdog,name='original-EKS-get-deadline',daemon=True);thread.start()
    try:
        wire.settimeout(max(.001,deadline-time.monotonic()));wire.connect((address,port))
        require(time.monotonic()<deadline,'ORIGINAL_EKS_CONNECT_DEADLINE')
        with gate:
            wire=context.wrap_socket(wire,server_hostname=host,do_handshake_on_connect=False);owner['socket']=wire
        wire.settimeout(max(.001,deadline-time.monotonic()));wire.do_handshake();require(time.monotonic()<deadline,'ORIGINAL_EKS_TLS_DEADLINE')
        connection=http.client.HTTPConnection(host,port,timeout=max(.001,deadline-time.monotonic()));connection.auto_open=0;connection.sock=wire
        target=path+('?' +urllib.parse.urlencode({'labelSelector':selector})if selector else'')
        connection.request('GET',target,headers={'Accept':'application/json','Authorization':'Bearer '+token,'Host':host+':'+str(port),'Connection':'close'})
        response=connection.getresponse();require(response.status==200 and sum(len(k)+len(v)for k,v in response.getheaders())<=65536,'NATIVE_EKS_HTTP_STATUS_HEADERS');facts['http200']=True
        expected=response.length;declared=response.msg.get_all('Content-Length',[]);encoding=response.msg.get_all('Transfer-Encoding',[])
        require(not encoding or len(encoding)==1 and encoding[0].strip().lower()=='chunked'and response.chunked and not declared,'UNAMBIGUOUS_ORIGINAL_EKS_TRANSFER_ENCODING')
        if declared:require(len(declared)==1 and re.fullmatch('[0-9]{1,20}',declared[0].strip())and not response.chunked and expected==int(declared[0].strip()),'UNAMBIGUOUS_ORIGINAL_EKS_CONTENT_LENGTH')
        require(expected is None or type(expected)is int and 0<expected<=CAP,'BOUNDED_ORIGINAL_EKS_CONTENT_LENGTH')
        raw=response.read(CAP+1)
        require(0<len(raw)<=CAP and(expected is None or len(raw)==expected)and response.read(1)==b'','NATIVE_EKS_BODY_EXACT_LENGTH_CAP_AND_EOF');facts['body_EOF']=True
        require(time.monotonic()<deadline,'ORIGINAL_EKS_BODY_DEADLINE')
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
    require(facts['watchdog_joined']and facts['body_close']and facts['same_socket_closed']and time.monotonic()<deadline,'ORIGINAL_EKS_CLOSE_JOIN_DEADLINE')
    return value
