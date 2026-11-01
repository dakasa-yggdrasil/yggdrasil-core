"""Real DNS UDP, route and original Cache in a disposable Linux namespace."""
import os,socket,struct,subprocess,threading,time
import dns_native,native_io,observations,whole_witness as whole

def start(endpoints, *, setup=True):
    if setup:
        subprocess.run(['/usr/sbin/ip','link','set','lo','up'],check=True)
        subprocess.run(['/usr/sbin/ip','link','add','br-2980a83da24e','type','dummy'],check=True)
        subprocess.run(['/usr/sbin/ip','addr','add','172.18.0.1/16','dev','br-2980a83da24e'],check=True)
        subprocess.run(['/usr/sbin/ip','link','set','br-2980a83da24e','up'],check=True)
    server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);server.bind(('127.0.0.1',5353));server.settimeout(5)
    errors=[]
    def respond():
        try:
            for _ in range(2):
                raw,addr=server.recvfrom(4096)
                if b'\x03rds' in raw:ip='172.18.1.3'
                elif b'\x05redis' in raw:ip='172.18.1.4'
                else:raise RuntimeError('unexpected DNS question')
                answer=raw[:2]+struct.pack('!5H',0x8180,1,1,0,0)+raw[12:]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton(ip)
                server.sendto(answer,addr)
        except BaseException as exc:errors.append(exc)
    worker=threading.Thread(target=respond);worker.start()
    try:
        cache=observations.Cache();entries,cores,prom=endpoints(4)
        topology=[x for x in entries if x.kind in ('core','broker')]
        cache.publish_topology((topology,cores,prom,{},frozenset(),time.monotonic()+(65 if os.environ.get('CI_HOLDER_TEST')=='1' else 25)))
        for role in ('rds','redis'):
            context=cache.collision_context();answer=dns_native.resolve(role,context[0])
            result=native_io.command(['/usr/sbin/ip','-j','-4','route','get',answer.addresses[0]],role='route_'+role)
            route=whole.route_from_original(answer,result.stdout,native_io.last_facts())
            cache.publish_dns(role,whole.complete(answer,route,context[0],context[1]),context)
        worker.join(5)
        if worker.is_alive() or errors:raise RuntimeError('fixture DNS responder failed') from (errors[0] if errors else None)
        value=cache.snapshot();assert len(value[0])==4 and len(value[1])==len(value[2])==1 and value[3]=={}
        return cache
    finally:
        server.close();worker.join(5)

class LiveReaders:
    """Actual Reader loops against a stoppable synthetic UDP DNS service."""
    def __init__(self,endpoints):
        self.server_errors=[];self.start_dns()
        def topology():
            entries,cores,prom=endpoints(4)
            return ([x for x in entries if x.kind in ('core','broker')],cores,prom,{},frozenset(),time.monotonic()+(65 if os.environ.get('CI_HOLDER_TEST')=='1' else 25))
        def route(answer,previous=None):
            output=native_io.command(['/usr/sbin/ip','-j','-4','route','get',answer.addresses[0]],role='route_'+answer.kind)
            if previous is not None:return whole.route_after_zero(previous,answer,output.stdout,native_io.last_facts())
            return whole.route_from_original(answer,output.stdout,native_io.last_facts())
        self.readers=observations.Readers(topology,dns_native.resolve,route);self.readers.start()
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            rows,cores,prom,errors,_=self.readers.cache.snapshot()
            if len(rows)==4 and len(cores)==1 and len(prom)==1 and not errors:return
            time.sleep(.025)
        self.close();raise RuntimeError('LIVE_READERS_NOT_READY')
    def start_dns(self):
        self.server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.server.bind(('127.0.0.1',5353));self.server.settimeout(.1)
        self.server_stop=threading.Event()
        def respond():
            while not self.server_stop.is_set():
                try:raw,addr=self.server.recvfrom(4096)
                except socket.timeout:continue
                except OSError:
                    if not self.server_stop.is_set():self.server_errors.append('SOCKET_ERROR')
                    break
                if b'\x03rds' in raw:ip='172.18.1.3'
                elif b'\x05redis' in raw:ip='172.18.1.4'
                else:self.server_errors.append('UNEXPECTED_QUESTION');break
                reply=raw[:2]+struct.pack('!5H',0x8180,1,1,0,0)+raw[12:]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton(ip)
                self.server.sendto(reply,addr)
        self.server_thread=threading.Thread(target=respond);self.server_thread.start()
    @property
    def cache(self):return self.readers.cache
    def stop_dns(self):
        self.server_stop.set();self.server_thread.join(2);self.server.close()
        if self.server_thread.is_alive() or self.server_errors:raise RuntimeError('DNS_FIXTURE_STOP_FAILED')
    def restart_dns(self):
        if not self.server_stop.is_set():raise RuntimeError('DNS_FIXTURE_STILL_RUNNING')
        self.start_dns()
    def close(self):
        if not self.server_stop.is_set():self.stop_dns()
        self.readers.close_join(time.monotonic()+5)
