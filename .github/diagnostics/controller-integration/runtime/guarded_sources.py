"""LAB-only pure join of same-process original witnesses and kernel tuple maps.

No receipt custody, genid/pidfd validation, refresh authority or service wiring.
Caller must independently bind both map snapshots to one kernel generation.
"""
import math,socket,struct,time
import nft_owner as nft
import observations
import dns_native
import whole_witness as whole

class Held(Exception):pass
class OriginalDNSWitnessUnavailable(Held):
    """An original DNS/route witness is not currently available."""
def require(ok,reason):
    if not ok:raise Held(reason)
def tk(src,dst,port):return socket.inet_aton(src)+socket.inet_aton(dst)+struct.pack('>H',port)+bytes(2)
def build_expected(cache,*,now=None):
    require(type(cache) is observations.Cache,'ORIGINAL_READER_CACHE_REQUIRED')
    now=time.monotonic() if now is None else now
    require(type(now) in (int,float) and math.isfinite(now),'FINITE_ORIGINAL_CLOCK')
    with cache.lock:
        for role in ('rds','redis'):
            if type(cache.dns.get(role)) is not whole.CompleteWitness:
                raise OriginalDNSWitnessUnavailable('ORIGINAL_DNS_ROUTE_WITNESS_REQUIRED')
        entries,cores,prom,errors,generation=cache._snapshot_locked()
        require(not errors and len(entries)==4 and {x.kind for x in entries}=={'core','broker','rds','redis'},'FOUR_ORIGINAL_BACKEND_WITNESSES_REQUIRED')
        require(1<=len(cores)<=8 and len(prom)==1 and len({x.address for x in cores})==len(cores),'CORE_PROM_CENSUS_REQUIRED')
        require(len(nft.PEERS)==16 and len(set(nft.PEERS))==16,'SIXTEEN_FIXED_PEERS_REQUIRED')
        require(now<cache.collision_expires,'ORIGINAL_COLLISION_CENSUS_EXPIRED')
        for x in (*entries,*cores,*prom):
            x.validate();require(x.observed_started<=now<x.expires<=cache.collision_expires and x.address not in cache.collisions,'ORIGINAL_WITNESS_WINDOW_OR_COLLISION')
        for role in ('rds','redis'):
            w=cache.dns.get(role);require(type(w)is whole.CompleteWitness,'ORIGINAL_DNS_ROUTE_WITNESS_REQUIRED')
            w.validate();project=dns_native.backend(w,cache.collisions,cache.collision_expires,now=now)
            match=next(x for x in entries if x.kind==role)
            require(project==match and project.expires<=w.original_expiry,'SAME_ORIGINAL_DNS_ROUTE_WITNESS_AND_EXPIRY')
        bykind={x.kind:x for x in entries};require(any(x==bykind['core'] for x in cores),'CORE_FORWARD_REVERSE_WITNESS_JOIN')
        inbound={tk(peer,item.address,item.port):math.floor(item.expires*1e9) for peer in nft.PEERS for item in entries}
        reverse={tk(item.address,peer,9447):math.floor(item.expires*1e9) for peer in nft.PEERS for item in cores}
        reverse.update({tk(item.address,peer,9080):math.floor(item.expires*1e9) for peer in nft.PEERS for item in prom})
        require(len(inbound)==16*len(entries) and len(reverse)==16*(len(cores)+len(prom)),'NO_AMBIGUOUS_DUPLICATE_TUPLES')
        wanted_dnat={nft.VIP_PORTS[x.kind]:(x.address,x.port) for x in entries}
        return {'inbound':inbound,'reverse':reverse,'dnat':wanted_dnat,'cores':{x.address for x in cores},'prom':{x.address for x in prom},'source_generation':generation,'invalidation_epoch':getattr(cache,'guard_invalidation_epoch',None)}

def verify(cache,kernel,maps,*,now=None):
    now=time.monotonic() if now is None else now;expected=build_expected(cache,now=now)
    require(type(maps)is dict and set(maps)=={'inbound','reverse'},'EXACT_TWO_MAPS_REQUIRED')
    for role in ('inbound','reverse'):
        rows=maps[role];require(type(rows)is list and all(type(k)is bytes and len(k)==12 and type(v)is int for k,v in rows),'BOUNDED_TYPED_KERNEL_MAP')
        actual=dict(rows);require(len(actual)==len(rows) and set(actual)==set(expected[role]),'EXACT_ORIGINAL_MAP_KEY_CENSUS')
        require(all(math.floor(now*1e9)<deadline<=expected[role][key] for key,deadline in actual.items()),'ABSOLUTE_MAP_DEADLINE_MUST_NOT_EXCEED_ORIGINAL')
    groups=kernel['dynamic_collections'];actual_dnat={}
    for row in groups['backend_dnat4']:
        vip,port=row['value'].split(' . ');target,dport=row['target'].split(' . ');actual_dnat[(vip,int(port))]=(target,int(dport))
    require(actual_dnat==expected['dnat'],'ORIGINAL_BACKENDS_MUST_EQUAL_KERNEL_DNAT')
    require({x['value'] for x in groups['core_ready4']}==expected['cores'],'ORIGINAL_CORE_MUST_EQUAL_KERNEL')
    require({x['value'] for x in groups['prometheus_ready4']}==expected['prom'],'ORIGINAL_PROMETHEUS_MUST_EQUAL_KERNEL')
    expected_forward={f'{vip} . {port} . {target} . {dport}' for (vip,port),(target,dport) in expected['dnat'].items()}
    require({x['value'] for x in groups['backend_forward4']}==expected_forward,'ORIGINAL_BACKEND_FORWARD_MUST_EQUAL_KERNEL')
    return {'checked_inbound':len(expected['inbound']),'checked_reverse':len(expected['reverse']),'source_generation':expected['source_generation'],'invalidation_epoch':expected['invalidation_epoch'],'production_authority':False}
