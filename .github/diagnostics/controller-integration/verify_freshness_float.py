"""Regression for exact original deadline, without extending source TTL."""
import dataclasses,math,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent/'runtime'))
import nft_owner as nft
import transition_adoption as adoption

for start in (38.624241261,50.642685612):
    expiry=start+30
    assert expiry-start>30, 'fixture must reproduce floating point subtraction drift'
    assert adoption._within_original_lifetime(start,expiry)
    assert not adoption._within_original_lifetime(start,math.nextafter(expiry,math.inf))
    assert not adoption._within_original_lifetime(start,start)
    items=[nft.Backend('rds','172.18.1.3',5432,start,expiry,'dns/rds'),
           nft.PrometheusSource('10.244.1.9',start,expiry,'prom/source')]
    for item in items:
        item.validate()
        assert item.expires==expiry
        too_late=dataclasses.replace(item,expires=math.nextafter(expiry,math.inf))
        try:too_late.validate();raise AssertionError('deadline beyond original 30s accepted')
        except nft.Held as error:assert str(error) in ('NATIVE_OBSERVATION_WINDOW','PROMETHEUS_NATIVE_OBSERVATION_WINDOW')
        zero=dataclasses.replace(item,expires=start)
        try:zero.validate();raise AssertionError('zero-length observation accepted')
        except nft.Held as error:assert str(error) in ('NATIVE_OBSERVATION_WINDOW','PROMETHEUS_NATIVE_OBSERVATION_WINDOW')
print('PASS exact original 30s accepted despite float drift; next representable deadline and zero-length rejected')
