"""Probe only disposable Linux CI kernel support for the candidate's real BPF."""
import os,time
import guarded_nl
record=guarded_nl.make_program([('01'*12,time.monotonic_ns()+10_000_000_000)])
try:
    assert guarded_nl.map_rows(record['map_id'])
    print('PASS real frozen BPF tuple map and candidate program; no nft attach',flush=True)
finally:
    os.close(record['program_fd']);os.close(record['map_fd'])
