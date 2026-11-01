"""Disposable systemd sender verifies writer lease precedes its socket."""
import os,socket,sys
from pathlib import Path
import drain_marker_v3_DRAFT as marker
if os.geteuid()!=0 or os.environ.get('CI_GUARDED_FIXTURE')!='1':raise RuntimeError('ONLY_PRIVATE_CI')
coord=marker.CoordinatorV3(Path(sys.argv[1])/'coord')
try:lease=coord.acquire_writer_lease()
except BlockingIOError:
    print('PASS isolated restart held before writer socket while EX lives',flush=True)
    sys.exit(0)
# If a writer gets a lease it would now be permitted to open its socket;
# this is always a failure for this particular EX-held diagnostic.
lease.close()
raise RuntimeError('RESTART_ACQUIRED_WRITER_LEASE_WHILE_EX_HELD')
