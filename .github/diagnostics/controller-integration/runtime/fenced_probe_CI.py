"""CI-only probe subprocess custody; no recovery or mutation authority."""
import drain_marker_v3_DRAFT as marker

def call(nl,prefix,path):
    import guarded_generation as generation
    coord=generation.CI_DRAIN_COORDINATION
    if type(coord) is not marker.CoordinatorV3:raise RuntimeError('EXACT_PROBE_COORDINATOR_REQUIRED')
    lease=coord.acquire_writer_lease()
    try:
        fd=lease.validate()
        # pass_fds preserves the same flock OFD across nsenter/exec. If this
        # parent dies first the probe retains SH until its own exit.
        return nl.cmd(*prefix,'/usr/bin/python3','-I','-B',str(path),'probe',str(fd),writer_lease=lease)
    finally:lease.close()
