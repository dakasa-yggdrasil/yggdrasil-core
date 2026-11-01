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


def read_nft(nl,prefix,*argv):
    # Only the fixed fixture reads are allowed here; no apply or check input.
    shapes={("-a","-j","list","ruleset"),
            ("-j","list","ruleset"),
            ("-a","list","table","inet","dakasa_capacity_network")}
    if tuple(argv) not in shapes:raise RuntimeError('EXACT_NFT_READ_REQUIRED')
    import guarded_generation as generation
    coord=generation.CI_DRAIN_COORDINATION
    if type(coord) is not marker.CoordinatorV3:raise RuntimeError('EXACT_NFT_COORDINATOR_REQUIRED')
    lease=coord.acquire_writer_lease()
    try:return nl.cmd(*prefix,'/usr/sbin/nft',*argv,writer_lease=lease)
    finally:lease.close()
