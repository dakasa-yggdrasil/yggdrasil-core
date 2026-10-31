# CI-only recovery marker evidence

This branch is a diagnostic built on guarded drain v3 commit `c4ae0f6`.
It does not install a service, authorize writes, clear an intent or establish
production readiness. The current production Guardian is not modified.

`recovery_terminality_DRAFT.py` retains a pidfd from an authenticated live
systemd peer in the same custodian process, captures the original marker's
device, inode and digest, and verifies that marker's process, start ticks,
systemd unit, invocation, cgroup, boot and network namespace match the peer.
It later requires terminal pidfd, exact failed/dead systemd invocation, no job,
and an unpopulated original cgroup. It anchors the cgroup v2 mount, mount and
cgroup namespaces and system.slice; missing cgroup means empty only after the
same mount and slice remain validated. Marker and terminal state are reread.
The return is a point-in-time observation, not a recovery capability.

The test creates the real v3 marker in a separate systemd process. It checks
that a live child prevents terminal evidence, that a replaced cgroup mount in a
private mount namespace is rejected, that a new invocation cannot use the
pending marker, and that changed marker bytes invalidate the snapshot. Linux
CI run 41253293667 passed these cases. This test does not demonstrate real
controller/Guardian service installation or recovery of an uncertain write.
Normal `systemctl stop` may remove InvocationID: this prototype holds instead
of inventing terminal history. Capturing a pidfd after the original process has
already disappeared is not supported.

Before any distinct recovery authority could be considered: a trusted surviving
custodian must capture every possible sender before its lifetime ends; the
system must establish exclusive privileged writer/socket custody, fence all
restarts and conflicting writers throughout recovery, independently reconcile
the original result and current nft generation and BPF program/map identity,
revalidate fresh Reader observations, and bind a one-use distinct send to those
facts. An unknown send or ACK must retain the original marker until an
independently verified disposition. None of those missing properties is
provided by this evidence helper. Callers must not convert it to write authority.
