# Submit inventory — CI/LAB only

GenerationEmitter.submit is the common guarded gate for the active fixture.
verify_submit_inventory.py tracks every submit call in both trees and fails on
new or removed call sites. This does not inventory production writers.

Active fixture, six call sites:
- runtime/controller.py (2): original 47 and guarded positive paths require the
  durable v3 marker and positive permit before prepare/send.
- runtime/ci_guardian50_session.py (2): Guardian emergency deny and separate
  deny recovery require distinct Guardian-bound deny-only capabilities and
  preserve the old marker.
- runtime/ci_guardian_registry.py (1): direct positive stand-in, requires an
  integrated marker/permit; no boolean bypass exists.
- runtime/guarded_generation.py (1): deny-after-unverified fixture helper,
  requires authenticated emergency capability.

Untouched legacy 8b5ad8d fixture, eleven call sites: same six plus five
standalone probes in verify_controller_guardian.py. The workflow runs its
entire original suite in separate fresh network namespaces and directories.
That legacy run does not demonstrate v3 marker/recovery. The v3 integrated
Guardian executes the send/unknown ACK/independent deny cases under real
Guardian capability in all four configured order/ACK combinations, while
retaining the unknown marker.

The BPF admission guard deliberately denies even without pending marker until
pin/genid/maps plus NFT tuples have an independently sealed witness. Source
sealing, host-wide exclusivity, systemd recovery custody and production
authorization are not established here.
