# Submit inventory — CI/LAB only

The GenerationEmitter.submit method is the common gate. This inventory covers
the diagnostic tree only and does not claim all production writers are known.

- runtime/controller.py (2): original 47 and guarded positive paths; require a
  durable v3 marker and positive permit before prepare/send.
- runtime/ci_guardian50_session.py (2): Guardian emergency deny and separate
  deny recovery; require Guardian-bound deny-only permits and preserve marker.
- runtime/ci_guardian_registry.py (1): direct positive stand-in, requires a
  marker/permit and cannot use a boolean bypass.
- runtime/guarded_generation.py (1): fixture deny-after-unverified helper,
  requires authenticated emergency permit.
- verify_controller_guardian.py (5): rejected duplicate, injected unknown
  positive, rejected replay, separate deny recovery and standalone positive
  test. Direct calls need isolated coordination or authenticated recovery.

The BPF admission guard deliberately denies even when no marker is pending until
pin/genid/maps plus NFT tuples have an independently sealed witness. This
fixture does not establish production source sealing, host-wide exclusivity,
systemd recovery custody or authorization.
