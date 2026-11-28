# AI docs freshness stamp

The reconciliation gate measures this source diff and actual generated context.
Earlier Source and CI receipts remain in their original history.

verified_at_commit: 9dbbf5c23ef5611b52b5d5d6e4c371cc09280eee
verified_diff_sha256: 66d4593ce022e6cc6748030f6aa1b5b71c548f61067f3d58cc390f6caaf54c85
reconciler_schema: 1

Reviewed the two test-only fixture changes against actual Main3b. The normal
Main race gate reported a controller-pin write after the UDP receiver started.
Fixture pin, key and deadline substitutions now occur before either receiver
starts. Production code, all fourteen roots, race/count, the 200ms incomplete
exchange deadline, packet assertions and normal publication gates are unchanged.
The genuine original failure is preserved; no local test/build/vet was run.

The installed released CLI produced the actual plan against Main3b and both
context outputs before this stamp. CI must validate this successor. No cloud
mutation, paid test, image adoption, installation or Hetzner load is claimed.
