# Installed Guest: historical read timeout

An installed Guest's prior Notify read can time out after its signed publication has completed. The read remains a `held` unknown effect: its challenge, original transport and hash are retained and it is never relabeled as successful or replayed. No new create, old publication replay, retirement, readiness or capacity admission is authorized by this historical record.

For the specifically pinned historical Core, Guest and Notify sources, reconciliation may inspect a fresh canary under a new fence after validating the original signed challenge, one-use Guest nonce, possible-send record, accepted causal publication, immutable issuer and compatibility map. The new epoch records the prior challenge ID and the exact historical transport hash. An incomplete publication, different source, missing original proof, changed identity or other transport failure remains held.

The pinned Guest serializes its Notify handlers and runtime participant. A busy actor or writer rejects competing work; elapsed time alone does not prove that the earlier operation stopped or had no effect. A subsequent canary establishes only its own result. PostgreSQL and signed test fixtures validate source behavior and do not establish a real Guest or provider effect; native concurrent qualification remains a separate required check.
