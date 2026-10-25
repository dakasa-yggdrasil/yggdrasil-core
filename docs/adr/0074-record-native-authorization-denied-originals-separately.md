# ADR-0074: Record native authorization-denied originals separately

- **Status:** Proposed
- **Date:** 2026-10-23
- **Deciders:** DaKasa platform maintainers
- **Scope:** Core capacity original-provider accounting
- **Supersedes:** —
- **Superseded by:** —

## Context

An owning single-send AWS RunInstances attempt can settle as uncertain without
resource or action identities when its SDK caller reports an error. A subsequent
authenticated CloudTrail event can establish that this exact request received an
authorization denial. Replacing the original settlement would invent an original
return. Accepted-create absence and witnessed-Guest failure have different
preconditions and must retain their existing meaning.

## Decision

Append a separate native-authorization-denied terminal ledger. The administrative
endpoint accepts only the original grant and dispatch job identities. Core loads
the immutable grant, preregistration, failed Create step and original unknown ACK,
then obtains source-pinned read-only evidence itself. The observer joins the
original client token, native request, scope, account, principal, region and time
to exactly one complete CloudTrail authorization-denial decision and a defensive
empty exact-client-token DescribeInstances read. It authorizes no provider writes.

Preserve the original uncertain settlement and missing identities. A distinct
terminal dispatch state and single fence advance close accounting; execution
remains prohibited until a new assessment, decision and grant. This is not an
accepted create, original HTTP error receipt, historical auxiliary-resource
absence, Guest never-started assertion, useful capacity or business evidence.

CloudTrail user-data is removed in RAM before evidence retention. Its explicit
projection records EOF/Close and hashes only the projected bytes. Original
CloudTrail body bytes, length and digest are not retained or claimed. STS and
DescribeInstances keep their bounded original read representations.

## Consequences

The new migration is additive; accepted-create and witnessed-failure ledgers stay
unchanged. Begin and Complete recheck the same closed original snapshots and
locks. Database constraints require atomic ledger/grant/job/failed-intent links
and preserve immutable terminal history. Missing, ambiguous, foreign, paginated
incomplete, successful or non-authorization events remain held. A new creator or
observer implementation requires explicit source review and publication pins.

## Related

- [ADR-0069](0069-record-expired-unadmitted-create-dispositions-separately.md)
- [ADR-0073](0073-record-terminal-failed-witnessed-original-lifetimes.md)
- [EC2 authorization failure](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/troubleshooting-launch.html#insufficient-permissions)
- [IAM request authorization](https://docs.aws.amazon.com/IAM/latest/UserGuide/intro-structure.html)
