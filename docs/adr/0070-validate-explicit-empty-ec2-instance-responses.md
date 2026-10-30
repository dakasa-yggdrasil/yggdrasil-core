# ADR-0070: Validate explicit empty EC2 instance responses

- **Status:** Proposed
- **Date:** 2026-10-23
- **Deciders:** Core maintainers and production operator
- **Scope:** Authenticated original-create disposition observations
- **Supersedes:** —
- **Superseded by:** —

## Context

An exact-ID EC2 DescribeInstances request can return HTTP 200 with an explicitly
empty reservation set after an originally accepted instance has terminated.
The disposition observer must preserve that successful native response rather
than manufacture an HTTP error or a terminated instance. An absent field, an
SDK zero value, an empty JSON projection or a paginated response cannot establish
complete native absence.

The original accepted grant and its unknown auxiliary inventory remain
immutable. The separately authenticated AWS inventory basis still needs all six
reads that join the original account, instance, RunInstances event and request,
AMI root snapshot, snapshot descendants and owning network interface.

## Decision

Allow HTTP 200 with resource state `absent` only in that existing complementary
AWS inventory basis, after validating the entire retained raw EC2 Query XML.
Require the original body representation, canonical base64, exact byte extent
and SHA-256; the existing outer contract continues to authenticate the exact
instance identity, observer source, times, native read tuple and all six reads.

Require a single `DescribeInstancesResponse` root in the EC2 2016-11-15
namespace, exactly one nonempty bounded request ID and exactly one explicitly
empty `reservationSet`. An optional single `nextToken` must be empty. Reject
nested items, unknown or duplicate fields and attributes, other namespaces,
directives, comments, malformed or trailing content. Only XML whitespace is
empty. Keep the original HTTP status 200 and record absence separately.

Keep the previous HTTP 200 terminated and HTTP 400 absent branches unchanged.
This extension does not alter known-inventory observations, infer an empty
original settlement, accept operator flags, mutate a grant or replay a create.

## Consequences

- A complete authenticated native empty response can close the instance part of
  the existing inventory basis without falsifying its status or resource state.
- An omitted reservation set or nonempty pagination token remains unresolved.
- Complete absence of all owned auxiliaries remains independently required.
- No Guest, workflow, business readiness or savings authority follows from the
  disposition itself; a successor still needs its own fenced decision and grant.

## Related

- ADR-0069: Separate expired accepted-create dispositions
- [EC2 DescribeInstances API and response elements](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html)
- [EC2 Query requests and success responses](https://docs.aws.amazon.com/ec2/latest/devguide/Query-Requests.html)
