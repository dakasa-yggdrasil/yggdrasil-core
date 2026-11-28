# ADR-0147: Receive Native abort closure from independent original resource inventory

- **Status:** Proposed
- **Date:** 2026-11-27
- **Deciders:** Giomaster
- **Scope:** Core / protected pre-admission abort receiving and immutable resource custody
- **Supersedes:** —
- **Superseded by:** —

## Context

The pre-admission abort store fences admission and exposes a single provider
delete right, but a provider acceptance or a terminated VM cannot prove that
its disks, interfaces and IPs are gone. The concrete network composition now
retains original launch and floor facts. Independent provider cleanup readers
and a complete Kubernetes Node/Pod inventory must join that same sealed birth.
The mutable latest observation is not historical resource authority.

## Decision

Compose `NativeWorkerConcreteAbortRuntime` only from the exact installed Core
Source, copied policy and database, a borrowed concrete network/worker runtime,
and separately owned protected read clients. The controller composition builds
the original catalog/resolver/RPC callbacks; no workflow supplies a URL, reader,
credential, resource inventory or absence claim. Reject shared opaque client
state, including copied wrappers, before taking ownership. Failed construction
closes nothing. Shared Close closes only the owned read handles.

Require optional `abort_inventory_observer` explicitly for this composition.
It pins a separate Kubernetes role, Source and whole inventory-file scope; it
does not reuse the admission observer's scope or grant a writer permission.
Absence preserves the old policy wire. Provider reader roles may explicitly
pair physical observation with cleanup; no reader role can mix with a writer.

Load the private immutable original and exact current Attempt/Launch before
any remote read. A null provider footprint can capture PRESENT facts only.
Persist the first nonnull safe snapshot in append-only abort history before a
delete right is exposed, including when Begin saw unknown and Redeem first
observes present. Compare redemption against that history in the same locked
transaction even if Reconcile replaced the latest observation. Resource IDs,
lifetime, ownership, Source/scope, allocation flags and public IP identity are
immutable. AWS execution state and observation time can progress without
replacing resource identity. The public abort permit wire stays unchanged.

For GET-only receiving, select ancillary reads solely from committed historical
custody. Require exact provider reply identity, complete fresh reads and every
original resource. Typed not-found is distinct from generic 404, denial, empty
collection, incomplete transport and unknown state. AWS terminated alone does
not close EBS or ENI charges; actual deleted EBS and typed missing ENI are checked
independently. HCloud server/local root and each actual Primary IP must close.
A present Primary IP is still chargeable; deletion cannot be sent through this
runtime when the captured IP is protected or does not auto-delete.

Derive the original Node hostname from the stored Attempt UUID and sealed
physical instance ID using the System bootstrap formula. Require the protected
complete all-namespace Pod inventory around exact Node/registry identity, realm,
pool epoch and birth. Every nonterminal Pod counts. Missing or unhealthy Node
facts do not prove zero Pods. Admitted registry identity or lost quarantine
cannot authorize a pre-admission delete; a present candidate also needs actual
cordon before send. Registry retirement remains an independent writer.

Receive a fresh complete floor peer/address-route/firewall inventory and join
all retained network producers. An exposed install with a closed partial
original still requires observed compensation; a momentarily absent peer does
not settle an active producer. `IPAMEntryAbsent` here means no external use of
the reserved address under that complete owned network projection and producer
fence. The internal Attempt/IP/cost reservation remains held until the existing
store atomically transitions to absent. Goose117 independently arbitrates
late network sends and final address release; no SQL guard is weakened.

## Consequences

This Source supplies a concrete read-only consumer, not a generic cleanup
writer. Node cordon/deletion, registry retirement and any non-disposable resource
cleanup remain separate capabilities. Unknown creation without a sealed birth
stays held; no original acceptance, HTTP identity or lifetime is fabricated.
There is no main-process installation or production activation in this change.

CI qualifies pure closed receiving and alias cases, real PostgreSQL append-only
custody/redemption/closure, the normally published System factory handle and
actual floor mTLS clients. Provider/Kubernetes/floor facts in the composition
fixture are explicitly synthetic. They do not prove a live provider deletion,
guest network, end-to-end MTU, warmup, admission, billing closure or production
provider switching. Tests execute only in GitHub Actions.

## Related

- ADR-0134: Source-owned pre-admission abort and separate cleanup requirements.
- ADR-0141: Typed HCloud original/independent witness and sealed lifetime.
- ADR-0143 and ADR-0145: Protected floor network clients and composition.
