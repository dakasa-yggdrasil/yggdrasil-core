# ADR-0051: Keep original creator admission source-owned and durably sealed

- **Status:** Proposed
- **Date:** 2026-10-13
- **Deciders:** Giovanni Martins
- **Scope:** Core original creator lifecycle, Host admission and persistent exclusions
- **Supersedes:** None
- **Superseded by:** None

## Context

Missing Guest enrollment, a missing provider result or an elapsed lease does not
prove that an original creator never started. A valid signature authenticates
bytes; it does not establish the original process, descriptor, return or absence
of another possible writer. An uncertain original remains in HOLD.

The ordinary creator must retain its actual prepared command and local mutation
permission. Host admission needs a separate sealed branch that cannot acquire
that permission or dispatch the command. Both branches share permanent identity
and exclusion rules; a new source revision, policy, generation or root cannot
turn a missing record into permission to create again.

## Decision

Admit the original creator through a fixed compiled source constructor and keep
all native ownership capabilities private to that process lifetime. Capture the
initial source-owned empty-realm observation before the actual public assessment
and single claim. Bind the actual private invocation once, store the original
claim JSON buffer in the same transaction, and capture its original Go return
before controller redaction. A capture failure after commit preserves the lease
in HOLD; it cannot claim rollback, renew the deadline or issue a second claim.

Prime the original Root and I/O history in SQL before public assessment or claim.
This source-owned operation consumes its original reservation before the first
transaction and retains the actual commit and Go return. Only verified SQL FIRST
associations and the complete original source/native graph can establish positive
initial admission. Run the current admission check after that successful commit
and its actual Go return, under the same original context, before public assessment
or claim. Validation inside the transaction may reject a commit but cannot release
an effect. Private registrar transfer authenticates custody before this
step; it supplies no SQL FIRST or native permission. Initial observations follow
their actual pre-claim chronology without requiring a future lease retroactively.

Keep Host admission sealed before possible creation. The ordinary path uses its
own early bootstrap and credential stream, parks the late grant descriptor until
actual preparation and registration, then redeems the original grant through the
current public guards. Only that same worker may hold the unexported once-only
creation capability for the same prepared command. Host records, signatures and
credentials cannot substitute for this capability.

Persist canonical original body and envelope bytes with immutable root, target,
owner, scope and grant associations. Exclude mutable source and policy epochs
from permanent target keys. Check these associations before grant expiry, reuse
and replay, including callbacks without a local Host context. Missing or restored
source trust remains unavailable. Keep Root and Scope credentials separate and
restrict recovery to the same original identity and exact retained hash.

Retain original I/O calls in immutable chunks and bounded manifests. Publish
completed returns once before a pending singleton. Its real return is a separate
singleton linked to the original pending fact; final coverage selects completed
chunks and real successors without overlap or duplicate calls. Preserve pending
history. Missing returns, owner joins or predecessor relations remain incomplete.
Wait, EOF, descriptor Close, pin return and process exit are separate observations.

An operation vector may span interleaved ordinals only when the complete original
handle inventory accounts for every intervening call. Terminal chunks themselves
retain contiguous original runs. A standalone sparse vector cannot establish
complete coverage, and a missing SQL FIRST association cannot be inferred from
row absence.

Keep native observations in complete bounded original records and use typed
immutable references in aggregate observations. The selected inline initial
observation cannot fit the existing 65,536-byte body limit under conservative
static bounds. Check each complete record and its signing envelope against their
separate limits; base64 encoding increases envelope size. Consumers resolve the
exact original bodies, envelopes, ownership, binding, I/O inventories and full
before/after thread census. References do not establish completeness on their own.
The exact representation requires one paired producer/consumer proposal before
Source adoption. A nonrepresentable observation remains HOLD without dropping,
reindexing or rewriting original returns.

Capture the effective source-owned phase context before its I/O and preserve the
original declared Root lifetime. Authenticate each aggregate's fixed original
signed native anchor and compare its deadline with that actual phase context.
A private RPC expectation cannot create this authority. Keep original Root
bindings, handle identities, acquisition deadlines and counters when later
Scope or ordinary observations reference those exact ancestor records.

Reserve the original phase under its preowned RPC slot before fresh parent or
child I/O. Transfer that actual parent phase origin through the original request
custody, while preserving each observer's own later reservations and returns.
The child retains the possibly smaller parent Root bound from the first actual
initial request read and its EOF and Close; later observations cannot replace it
with the declared lifetime or a minimum of sampled record times. Terminal inputs
precede their independent observation: the original choice and parent join for
the sealed branch, and the actual creator return for the ordinary branch.
Disposition, independent QMP results and settlement follow their actual returns.

Transfer the registrar's complete signed originals and private custody records
through fixed one-shot files under the same held original root. Native records,
envelopes and reference manifests retain their separate byte limits. Preserve
actual raw getdents buffers, including a known empty buffer, separately from an
unknown return. Source file EOF, metadata and signatures cannot substitute for
the original syscall, call inventory, source basis or complete thread census.
Keep independent observers and the original compiled signer roles; composition
does not re-sign another observer's records or copy its reservations.

Transfer the parent's actual original graph before each normal registrar phase.
Reserve that export once before its I/O and retain its successful owning return;
the final request only copies the cached original manifest. A fresh registrar
observation cannot replace an ancestor's process, bootstrap or I/O record.

Bind transferred getdents files to their exact source-owned writer and reader
handles and every actual audit call. A known empty native buffer has no file
Write call: retain its actual Open, Fstat, Sync and Close, followed by the separate
publication Rename and directory Sync. Transfer that complete writer audit as a
bounded private original and retain its own reader's EOF and Close. Select an
empty source file only through the same signed native call, raw count, errno,
binding and SQL FIRST association. Local kernel custody cannot excuse an empty
transfer file, and these private audit records confer no native permission.

Bound private transfer metadata through typed reference trees without splitting
the returned native facts. Authenticate every whole original file, request,
category, range and reference, and match all supplied metadata files to the
reachable tree. Missing files, cycles, unused files, overlaps or gaps remain HOLD.
An empty metadata category describes transfer structure and proves no native
absence. The original roster and Source audit limits still apply to the complete
transfer; a geometry that exceeds either limit remains unavailable.

Seal publication and join the actual launch and observation owners before the
original registrar's graceful closing exchange. Consume its pre-reserved closing
slot before cancelling the Root or signalling the same process. A missing or
uncertain closing reply uses the original fallback join and remains HOLD. Close
held roots, pins and ledgers only after the actual owning returns. Cleanup time
supports diagnostic retention and joins, not a new native admission window.

Persist original closing I/O while the same database remains open. The Realm
signs and caches its own closing records during its actual close; the subsequent
getter only copies those originals. The Main owner persists their immutable SQL
associations once before closing the database and retains the actual commit and
Go return. Later closing rows are separate from the earlier live snapshot. Unknown
commit outcomes remain HOLD. Final completion follows the actual resource returns,
and the final getter copies the cached corpus.

Join the actual server, handler and workflow owners before closing the Realm.
Retain the Realm, transport and closing SQL returns before calling broker Close;
its actual return precedes database Close. Each operation keeps its own original
deadline, including a smaller shutdown bound. Cleanup cannot backdate those
returns or provide a new observation window.

## Consequences

Production and Host qualification registries remain empty until actual reviewed
source, publication, build and approval inputs exist. Source implementation,
cryptographic grammar validation and SQL association checks grant no native
execution, Guest creation, enrollment, capacity, settlement or provider billing
claim. Physical qualification and its finite resource authorization are separate.

Keep all original capacity assertions and censuses. Additional Source and
PostgreSQL cases describe their own evidence boundary and cannot replace the
original native positives or qualify a larger geometry. The existing provisioning,
retirement and snapshot ABI and their original smaller deadlines stay unchanged.
Owning GitHub Actions supplies execution evidence after the cohesive Source
review.

## Related

- [ADR-0036](0036-redeem-provider-mutations-once-under-durable-capacity-authority.md): durable original mutation redemption.
- [ADR-0040](0040-separate-native-process-lifetimes-from-reservation-decisions.md): independent native lifetime ownership.
- [ADR-0050](0050-bind-guest-admission-and-retirement-to-original-native-returns.md): Guest admission, enrollment and retirement boundaries.
