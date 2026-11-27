# AI docs freshness stamp

The reconciliation gate measures this source diff and actual generated context.
Earlier reviews remain in Git history and their owning Source/CI receipts.

verified_at_commit: 8f53fa673337db41d54dda69ff0121226e0f6690
verified_diff_sha256: 0436a96a0a0740063528ec358228e33bf3b6e7a3e257baf7b1687a88527d493a
reconciler_schema: 1

Reviewed the exact published Commons dual-reader commit and complete tracked-tree
SHA256, the unchanged complete source selection, bounded deterministic v2 producer,
index paths and per-leaf hashes/sizes/counts, and all current service-contract
references. Static artifact comparison preserves every894 prior source fact after
normalizing the existing empty build-constraint default. Other10 evidence envelopes
are byte-identical. Two leaves plus index occupy147040bytes; limits stay128KiB per
file,2MiB including index,16 leaves and4096 unique facts.

CI first runs the actual new checker against published complete v1 Core34d664,
then verifies current v2 generation, every union fact and the same complete actual
source-tree walk. Independent whole bounded review reported no open finding.
Only static parsing, formatting/diff checks and the released Source/context
and reconciliation generators ran locally. No local tests/builds/vet or product
execution occurred. Actual CI remains required; this change activates no provider,
worker, private factory, capacity owner or production switch.
