# AI docs freshness stamp

The reconciliation gate measures this source diff and actual generated context.
Earlier reviews remain in Git history and their owning Source/CI receipts.

verified_at_commit: 5327066b26c541cce15d8d3abc18072245090c1d
verified_diff_sha256: d681d6a5126513a465d2bf5fc4e1a7d61b63978aba246686e2235891880b73df
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
