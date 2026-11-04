#!/usr/bin/env bash
# Keep the owning Core checkout clean for real -buildvcs identity. These are
# already pinned and compiled by the preceding steps; the Notify checkout is
# also consumed by later source-owned tests.
set -euo pipefail
workspace="$(cd "$GITHUB_WORKSPACE" && pwd -P)"
git_root="$(git rev-parse --show-toplevel)"
test "$workspace" = "$(cd "$git_root" && pwd -P)"
runner="$(cd "$RUNNER_TEMP" && pwd -P)"
case "$runner/" in "$workspace/"*) echo "fixture stage must be outside the Core checkout" >&2; exit 1;; esac
for source in .ci-native-hetzner .ci-bound-prometheus .ci-bound-kubernetes .ci-original-notify; do
  test -d "$workspace/$source" && test ! -L "$workspace/$source"
done
stage="$(mktemp -d "$runner/capacity-fixture-sources.XXXXXXXX")"
for source in .ci-native-hetzner .ci-bound-prometheus .ci-bound-kubernetes .ci-original-notify; do
  mv "$workspace/$source" "$stage/$source"
done
# Do not hide untracked inputs from git: the compiler must see the exact HEAD.
status="$(git -C "$workspace" status --porcelain --untracked-files=normal)"
test -z "$status"
printf 'CAPACITY_NOTIFY_FIXTURE_SOURCE_DIR=%s\n' "$stage/.ci-original-notify" >> "$GITHUB_ENV"
