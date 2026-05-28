#!/usr/bin/env bash
# lint-no-legacy-error-envelopes.sh — §14 RFC 7807 regression guard.
#
# Fails CI when a §14-CLOSED handler file (auth/MFA/password) emits a
# 4xx/5xx HTTP error response using the legacy `writeJSON(w, status,
# map[...]{...})` shape instead of the canonical
# `httperr.WriteProblem(...)` helper. Files outside §14-close scope are
# reported as WARN until their own migration cycle lands.
#
# §14 of INTEGRATION_CONTRACT requires Content-Type=application/problem+json
# and a stable dotted `code` field on every error body. The legacy shape
# emits Content-Type=application/json and no canonical code namespace —
# surfaces have to fall back to regex-humanizers (the bug §14 fixes).
#
# Migration scope (CLOSED 2026-05-28):
#   - controllers/httpapi/auth.go
#   - controllers/httpapi/mfa.go
#   - controllers/httpapi/credentials.go
#   - controllers/httpapi/middleware_credentials.go
#
# Whitelist: success-path responses (StatusOK / StatusCreated /
# StatusAccepted / StatusNoContent) are explicitly allowed to use the
# raw writeJSON helper. The Problem+JSON envelope is for FAILURES only.
#
# Exit: 0 = clean (or only out-of-scope warnings), 1 = a CLOSED file
# regressed.
#
# Usage:
#   ./scripts/lint-no-legacy-error-envelopes.sh           # full repo scan
#   ./scripts/lint-no-legacy-error-envelopes.sh --diff    # only changed files vs origin/main

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# CLOSED files: regression here is HARD-FAIL. Future cycles add to this list.
CLOSED_FILES=(
  "controllers/httpapi/auth.go"
  "controllers/httpapi/mfa.go"
  "controllers/httpapi/credentials.go"
  "controllers/httpapi/middleware_credentials.go"
)

FORBIDDEN_PATTERN='writeJSON\(.*http\.Status(BadRequest|Unauthorized|Forbidden|NotFound|Conflict|UnprocessableEntity|Locked|TooManyRequests|PreconditionRequired|NotImplemented|ServiceUnavailable|InternalServerError|Gone|RequestTimeout|UnsupportedMediaType).*map\[string\]'

if [[ "${1:-}" == "--diff" ]]; then
  FILES=$(git diff --name-only origin/main...HEAD -- 'controllers/httpapi/*.go' 2>/dev/null || true)
else
  FILES=$(find controllers/httpapi -name "*.go" ! -name "*_test.go" -print)
fi

if [[ -z "$FILES" ]]; then
  exit 0
fi

EXIT_CODE=0
WARN_COUNT=0
FAIL_COUNT=0

for f in $FILES; do
  hits=$(grep -nE "$FORBIDDEN_PATTERN" "$f" 2>/dev/null || true)
  if [[ -z "$hits" ]]; then
    continue
  fi
  is_closed=0
  for c in "${CLOSED_FILES[@]}"; do
    if [[ "$f" == "$c" ]]; then
      is_closed=1
      break
    fi
  done
  if [[ $is_closed -eq 1 ]]; then
    echo "::error file=$f::§14 RFC 7807 REGRESSION — file is CLOSED, use httperr.WriteProblem(...)" >&2
    echo "$hits" >&2
    FAIL_COUNT=$((FAIL_COUNT + 1))
    EXIT_CODE=1
  else
    echo "::warning file=$f::§14 RFC 7807 pending migration (out of §14-close scope)" >&2
    echo "$hits" | sed 's/^/  /' >&2
    WARN_COUNT=$((WARN_COUNT + 1))
  fi
done

echo "" >&2
echo "Summary: $FAIL_COUNT hard-fail file(s), $WARN_COUNT pending-migration file(s)" >&2
echo "Docs: docs/error_codes.md" >&2

exit $EXIT_CODE
