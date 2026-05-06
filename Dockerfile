# Multi-stage build with cross-compile support.
# Build stage runs on BUILDPLATFORM (e.g. arm64 on Apple Silicon dev) and Go
# cross-compiles to TARGETPLATFORM (e.g. amd64 for production). Avoids qemu
# emulation, which segfaults the Go toolchain on M-series Macs.

# Stage 0: build the Yggdrasil console SPA.
# The output replaces the placeholder index.html committed at
# controllers/console/yggdrasil-console-dist/ before the Go embed pass.
# Pinned to node:20 LTS for reproducibility; bump deliberately.
FROM --platform=$BUILDPLATFORM node:20-alpine AS console-build
WORKDIR /console
ARG CONSOLE_REPO=https://github.com/dakasa-yggdrasil/yggdrasil-console.git
ARG CONSOLE_REF=main
# WITH_CONSOLE controls whether to clone+build the console SPA bundle.
# When unset/false (default in CI without a cross-repo token), the
# stage produces an empty /console/dist with a minimal placeholder so
# COPY --from=console-build in the build stage still works; the Go
# binary then serves the placeholder from controllers/console/yggdrasil-console-dist
# already committed to this repo.
#
# When set to true, the stage clones the private dakasa-yggdrasil/yggdrasil-console
# repo using the BuildKit secret id=github_token (which must be a PAT
# or GitHub App token with read access to that repo — GITHUB_TOKEN of
# the current repo does NOT suffice for cross-repo clones).
ARG WITH_CONSOLE=false
RUN --mount=type=secret,id=github_token \
    if [ "${WITH_CONSOLE}" = "true" ]; then \
        apk add --no-cache git \
     && if [ -f /run/secrets/github_token ]; then \
            TOKEN=$(cat /run/secrets/github_token) \
         && git config --global url."https://x-access-token:${TOKEN}@github.com/".insteadOf "https://github.com/"; \
        fi \
     && git clone --depth=1 --branch "${CONSOLE_REF}" "${CONSOLE_REPO}" . \
     && npm ci \
     && npm run build; \
    else \
        echo "WITH_CONSOLE=false — skipping console SPA build (placeholder used)"; \
        mkdir -p /console/dist; \
        echo '<!doctype html><meta charset=utf-8><title>Yggdrasil Console</title><body>Console SPA was not embedded in this image (WITH_CONSOLE=false at build time). Mount via WithConsole ServerOption only when the bundle is present.</body>' > /console/dist/index.html; \
    fi

FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /build

ENV CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH \
    GOPROXY=https://proxy.golang.org,direct

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Replace the committed placeholder bundle with the freshly-built one
# from stage console-build. The destination dir already exists with a
# placeholder index.html so go:embed compiles in dev/local builds.
COPY --from=console-build /console/dist ./controllers/console/yggdrasil-console-dist

RUN go build -o /bin/yggdrasil-core . \
 && go build -o /bin/goose ./scripts/goose \
 && go build -o /bin/yggdrasil-bootstrap ./scripts/bootstrap \
 && go build -o /bin/yggdrasil-bootstrap-admin ./scripts/bootstrap-admin

FROM alpine:3.21

ARG TARGETARCH=amd64

RUN apk add --no-cache ca-certificates curl \
    && curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/${TARGETARCH}/kubectl" \
    && chmod +x kubectl \
    && mv kubectl /usr/local/bin/ \
    && rm -rf /tmp/*

WORKDIR /app

COPY --from=build /bin/yggdrasil-core /app/yggdrasil-core
COPY --from=build /bin/goose /app/goose
COPY --from=build /bin/yggdrasil-bootstrap /app/yggdrasil-bootstrap
COPY --from=build /bin/yggdrasil-bootstrap-admin /app/yggdrasil-bootstrap-admin
# Ship schema migrations and default seed manifests so a self-hosted
# deployment can `goose up` and bootstrap without mounting anything.
COPY db/migrations /app/db/migrations
COPY docs/bootstrap /app/docs/bootstrap
COPY scripts/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 9080
ENTRYPOINT ["/app/entrypoint.sh"]
