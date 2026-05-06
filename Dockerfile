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
# yggdrasil-console is a private repo. CI passes a GitHub token via
# BuildKit secret (id=github_token) and we wire it into git via
# `insteadOf` so the clone re-uses the token without leaking it into
# any image layer. The token file is mounted only for this RUN.
# The guard allows local builds without a token (will only succeed if
# CONSOLE_REPO is overridden to a public mirror or unset).
RUN --mount=type=secret,id=github_token \
    apk add --no-cache git \
 && if [ -f /run/secrets/github_token ]; then \
        TOKEN=$(cat /run/secrets/github_token) \
     && git config --global url."https://x-access-token:${TOKEN}@github.com/".insteadOf "https://github.com/"; \
    fi \
 && git clone --depth=1 --branch "${CONSOLE_REF}" "${CONSOLE_REPO}" . \
 && npm ci \
 && npm run build

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
