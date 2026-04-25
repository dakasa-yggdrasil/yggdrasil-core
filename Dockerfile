# Multi-stage build with cross-compile support.
# Build stage runs on BUILDPLATFORM (e.g. arm64 on Apple Silicon dev) and Go
# cross-compiles to TARGETPLATFORM (e.g. amd64 for production). Avoids qemu
# emulation, which segfaults the Go toolchain on M-series Macs.
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

RUN go build -o /bin/yggdrasil-core . \
 && go build -o /bin/goose ./scripts/goose \
 && go build -o /bin/yggdrasil-bootstrap ./scripts/bootstrap

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
# Ship schema migrations and default seed manifests so a self-hosted
# deployment can `goose up` and bootstrap without mounting anything.
COPY db/migrations /app/db/migrations
COPY docs/bootstrap /app/docs/bootstrap
COPY scripts/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 9080
ENTRYPOINT ["/app/entrypoint.sh"]
