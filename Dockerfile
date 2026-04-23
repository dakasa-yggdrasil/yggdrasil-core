FROM golang:1.25-bookworm AS build

WORKDIR /build

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    GOPROXY=https://proxy.golang.org,direct

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o /bin/yggdrasil-core . \
 && go build -o /bin/goose ./scripts/goose \
 && go build -o /bin/yggdrasil-bootstrap ./scripts/bootstrap

FROM alpine:3.21

RUN apk add --no-cache ca-certificates curl \
    && curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
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
