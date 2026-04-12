FROM golang:1.25-bookworm AS build

WORKDIR /build

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    GOPROXY=https://proxy.golang.org,direct

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o /bin/yggdrasil-core .

FROM gcr.io/distroless/base-debian12:nonroot

WORKDIR /app

COPY --from=build /bin/yggdrasil-core /app/yggdrasil-core

EXPOSE 9080
ENTRYPOINT ["/app/yggdrasil-core"]
