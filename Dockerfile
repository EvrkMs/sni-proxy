FROM golang:1.24-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal

ARG TARGETARCH
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /sni-proxy ./cmd/sni-proxy

FROM scratch
COPY --from=builder /sni-proxy /sni-proxy
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/sni-proxy"]