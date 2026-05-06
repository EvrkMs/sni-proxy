# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.24-alpine AS builder

WORKDIR /src

# Copy module files and let Go resolve everything fresh
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /sni-proxy ./cmd/sni-proxy

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM scratch

COPY --from=builder /sni-proxy /sni-proxy
# CA certs needed for DoH HTTPS requests
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT ["/sni-proxy"]
