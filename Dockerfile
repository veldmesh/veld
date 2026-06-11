# Copyright (c) 2026 Veld Authors.
# SPDX-License-Identifier: MIT

# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /src

# Fetch dependencies separately for layer caching.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/veld-coord \
    ./cmd/veld-coord

# ── Stage 2: minimal runtime image ────────────────────────────────────────────
FROM scratch

# CA certificates for outbound TLS (e.g. future managed webhooks).
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY --from=builder /out/veld-coord /veld-coord

# gRPC listen port
EXPOSE 50051

# Persist the bbolt database across container restarts.
VOLUME ["/data"]

ENTRYPOINT ["/veld-coord"]
CMD ["-listen", ":50051", "-db", "/data/coord.db"]
