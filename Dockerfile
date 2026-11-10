# Copyright (c) 2026 Veld Authors.
# SPDX-License-Identifier: MIT

# ── Stage 1: build ────────────────────────────────────────────────────────────
# golang:1.26.10-alpine — includes a ca-certificates bundle that distrusts the
# eMudhra intermediates (emSign Root TLS CA - G3, emSign ECC Root CA - G3).
# Pinned by digest for reproducible builds; bump via Dependabot docker updates.
FROM golang@sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e AS builder

WORKDIR /src

# Upgrade ca-certificates to pick up the eMudhra distrust (Alpine 20261020-r0
# or later), then fail the build if the distrusted roots are still trusted.
RUN apk upgrade --no-cache ca-certificates \
 && if grep -q "emSign Root TLS CA - G3\|emSign ECC Root CA - G3" /etc/ssl/certs/ca-certificates.crt; then \
        echo "ERROR: ca-certificates bundle still trusts a distrusted eMudhra root" >&2; \
        exit 1; \
    fi

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
# The builder bundle is verified free of emSign Root TLS CA - G3 and
# emSign ECC Root CA - G3 by the RUN step above.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY --from=builder /out/veld-coord /veld-coord

# gRPC listen port
EXPOSE 50051

# Persist the bbolt database across container restarts.
VOLUME ["/data"]

ENTRYPOINT ["/veld-coord"]
CMD ["-listen", ":50051", "-db", "/data/coord.db"]