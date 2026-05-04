FROM golang:1.25-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=1 go build \
      -ldflags "-s -w -X main.Version=${VERSION}" \
      -o /argus ./cmd/argus

# ── runtime ──────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /argus /usr/local/bin/argus

# Data directory for the DuckDB file
VOLUME ["/data"]
ENV ARGUS_DB=/data/vulns.db

# Ollama host — point to your Ollama instance
ENV OLLAMA_HOST=http://host.docker.internal:11434

ENTRYPOINT ["argus", "--db", "/data/vulns.db"]
CMD ["--help"]
