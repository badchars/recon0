# ══════════════════════════════════════════
# recon0 — All-in-one Recon Pipeline Image
# ══════════════════════════════════════════

# ── Stage 1: Build recon0 binary ──
FROM golang:1.23-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /recon0 ./cmd/recon0

# ── Stage 2: Install Go security tools ──
FROM golang:1.23-bookworm AS tools
ENV GOBIN=/tools/bin

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ── Stage 3: Final image ──
FROM ubuntu:24.04

# System deps + Chromium for CDP crawling
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libpcap-dev \
    jq \
    dnsutils \
    curl \
    wget \
    chromium-browser \
    fonts-liberation \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libgbm1 \
    libasound2t64 \
    libpangocairo-1.0-0 \
    libxdamage1 \
    libxrandr2 \
    libxcomposite1 \
    libxshmfence1 \
    && rm -rf /var/lib/apt/lists/*

# Tool binaries from builder stages
COPY --from=builder /recon0 /usr/local/bin/
COPY --from=tools /tools/bin/* /usr/local/bin/

# nuclei templates (pre-download)
RUN nuclei -update-templates 2>/dev/null || true

# Chrome path for CDP
ENV CHROME_PATH=/usr/bin/chromium-browser

# Default working directory
WORKDIR /data

# Labels
LABEL org.opencontainers.image.title="recon0"
LABEL org.opencontainers.image.description="Bug bounty recon pipeline"
LABEL org.opencontainers.image.source="https://github.com/badchars/recon0"

ENTRYPOINT ["recon0"]
CMD ["--help"]
