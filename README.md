<p align="center">
  <br>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/badchars/recon0/main/.github/banner-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/badchars/recon0/main/.github/banner-light.svg">
    <img alt="recon0" src="https://raw.githubusercontent.com/badchars/recon0/main/.github/banner-dark.svg" width="700">
  </picture>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.24-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/CDP-Chromium-4285F4?style=flat-square&logo=googlechrome&logoColor=white" alt="CDP">
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#pipeline">Pipeline</a> &bull;
  <a href="#providers">Providers</a> &bull;
  <a href="#dsl-engine">DSL Engine</a> &bull;
  <a href="#api">API</a> &bull;
  <a href="#configuration">Configuration</a> &bull;
  <a href="#docker">Docker</a>
</p>

---

**recon0** is a modular reconnaissance framework written in Go that orchestrates a 9-stage pipeline — subdomain enumeration, DNS resolution, HTTP probing, headless browser crawling, port scanning, endpoint discovery, secret analysis, intelligence aggregation, and vulnerability scanning — into a single command.

```
recon0 run target.com
```

### Why recon0?

- **Single binary, zero config** — auto-detects CPU/RAM, resolves tool paths, runs with sane defaults
- **9-stage pipeline** — each stage feeds the next; gate stages halt early on zero results
- **Headless browser crawling** — native Chrome DevTools Protocol via `chromedp`; HAR capture, JS extraction, multi-round click interaction
- **60+ DSL rules** — regex-based secret, token, and cloud asset detection across JS files, HAR bodies, and HTTP headers
- **Tech-aware active probing** — fingerprints the stack (Spring Boot, WordPress, Django, Go, .NET, Laravel, Node.js) then fires targeted probes
- **LLM intelligence** — optional OpenAI/Ollama enrichment: correlates findings, ranks attack paths, filters false positives
- **Resumable** — `--from-stage` picks up where you left off; state persisted to JSON
- **Distributed** — `serve` mode exposes a REST API + persistent job queue for remote scan submission
- **3 dependencies** — `chromedp`, `cdproto`, `yaml.v3` — that's it

---

## Pipeline

```
   Domain
     |
     v
 ┌────────────────────────────────────────────────────────────────────────────┐
 │  1. ENUM           subfinder+amass   Passive subdomain enumeration        │
 │  2. RESOLVE        dnsx          ◄── DNS gate: 0 results = stop          │
 │  3. PROBE          httpx + tlsx      HTTP probing, tech fingerprint, TLS │
 │  4. CRAWL          cdpcrawl          Headless Chrome + HAR + JS capture  │
 │  5. PORTSCAN       naabu             TCP port scanning (optional)        │
 │  6. DISCOVER       discover          Endpoint extraction from HAR/JS     │
 │  7. ANALYZE        analyzer          DSL engine: secrets, tokens, paths  │
 │  8. COLLECT        collector         Intelligence report + LLM analysis  │
 │  9. VULN           nuclei+smartfuzz  Vulnerability scanning + fuzzing    │
 └────────────────────────────────────────────────────────────────────────────┘
     |
     v
  runs/<program>-<timestamp>/
  ├── input/domains.txt
  ├── output/
  │   ├── subdomains.txt       (enum)
  │   ├── alive.txt            (resolve)
  │   ├── live-hosts.txt       (probe — JSON lines: url, status, tech, cdn)
  │   ├── urls.txt             (crawl)
  │   ├── ports.txt            (portscan)
  │   ├── endpoints.json       (discover)
  │   ├── findings.json        (analyze — DSL matches)
  │   ├── intel.json           (collect — full intelligence report)
  │   └── findings.txt         (vuln — nuclei + active probe results)
  ├── har/                     (raw HAR files from crawl)
  ├── js/                      (extracted JS files)
  ├── raw/                     (per-provider raw output)
  ├── logs/pipeline.log
  └── state.json               (execution state — resumable)
```

### Stage Data Flow

| Stage | Input | Output | Gate? |
|-------|-------|--------|-------|
| `enum` | `domains.txt` | `subdomains.txt` | |
| `resolve` | `subdomains.txt` | `alive.txt` | Yes — stops pipeline if 0 alive |
| `probe` | `alive.txt` | `live-hosts.txt` | |
| `crawl` | `live-hosts.txt` | `urls.txt` + `har/` + `js/` | |
| `portscan` | `alive.txt` | `ports.txt` | |
| `discover` | `har/` | `endpoints.json` | |
| `analyze` | `har/` + `js/` | `findings.json` | |
| `collect` | `output/*` | `intel.json` | |
| `vuln` | `live-hosts.txt` | `findings.txt` | |

---

## Installation

### One-liner (recommended)

```bash
curl -sSL https://raw.githubusercontent.com/badchars/recon0/main/install.sh | bash
```

Detects OS/architecture, downloads the latest release, verifies SHA256 checksum, installs to `/usr/local/bin/`.

### Go Install

```bash
go install github.com/badchars/recon0/cmd/recon0@latest
```

### Manual Download

Grab the binary for your platform from [Releases](https://github.com/badchars/recon0/releases):

```bash
curl -sL https://github.com/badchars/recon0/releases/latest/download/recon0-linux-amd64.tar.gz | tar xz
sudo mv recon0 /usr/local/bin/
```

---

## Quick Start

### From Source

```bash
# Build
git clone https://github.com/badchars/recon0.git
cd recon0
make build

# Install external tools (ProjectDiscovery suite)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/owasp-amass/amass/v4/...@master

# Run
./recon0 run target.com
```

### Docker (batteries included)

```bash
docker pull ghcr.io/badchars/recon0:latest

# Basic scan
docker run --rm -v $(pwd)/runs:/data/runs ghcr.io/badchars/recon0 run target.com

# With custom config
docker run --rm \
  -v $(pwd)/runs:/data/runs \
  -v $(pwd)/recon0.yaml:/data/recon0.yaml \
  ghcr.io/badchars/recon0 run target.com --config /data/recon0.yaml
```

The Docker image includes all ProjectDiscovery tools, Chromium, and nuclei templates pre-installed.

### Verify Providers

```bash
$ recon0 providers

  Provider       Stage        Status     Binary
  ──────────────────────────────────────────────────
  amass          enum         enabled    /usr/local/bin/amass
  subfinder      enum         enabled    /usr/local/bin/subfinder
  dnsx           resolve      enabled    /usr/local/bin/dnsx
  httpx          probe        enabled    /usr/local/bin/httpx
  tlsx           probe        enabled    /usr/local/bin/tlsx
  cdpcrawl       crawl        enabled    (built-in)
  naabu          portscan     enabled    /usr/local/bin/naabu
  discover       discover     enabled    (built-in)
  analyzer       analyze      enabled    (built-in)
  collector      collect      enabled    (built-in)
  smartfuzz      vuln         enabled    (built-in)
  nuclei         vuln         disabled   /usr/local/bin/nuclei
```

---

## CLI Reference

```
recon0 — bug bounty recon pipeline

Usage:
  recon0 run <domain|d1,d2,...> [-l file] [flags]   Execute the pipeline
  recon0 serve [flags]              Start API server + job queue worker
  recon0 scan <domain|d1,d2,...> [-l file] [flags] Submit a scan
  recon0 status [RUN_ID] [flags]    Show scan status
  recon0 list                       List all runs
  recon0 providers                  List registered providers
  recon0 update [--check]           Self-update to latest release
  recon0 uninstall [--purge]        Remove recon0 from system
  recon0 version                    Show version
```

### `run` flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--list FILE` | `-l` | | Read domains from a file (one per line) |
| `--program NAME` | `-p` | domain | Group scans under a program name |
| `--config PATH` | `-c` | `recon0.yaml` | Path to config file |
| `--from-stage STAGE` | `-f` | | Resume from a specific stage |

### `serve` flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--config PATH` | `-c` | `recon0.yaml` | Path to config file |
| `--port PORT` | | `8484` | API listen port |

### `scan` flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--list FILE` | `-l` | | Read domains from a file (one per line) |
| `--program NAME` | `-p` | domain | Program name |
| `--remote HOST:PORT` | `-r` | `localhost:8484` | Remote server address |

### `update` flags

| Flag | Default | Description |
|------|---------|-------------|
| `--check` | `false` | Only check for updates, don't install |

### `uninstall` flags

| Flag | Default | Description |
|------|---------|-------------|
| `--purge` | `false` | Also remove all scan data (`runs/`) and config files |

### Examples

```bash
# Basic scan
recon0 run example.com

# Multiple domains (comma-separated)
recon0 run example.com,api.example.com,dev.example.com --program acme

# Multiple domains (from file)
recon0 run -l targets.txt --program acme

# Organize under a bug bounty program
recon0 run example.com --program hackerone-example

# Resume from the analyze stage (reuses previous data)
recon0 run example.com --program hackerone-example --from-stage analyze

# Start the daemon
recon0 serve --port 9090

# Queue a remote scan (multi-domain works here too)
recon0 scan example.com,api.example.com --remote 10.0.0.5:9090

# Check status
recon0 status --remote 10.0.0.5:9090
```

---

## Providers

### External Tools (CLI binaries)

| Provider | Stage | Tool | Purpose |
|----------|-------|------|---------|
| `subfinder` | enum | [subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain enumeration from 100+ sources |
| `amass` | enum | [amass](https://github.com/owasp-amass/amass) | OWASP subdomain enumeration — DNS, scraping, certificates, APIs |
| `dnsx` | resolve | [dnsx](https://github.com/projectdiscovery/dnsx) | DNS resolution, A/AAAA/CNAME records, takeover checks |
| `httpx` | probe | [httpx](https://github.com/projectdiscovery/httpx) | HTTP probing, status codes, tech fingerprinting, CDN detection |
| `tlsx` | probe | [tlsx](https://github.com/projectdiscovery/tlsx) | TLS certificate extraction, SAN enumeration, expiry checks |
| `naabu` | portscan | [naabu](https://github.com/projectdiscovery/naabu) | SYN/CONNECT port scanning, top-N ports |
| `nuclei` | vuln | [nuclei](https://github.com/projectdiscovery/nuclei) | Template-based vulnerability scanning |

### Built-in Providers (no external binary)

| Provider | Stage | Purpose |
|----------|-------|---------|
| `cdpcrawl` | crawl | Headless Chromium crawling via Chrome DevTools Protocol (CDP). Captures full HAR archives, extracts JS files, performs multi-round click-and-navigate interaction. Cookie isolation via browser contexts. |
| `discover` | discover | Parses HAR request logs and JavaScript files to extract API endpoints, HTTP methods, query parameters, and request bodies. Deduplicates by method+URL. |
| `analyzer` | analyze | Runs the DSL rule engine against JS files, HAR bodies, HTTP headers, and discovered endpoints. Detects secrets, tokens, cloud assets, misconfigurations, and interesting paths. |
| `collector` | collect | Aggregates all stage outputs into a structured intelligence report (`intel.json`). Optionally enriches with LLM analysis via OpenAI or Ollama. |
| `smartfuzz` | vuln | Smart fuzzer: universal probes (every host), runtime tech discovery, prefix expansion (`/manage/actuator/env`), discovery-based fuzzing from `endpoints.json`, CDN-aware filtering. |

### Provider Architecture

```go
type Provider interface {
    Name() string
    Stage() string
    OutputType() string                                // "txt", "json", "jsonl"
    Check() error                                      // verify binary exists
    Run(ctx context.Context, opts *RunOpts) (*Result, error)
}
```

Providers register via `init()`. The pipeline queries the registry for each stage, runs enabled providers (sequential or parallel per stage config), merges outputs, applies deduplication, and feeds results to the next stage.

---

## DSL Engine

The built-in DSL engine scans JS files, HAR response bodies, HTTP headers, and discovered endpoints using 60+ regex-based rules with false-positive filtering.

### Rule Categories

| Category | Rules | Severity | Examples |
|----------|-------|----------|---------|
| **Secrets & Tokens** | 20 | Critical/High | AWS keys, GitHub PATs, Slack tokens, Stripe keys, JWTs, private keys |
| **Cloud Assets** | 22 | Medium/Info | S3 buckets, Azure Blob, GCP Storage, Firebase, Cloudflare R2, Supabase |
| **HTTP Headers** | 8 | Low-High | CORS misconfig, missing CSP, server version disclosure, debug headers |
| **Interesting Paths** | 12 | Info-Critical | Admin panels, .env files, .git exposure, Spring Actuator, Go pprof, source maps |
| **Response Content** | 4 | Medium-High | Stack traces, SQL errors, internal IPs |

### Rule Format

Rules are defined in YAML (`internal/dsl/rules/default.yaml`):

```yaml
rules:
  - id: aws-access-key
    name: "AWS Access Key ID"
    severity: critical
    pattern: "(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
    source: [js, har]
    tags: [secret, aws]

  - id: generic-api-key
    name: "Generic API Key"
    severity: medium
    pattern: "(?i)(?:api[_\\-]?key|apikey)[\\s=:\"']+[A-Za-z0-9_\\-]{20,}"
    source: [js, har]
    tags: [secret, generic]
    false_positive: ["(?i)example|placeholder|your[_-]?api|xxx|replace|TODO"]
```

### Custom Rules

Add your own rules via config:

```yaml
providers:
  analyzer:
    enabled: true
    custom_rules: /path/to/my-rules.yaml
```

---

## Smart Fuzzing

The `smartfuzz` provider replaces traditional blind fuzzing with an intelligent, multi-phase approach. It combines universal probes (sent to every host), runtime tech discovery, prefix expansion, and discovery-based fuzzing from pipeline data.

| Tech Stack | Probes | Examples |
|------------|--------|---------|
| **Generic** (all hosts) | `.env`, `.git/HEAD`, `server-status`, `robots.txt`, `.well-known` | Config leak, source code exposure |
| **Spring Boot** | `/actuator/env`, `/actuator/heapdump`, `/actuator/configprops` | Env dump, heap memory, config |
| **WordPress** | `wp-config.php.bak`, `xmlrpc.php`, `wp-json/wp/v2/users` | Backup leak, user enum |
| **Node.js** | `package.json`, `/graphql` introspection | Dependency leak, schema exposure |
| **Laravel/PHP** | `telescope`, `_debugbar`, `phpinfo()` | Debug panels, info disclosure |
| **Django** | `/admin/`, `__debug__/` | Admin panel, debug toolbar |
| **.NET** | `elmah.axd`, `trace.axd`, `web.config` | Error logs, config leak |
| **Go** | `/debug/pprof/`, `/debug/vars` | Profiler, runtime vars |
| **CORS** | Origin reflection test | Misconfigured CORS policies |

---

## LLM Intelligence

The `collector` stage aggregates all pipeline data, cross-correlates findings, and generates structured investigation files for AI agent verification:

1. **IDOR Candidates** — parameterized endpoints with numeric/UUID IDs
2. **SSRF Candidates** — URL-like query parameters (url, redirect, callback, etc.)
3. **Exposed Secrets** — critical secrets correlated with same-file/host findings
4. **Access Control Gaps** — admin/debug paths accessible without auth
5. **Tech-Specific Vulns** — framework-specific findings (Spring Actuator, etc.)
6. **Misconfigurations** — CORS reflection, missing security headers
7. **Information Disclosure** — SQL errors, stack traces, internal IPs
8. **Subdomain Takeover** — dangling CNAME records matching known fingerprints

Output: `investigations.json` (for AI agent) + `intel.json` (summary report)

---

## API

Start the API server with `recon0 serve`. All endpoints return JSON.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |
| `GET` | `/api/status` | Current scan status (or most recent) |
| `GET` | `/api/status/:run_id` | Status by run ID |
| `GET` | `/api/runs` | List all runs with summary |
| `GET` | `/api/logs/:run_id?lines=N` | Tail log file (default: 100 lines) |
| `POST` | `/api/scan` | Queue a new scan |
| `GET` | `/api/queue` | List queued jobs |
| `DELETE` | `/api/queue/:id` | Remove a queued job |

### Queue a Scan

```bash
curl -X POST http://localhost:8484/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"domain": "example.com", "program": "bugbounty-1"}'
```

```json
{
  "queue_id": "a1b2c3d4",
  "position": 1,
  "domain": "example.com",
  "program": "bugbounty-1",
  "status": "pending"
}
```

### Check Status

```bash
curl http://localhost:8484/api/status
```

```json
{
  "job_id": "bugbounty-1-20260306-143022",
  "program": "bugbounty-1",
  "domain": "example.com",
  "status": "running",
  "started_at": "2026-03-06T14:30:22Z",
  "current_stage": "crawl",
  "stages": {
    "enum": {"status": "completed", "results": 247},
    "resolve": {"status": "completed", "results": 189},
    "probe": {"status": "completed", "results": 142},
    "crawl": {"status": "running", "results": 38}
  }
}
```

---

## Configuration

recon0 loads config from (in order): `recon0.yaml` in CWD, `--config` flag, environment variables.

<details>
<summary><strong>Full config reference (click to expand)</strong></summary>

```yaml
# General
output_dir: ./runs              # Scan output directory
resume: true                    # Resume incomplete scans automatically
disk_min_gb: 20                 # Minimum free disk space (GB)
url_cap: 2000000                # Max URLs to process

# Resource management
resources:
  auto: true                    # Auto-detect CPU/RAM (cgroup-aware)
  max_threads: 0                # 0 = auto (based on CPU cores)
  max_rate: 5000                # Global max requests/sec

# Logging
log:
  level: info                   # debug | info | warn | error
  format: color                 # color | json | plain
  file: true                    # Write pipeline.log per run

# Status API + Job Queue
api:
  enabled: true
  port: 8484
  listen: 0.0.0.0              # 127.0.0.1 for local only

# Providers
providers:
  subfinder:
    enabled: true
    timeout: 30                 # Timeout in minutes
    # all: true                 # Use all passive sources
    # recursive: true           # Recursive enumeration

  amass:
    enabled: true
    timeout: 30                 # Timeout in minutes (passive mode)

  dnsx:
    enabled: true
    # retry: 3
    # record_types: [a, aaaa, cname]
    # takeover_check: true

  httpx:
    enabled: true
    ports: [80, 443, 8080, 8443, 8000, 8081, 8888, 3000, 5000, 9090]
    # store_response: true
    # follow_redirect: true

  tlsx:
    enabled: true
    # san: true                 # Extract Subject Alternative Names
    # jarm: true                # JARM fingerprinting

  cdpcrawl:
    enabled: true
    headless: true              # false = visible browser (debug)
    timeout_per_page: 30s
    click_depth: 2              # Rounds of click interaction
    max_concurrent_tabs: 5
    user_agent: "Mozilla/5.0 ..."
    viewport_width: 1920
    viewport_height: 1080

  naabu:
    enabled: true
    top_ports: 100
    # scan_type: s              # SYN scan (needs NET_RAW)

  discover:
    enabled: true               # Endpoint extraction from HAR/JS

  analyzer:
    enabled: true
    # custom_rules: /path/to/rules.yaml

  collector:
    enabled: true               # Investigation generator + intel report

  smartfuzz:
    enabled: true
    timeout: 10s
    max_concurrent: 30
    skip_cors: false            # Skip CORS checks
    cdn_mode: critical_only     # skip | critical_only | full
    prefix_expansion: true      # Path prefix variations
    discovery_fuzz: true        # Fuzz from discovered endpoints
    max_probes_per_host: 100

  nuclei:
    enabled: false              # Enable manually for filtered targets
    severity: [medium, high, critical]
    # custom_templates: ~/nuclei-custom/
    # exclude_tags: [dos, fuzz]
```

</details>

### Environment Variables

| Variable | Description |
|----------|-------------|
| `RECON0_CONFIG` | Config file path |
| `RECON0_OUTPUT` | Output directory override |
| `RECON0_LOG_LEVEL` | Log level (`debug`, `info`, `warn`, `error`) |
| `RECON0_RESUME` | Resume mode (`true`/`false`) |
| `CHROME_PATH` | Chromium binary path override |

---

## Docker

### Build

```bash
make docker-build
```

The multi-stage Dockerfile produces a self-contained image (~1.5 GB) with:
- recon0 binary (statically compiled)
- All ProjectDiscovery tools (subfinder, dnsx, httpx, tlsx, naabu, nuclei)
- Chromium browser + fonts
- Pre-downloaded nuclei templates

### Run as Daemon

```bash
docker run -d \
  --name recon0 \
  -p 8484:8484 \
  -v $(pwd)/runs:/data/runs \
  -v $(pwd)/recon0.yaml:/data/recon0.yaml \
  ghcr.io/badchars/recon0 serve
```

### Port Scanning with SYN

```bash
# naabu SYN scan requires NET_RAW capability
docker run --rm --cap-add NET_RAW \
  -v $(pwd)/runs:/data/runs \
  ghcr.io/badchars/recon0 run target.com
```

---

## Architecture

```
cmd/recon0/main.go         CLI entry — run, serve, scan, status, list, providers
internal/
├── api/api.go             REST API server (health, status, scan, queue, logs)
├── cdp/
│   ├── browser.go         Chrome browser pool (allocate, release, concurrent tabs)
│   ├── har.go             HAR capture (network events → HAR 1.2 format)
│   └── interact.go        Page interaction (click, navigate, scroll, JS collection)
├── config/
│   ├── config.go          YAML config loader + env overrides
│   └── resources.go       CPU/RAM detection (cgroup v1/v2 aware)
├── dsl/
│   ├── engine.go          Rule engine (compile, match, false-positive filter)
│   ├── rules.go           Rule loader (YAML → compiled regex)
│   ├── types.go           Finding, Rule, Match types
│   └── rules/default.yaml 60+ built-in detection rules
├── llm/
│   ├── client.go          OpenAI-compatible chat completion client
│   └── prompt.go          Intelligence analysis prompt + report types
├── log/log.go             Structured logger (color, JSON, plain + file output)
├── merge/merge.go         Result merging + deduplication
├── pipeline/
│   ├── pipeline.go        Orchestrator (stage loop, provider dispatch, progress)
│   ├── stage.go           9-stage definition + input/output routing
│   └── state.go           Execution state (JSON persistence, Query() display)
├── provider/
│   ├── provider.go        Provider interface + registry
│   ├── subfinder.go       Subdomain enumeration
│   ├── amass.go           OWASP Amass passive enumeration
│   ├── dnsx.go            DNS resolution + takeover checks
│   ├── httpx.go           HTTP probing + tech detection
│   ├── tlsx.go            TLS certificate extraction
│   ├── cdpcrawl.go        Headless browser crawling
│   ├── naabu.go           Port scanning
│   ├── nuclei.go          Vulnerability scanning
│   ├── discover.go        Endpoint extraction from HAR/JS
│   ├── analyzer.go        DSL engine wrapper
│   ├── collector.go       Intelligence aggregation + LLM
│   ├── smartfuzz.go       Smart fuzzer (universal probes + tech discovery + CDN-aware)
│   ├── smartfuzz_probes.go  Probe definitions (universal, Spring, WordPress, Go, .NET, ...)
│   └── smartfuzz_discover.go  Discovery-based fuzzing (path siblings, extension swap)
└── queue/queue.go         Persistent job queue (JSON file-backed)
```

---

## Intelligence Report

The `collect` stage produces `intel.json` — a structured intelligence report:

```json
{
  "target": "example.com",
  "generated_at": "2026-03-06T15:42:00Z",
  "subdomain_count": 247,
  "live_host_count": 142,
  "open_port_count": 389,
  "endpoint_count": 1847,
  "hosts": [
    {
      "host": "api.example.com",
      "url": "https://api.example.com",
      "ip": "52.12.34.56",
      "status_code": 200,
      "tech": ["Spring Boot", "Java", "Nginx"],
      "cdn": "",
      "server": "nginx/1.24.0",
      "tls_version": "TLSv1.3",
      "tls_issuer": "Let's Encrypt",
      "ports": [80, 443, 8080]
    }
  ],
  "findings": [
    {
      "rule_id": "aws-access-key",
      "rule_name": "AWS Access Key ID",
      "severity": "critical",
      "value": "AKIA...",
      "source": "js",
      "file": "app.bundle.js"
    }
  ],
  "attack_surface": {
    "api_endpoints": ["/api/v2/users", "/graphql"],
    "admin_panels": ["https://admin.example.com"],
    "exposed_files": ["/.env", "/.git/HEAD"]
  },
  "recommendations": ["..."],
  "llm_analysis": "..."
}
```

---

## Resuming Scans

recon0 supports resuming at any stage. This is useful for:
- Interrupted scans (Ctrl+C, network issues)
- Re-running analysis after adding custom DSL rules
- Skipping expensive stages (crawl, portscan) when only re-analyzing data

```bash
# Initial scan (interrupted at crawl stage)
recon0 run target.com --program myprogram
^C

# Resume from where it stopped
recon0 run target.com --program myprogram

# Or jump to a specific stage
recon0 run target.com --program myprogram --from-stage analyze
```

The `--from-stage` flag reuses the existing run directory, preserving all previously collected data.

---

## Resource Management

recon0 auto-detects system resources and adjusts concurrency:

| Pool | Calculation | Used By |
|------|-------------|---------|
| Full | All CPU cores | httpx, subfinder |
| Heavy | cores / 2 (min 1) | cdpcrawl, naabu |
| Light | cores / 4 (min 1) | nuclei (rate-limited) |

```yaml
resources:
  auto: true           # Reads /proc/cpuinfo, cgroup limits
  max_threads: 0       # 0 = auto, or set explicit cap
  max_rate: 5000       # Global requests/sec ceiling
```

cgroup v1/v2 aware — works correctly inside Docker and Kubernetes.

---

## Updating

```bash
# Check if a new version is available
recon0 update --check

# Download and install the latest release
recon0 update
```

Self-update downloads the correct binary for your OS/architecture from [GitHub Releases](https://github.com/badchars/recon0/releases), verifies the SHA256 checksum, and replaces the current binary atomically.

Supported platforms: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`.

> recon0 automatically checks for new releases in the background on every run. If a newer version is available, a one-line notice is printed to stderr — no delay, no blocking.

> Container environments are detected automatically — use `docker build` to update instead.

---

## Uninstalling

```bash
# Remove the binary
recon0 uninstall

# Remove binary + all scan data and config
recon0 uninstall --purge
```

---

## Releasing

Releases are automated via [GoReleaser](https://goreleaser.com/) and GitHub Actions:

```bash
git tag v0.2.0
git push --tags
# → GitHub Actions builds cross-platform binaries and creates a release
```

---

## Build

```bash
make build              # Build for current platform
make build-linux        # Cross-compile to Linux amd64
make test               # Run tests
make fmt                # Format code
make vet                # Static analysis
make docker-build       # Build Docker image
make docker-push        # Push to GHCR
make clean              # Remove build artifacts
```

---

## License

MIT

---

<p align="center">
  <sub>Built by <a href="https://github.com/badchars">@badchars</a></sub>
</p>
