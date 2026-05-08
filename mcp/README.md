# recon0 MCP Server

An [MCP](https://modelcontextprotocol.io) server that exposes the recon0 REST API as tools for Claude. Use it to manage bug bounty programs, queue scans, and read results — directly from a conversation.

## Requirements

- Node.js 20+
- A running recon0 instance (`recon0 serve`)

## Installation

```bash
cd mcp
npm install
npm run build
```

## Configuration

### Claude Code (recommended)

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "recon0": {
      "command": "node",
      "args": ["/absolute/path/to/recon0/mcp/dist/index.js"],
      "env": {
        "RECON0_URL": "http://localhost:8484"
      }
    }
  }
}
```

Restart Claude Code after saving. Run `/mcp` to verify the server is connected.

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "recon0": {
      "command": "node",
      "args": ["/absolute/path/to/recon0/mcp/dist/index.js"],
      "env": {
        "RECON0_URL": "http://your-recon0-host:8484"
      }
    }
  }
}
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `RECON0_URL` | `http://localhost:8484` | Base URL of the recon0 API |

## Available tools

### Programs

| Tool | Description |
|---|---|
| `list_programs` | List all bug bounty programs |
| `get_program` | Get a program by slug |
| `create_program` | Create a new program with scope |
| `update_program` | Update description, vendor, or scope |
| `delete_program` | Delete a program (runs/vulns are kept) |

### Scanning

| Tool | Description |
|---|---|
| `queue_scan` | Queue a recon scan for a program |
| `get_queue` | Get current queue state |
| `cancel_queued_job` | Remove a pending job from the queue |

#### Wildcard vs fixed hosts

`queue_scan` accepts two buckets:

- **`wildcards`** — apex domains. subfinder + amass enumerate subdomains from these. Example: `["example.com", "target.io"]`
- **`fixed_hosts`** — exact hostnames probed directly, skipping subdomain enum. Example: `["admin.example.com", "vpn.target.io"]`

### Runs

| Tool | Description |
|---|---|
| `list_runs` | List all runs (completed + in-progress) |
| `get_run_status` | Detailed stage/provider progress for a run |
| `get_run_logs` | Last N log lines from a run |

### Run results

| Tool | Description |
|---|---|
| `get_run_hosts` | Live HTTP/HTTPS hosts (title, tech, TLS, CDN, IPs) |
| `get_run_findings` | Secret/sensitive-data findings from JS + HAR |
| `get_run_endpoints` | Crawled API endpoints with method + source |
| `get_run_investigations` | AI-generated vulnerability investigations |
| `get_run_attack_surface` | Summarised attack surface (admin panels, APIs, files) |

### Vulnerabilities

| Tool | Description |
|---|---|
| `list_vulnerabilities` | List all tracked vulnerabilities |
| `get_vulnerability` | Get a vulnerability by UUID |
| `create_vulnerability` | Create a new vuln record |
| `update_vulnerability` | Update an existing vuln |
| `delete_vulnerability` | Delete a vuln permanently |

### Host annotations

| Tool | Description |
|---|---|
| `list_host_annotations` | Get all host review annotations |
| `upsert_host_annotation` | Create or update a host annotation |

## Example usage

```
List all programs, then queue a scan for legalzoom with wildcards
legalzoom.com and legalinc.com, and admin.legalzoom.com as a fixed host.
```

```
Show me the investigations from the latest legalzoom run and create
vulnerability records for any high or critical findings.
```

```
Mark all hosts from run legalzoom-20260505-170242 that return 200
as 'reviewing' in host annotations.
```

## Development

Run directly without building (uses `tsx`):

```bash
npm run dev
```

Rebuild after editing `src/index.ts`:

```bash
npm run build
```
