/**
 * recon0 MCP Server
 *
 * Exposes the recon0 REST API as MCP tools so Claude can:
 *   - manage bug bounty programs and their scope
 *   - queue and monitor recon scans
 *   - read scan results (hosts, findings, investigations)
 *   - manage discovered vulnerabilities
 *
 * Configure the recon0 instance URL via RECON0_URL env var
 * (default: http://localhost:8484).
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// ── HTTP client ────────────────────────────────────────────────────────────────

const BASE_URL = (process.env.RECON0_URL ?? "http://localhost:8484").replace(
  /\/+$/,
  "",
);

class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(`HTTP ${status}: ${message}`);
    this.name = "ApiError";
  }
}

async function api<T>(
  path: string,
  init?: RequestInit & { json?: unknown },
): Promise<T> {
  const { json, ...rest } = init ?? {};
  const res = await fetch(`${BASE_URL}${path}`, {
    ...rest,
    headers: {
      "Content-Type": "application/json",
      ...(rest.headers ?? {}),
    },
    body: json !== undefined ? JSON.stringify(json) : rest.body,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new ApiError(res.status, text || res.statusText);
  }
  return res.json() as Promise<T>;
}

// ── Server setup ──────────────────────────────────────────────────────────────

const server = new McpServer({
  name: "recon0",
  version: "1.0.0",
});

// ── Programs ──────────────────────────────────────────────────────────────────

server.tool(
  "list_programs",
  "List all bug bounty programs stored in recon0. Returns name, vendor, scope (in-scope hostnames), and run/vuln stats.",
  {},
  async () => {
    const data = await api<unknown[]>("/api/programs");
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

server.tool(
  "get_program",
  "Get a single bug bounty program by its slug name. Returns full details including scope, vendor link, description, and version.",
  { name: z.string().describe("Program slug (e.g. 'legalzoom')") },
  async ({ name }) => {
    const data = await api<unknown>(`/api/programs/${encodeURIComponent(name)}`);
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

server.tool(
  "create_program",
  "Create a new bug bounty program. Scope entries can be wildcards (*.example.com) or fixed hostnames (admin.example.com).",
  {
    name: z
      .string()
      .describe("Unique slug — lowercase letters, digits, hyphens only"),
    description: z.string().describe("Short description of the program"),
    vendor: z
      .string()
      .describe(
        "Bug bounty platform (e.g. hackerone, bugcrowd, intigriti, private)",
      ),
    vendor_link: z.string().describe("URL to the program page on the platform"),
    scope: z
      .array(z.string())
      .describe(
        "In-scope hostnames. Use *.example.com for wildcard subdomain enumeration or example.com for a fixed host.",
      ),
  },
  async (args) => {
    const data = await api<unknown>("/api/programs", {
      method: "POST",
      json: args,
    });
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

server.tool(
  "update_program",
  "Update an existing program's description, vendor info, or scope. Requires the current version number to prevent conflicts.",
  {
    name: z.string().describe("Program slug to update"),
    description: z.string().describe("Updated description"),
    vendor: z.string().describe("Updated vendor/platform name"),
    vendor_link: z.string().describe("Updated vendor URL"),
    scope: z
      .array(z.string())
      .describe("Updated scope list (replaces existing scope)"),
    expected_version: z
      .number()
      .int()
      .describe(
        "Current version number from get_program — used for optimistic locking",
      ),
  },
  async ({ name, ...body }) => {
    const data = await api<unknown>(
      `/api/programs/${encodeURIComponent(name)}`,
      { method: "PUT", json: body },
    );
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

server.tool(
  "delete_program",
  "Delete a bug bounty program by slug. This does NOT delete associated runs or vulnerabilities.",
  { name: z.string().describe("Program slug to delete") },
  async ({ name }) => {
    const data = await api<unknown>(
      `/api/programs/${encodeURIComponent(name)}`,
      { method: "DELETE" },
    );
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

// ── Scan / Queue ───────────────────────────────────────────────────────────────

server.tool(
  "queue_scan",
  `Queue a recon scan for a program's assets. Hosts are split into two buckets:
- wildcards: apex domains to enumerate subdomains from (subfinder / amass will run). Example: ["example.com", "target.io"]
- fixed_hosts: exact hostnames to probe directly, skipping subdomain enumeration. Example: ["admin.example.com", "vpn.target.io"]

At least one host in either bucket is required. The scan runs asynchronously; use get_queue or get_run_status to track progress.`,
  {
    program: z.string().describe("Program slug this scan belongs to"),
    wildcards: z
      .array(z.string())
      .default([])
      .describe(
        "Apex domains for subdomain enumeration (no *.  prefix needed here)",
      ),
    fixed_hosts: z
      .array(z.string())
      .default([])
      .describe("Exact hostnames to probe without subdomain enumeration"),
  },
  async (args) => {
    const data = await api<unknown>("/api/scan", {
      method: "POST",
      json: args,
    });
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

server.tool(
  "get_queue",
  "Get the current scan queue. Shows the actively running job and count of pending jobs, plus full job list with statuses.",
  {},
  async () => {
    const data = await api<unknown>("/api/queue");
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

server.tool(
  "cancel_queued_job",
  "Remove a pending job from the scan queue. Cannot cancel a job that is already running.",
  { job_id: z.string().describe("Queue job ID to remove (from get_queue)") },
  async ({ job_id }) => {
    const data = await api<unknown>(
      `/api/queue/${encodeURIComponent(job_id)}`,
      { method: "DELETE" },
    );
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

// ── Runs ──────────────────────────────────────────────────────────────────────

server.tool(
  "list_runs",
  "List all completed and in-progress scan runs. Returns run ID, program, domain, status, and timestamps. Use the run ID with other tools to read results.",
  {},
  async () => {
    const data = await api<unknown>("/api/runs");
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

server.tool(
  "get_run_status",
  "Get detailed status for a specific run: current stage, per-stage and per-provider progress, resource usage, errors, and summary counts.",
  { run_id: z.string().describe("Run ID (from list_runs or queue_scan)") },
  async ({ run_id }) => {
    const data = await api<unknown>(
      `/api/status/${encodeURIComponent(run_id)}`,
    );
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

server.tool(
  "get_run_logs",
  "Stream the last N log lines from a run. Useful for debugging stuck or failed stages.",
  {
    run_id: z.string().describe("Run ID"),
    lines: z
      .number()
      .int()
      .min(1)
      .max(2000)
      .default(200)
      .describe("Number of log lines to return (default 200, max 2000)"),
  },
  async ({ run_id, lines }) => {
    const data = await api<unknown>(
      `/api/logs/${encodeURIComponent(run_id)}?lines=${lines}`,
    );
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

// ── Run results ───────────────────────────────────────────────────────────────

server.tool(
  "get_run_hosts",
  "Get all live HTTP/HTTPS hosts discovered in a run. Each entry includes URL, status code, page title, tech stack, CDN info, TLS details, and IP addresses.",
  { run_id: z.string().describe("Run ID") },
  async ({ run_id }) => {
    const data = await api<unknown>(
      `/api/runs/${encodeURIComponent(run_id)}/hosts`,
    );
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

server.tool(
  "get_run_findings",
  "Get secret / sensitive-data findings from a run (JS files, HAR, response headers). Each finding has a rule ID, severity, and matched value.",
  { run_id: z.string().describe("Run ID") },
  async ({ run_id }) => {
    const data = await api<unknown>(
      `/api/runs/${encodeURIComponent(run_id)}/findings`,
    );
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

server.tool(
  "get_run_endpoints",
  "Get crawled API endpoints from a run. Each entry includes URL, HTTP method, source (JS/crawl/HAR), status code, and content type.",
  { run_id: z.string().describe("Run ID") },
  async ({ run_id }) => {
    const data = await api<unknown>(
      `/api/runs/${encodeURIComponent(run_id)}/endpoints`,
    );
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

server.tool(
  "get_run_investigations",
  "Get AI-generated vulnerability investigations from a run. Each investigation has a type, confidence, severity, title, description, evidence, and suggested verify steps.",
  { run_id: z.string().describe("Run ID") },
  async ({ run_id }) => {
    const data = await api<unknown>(
      `/api/runs/${encodeURIComponent(run_id)}/investigations`,
    );
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

server.tool(
  "get_run_attack_surface",
  "Get the summarised attack surface for a run: exposed API endpoints, admin panels, and sensitive files found during discovery.",
  { run_id: z.string().describe("Run ID") },
  async ({ run_id }) => {
    const data = await api<unknown>(
      `/api/runs/${encodeURIComponent(run_id)}/attack-surface`,
    );
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

// ── Vulnerabilities ───────────────────────────────────────────────────────────

server.tool(
  "list_vulnerabilities",
  "List all tracked vulnerabilities across all programs. Returns title, severity, submission status, bounty amount, asset, and program.",
  {},
  async () => {
    const data = await api<unknown>("/api/vulnerabilities");
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

server.tool(
  "get_vulnerability",
  "Get full details for a single vulnerability including description, references, tags, and source run/finding.",
  { id: z.string().describe("Vulnerability UUID") },
  async ({ id }) => {
    const data = await api<unknown>(
      `/api/vulnerabilities/${encodeURIComponent(id)}`,
    );
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

server.tool(
  "create_vulnerability",
  `Create a new vulnerability record. Use this when a finding from a run has been triaged and confirmed.

Severity: critical | high | medium | low | info
Submission status: wait | submitted | triaged | na | duplicate`,
  {
    title: z.string().describe("Short descriptive title"),
    severity: z
      .enum(["critical", "high", "medium", "low", "info"])
      .describe("CVSS-style severity"),
    submission_status: z
      .enum(["wait", "submitted", "triaged", "na", "duplicate"])
      .describe("Current status in the bounty submission lifecycle"),
    bounty: z
      .number()
      .min(0)
      .default(0)
      .describe("Bounty amount in USD (0 if not yet paid)"),
    asset: z.string().describe("Affected asset URL or hostname"),
    program: z
      .string()
      .optional()
      .describe("Program slug this vuln belongs to"),
    description: z.string().describe("Full description of the vulnerability"),
    references: z
      .array(z.string())
      .default([])
      .describe("URLs to relevant CVEs, write-ups, or proof-of-concept"),
    tags: z.array(z.string()).default([]).describe("Freeform tags"),
    source_run_id: z
      .string()
      .optional()
      .describe("Run ID where this was discovered"),
    source_finding_id: z
      .string()
      .optional()
      .describe("Finding ID from get_run_findings"),
  },
  async (args) => {
    const data = await api<unknown>("/api/vulnerabilities", {
      method: "POST",
      json: args,
    });
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

server.tool(
  "update_vulnerability",
  "Update an existing vulnerability. Requires the current version number for optimistic locking.",
  {
    id: z.string().describe("Vulnerability UUID"),
    title: z.string().describe("Updated title"),
    severity: z.enum(["critical", "high", "medium", "low", "info"]),
    submission_status: z.enum([
      "wait",
      "submitted",
      "triaged",
      "na",
      "duplicate",
    ]),
    bounty: z.number().min(0),
    asset: z.string(),
    program: z.string().optional(),
    description: z.string(),
    references: z.array(z.string()).default([]),
    tags: z.array(z.string()).default([]),
    source_run_id: z.string().optional(),
    source_finding_id: z.string().optional(),
    expected_version: z
      .number()
      .int()
      .describe("Current version from get_vulnerability"),
  },
  async ({ id, ...body }) => {
    const data = await api<unknown>(
      `/api/vulnerabilities/${encodeURIComponent(id)}`,
      { method: "PUT", json: body },
    );
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

server.tool(
  "delete_vulnerability",
  "Permanently delete a vulnerability record.",
  { id: z.string().describe("Vulnerability UUID to delete") },
  async ({ id }) => {
    const data = await api<unknown>(
      `/api/vulnerabilities/${encodeURIComponent(id)}`,
      { method: "DELETE" },
    );
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

// ── Host annotations ──────────────────────────────────────────────────────────

server.tool(
  "list_host_annotations",
  "Get all manual host annotations. Annotations track review status and notes for individual hosts discovered during scans.",
  {},
  async () => {
    const data = await api<unknown>("/api/host-annotations");
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

server.tool(
  "upsert_host_annotation",
  `Create or update a review annotation for a specific host.

Review status: not_reviewed | reviewing | reviewed`,
  {
    hostname: z
      .string()
      .describe("Hostname to annotate (e.g. admin.example.com)"),
    description: z
      .string()
      .describe("Notes about this host — findings, context, next steps"),
    review_status: z
      .enum(["not_reviewed", "reviewing", "reviewed"])
      .describe("Current review state"),
    expected_version: z
      .number()
      .int()
      .describe("Use 0 when creating; use current version when updating"),
  },
  async ({ hostname, ...body }) => {
    const data = await api<unknown>(
      `/api/host-annotations/${encodeURIComponent(hostname)}`,
      { method: "PUT", json: body },
    );
    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  },
);

// ── Transport ─────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);
