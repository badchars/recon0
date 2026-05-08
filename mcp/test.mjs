/**
 * MCP server smoke test — spawns the server and calls every tool via JSON-RPC.
 * Usage: RECON0_URL=http://localhost:8484 node test.mjs
 */
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

const BASE = process.env.RECON0_URL ?? "http://localhost:8484";
let id = 0;
let proc;

// ── transport helpers ─────────────────────────────────────────────────────────

const pending = new Map();

function send(method, params = {}) {
  const msgId = ++id;
  return new Promise((resolve, reject) => {
    pending.set(msgId, { resolve, reject });
    const msg = JSON.stringify({ jsonrpc: "2.0", id: msgId, method, params });
    proc.stdin.write(msg + "\n");
  });
}

function callTool(name, args = {}) {
  return send("tools/call", { name, arguments: args });
}

// ── output ────────────────────────────────────────────────────────────────────

const OK   = "\x1b[32m✓\x1b[0m";
const FAIL = "\x1b[31m✗\x1b[0m";
const DIM  = "\x1b[2m";
const RST  = "\x1b[0m";

let passed = 0, failed = 0;

function result(name, ok, detail) {
  if (ok) { passed++; console.log(`${OK} ${name}`); }
  else     { failed++; console.log(`${FAIL} ${name}\n  ${DIM}${detail}${RST}`); }
}

// ── tests ─────────────────────────────────────────────────────────────────────

async function run() {
  // 1 – Initialize
  const init = await send("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "smoke-test", version: "0" },
  });
  result("initialize", init.result?.serverInfo?.name === "recon0", JSON.stringify(init));

  // 2 – List tools
  const toolsList = await send("tools/list");
  const tools = toolsList.result?.tools ?? [];
  result(`tools/list — ${tools.length} tools`, tools.length > 0, JSON.stringify(toolsList));

  // verify every expected tool is registered
  const expected = [
    "list_programs","get_program","create_program","update_program","delete_program",
    "queue_scan","get_queue","cancel_queued_job",
    "list_runs","get_run_status","get_run_logs",
    "get_run_hosts","get_run_findings","get_run_endpoints","get_run_investigations","get_run_attack_surface",
    "list_vulnerabilities","get_vulnerability","create_vulnerability","update_vulnerability","delete_vulnerability",
    "list_host_annotations","upsert_host_annotation",
  ];
  const names = tools.map(t => t.name);
  for (const t of expected) {
    result(`  tool registered: ${t}`, names.includes(t), `missing from tools/list`);
  }

  // ── programs ────────────────────────────────────────────────────────────────

  let programName;
  {
    const r = await callTool("create_program", {
      name: "mcp-test-prog",
      description: "Created by MCP smoke test",
      vendor: "private",
      vendor_link: "https://example.com",
      scope: ["*.mcp-test.local", "admin.mcp-test.local"],
    });
    const ok = !r.result?.isError;
    result("create_program", ok, JSON.stringify(r));
    if (ok) programName = "mcp-test-prog";
  }

  {
    const r = await callTool("list_programs");
    const text = r.result?.content?.[0]?.text ?? "[]";
    const arr = JSON.parse(text);
    result("list_programs", Array.isArray(arr), text);
  }

  if (programName) {
    const r = await callTool("get_program", { name: programName });
    const ok = !r.result?.isError;
    result("get_program", ok, JSON.stringify(r));
  }

  let progVersion = 1;
  if (programName) {
    const r = await callTool("update_program", {
      name: programName,
      description: "Updated by MCP smoke test",
      vendor: "private",
      vendor_link: "https://example.com",
      scope: ["*.mcp-test.local"],
      expected_version: 1,
    });
    const ok = !r.result?.isError;
    if (ok) progVersion = 2;
    result("update_program", ok, JSON.stringify(r));
  }

  // ── scan / queue ─────────────────────────────────────────────────────────────

  {
    const r = await callTool("get_queue");
    result("get_queue", !r.result?.isError, JSON.stringify(r));
  }

  // skip actually queuing to avoid kicking off a real scan during testing

  // ── runs ─────────────────────────────────────────────────────────────────────

  let firstRunId;
  {
    const r = await callTool("list_runs");
    const text = r.result?.content?.[0]?.text ?? "[]";
    const arr = JSON.parse(text);
    const ok = Array.isArray(arr);
    result("list_runs", ok, text.slice(0, 200));
    if (ok && arr.length > 0) firstRunId = arr[0].id;
  }

  if (firstRunId) {
    for (const tool of [
      "get_run_status", "get_run_logs",
      "get_run_hosts", "get_run_findings", "get_run_endpoints",
      "get_run_investigations", "get_run_attack_surface",
    ]) {
      const args = tool === "get_run_logs"
        ? { run_id: firstRunId, lines: 10 }
        : { run_id: firstRunId };
      const r = await callTool(tool, args);
      result(tool, !r.result?.isError, JSON.stringify(r).slice(0, 200));
    }
  } else {
    console.log(`${DIM}  (skipping run-result tools — no runs found)${RST}`);
  }

  // ── vulnerabilities ──────────────────────────────────────────────────────────

  let vulnId;
  {
    const r = await callTool("create_vulnerability", {
      title: "MCP smoke test vuln",
      severity: "info",
      submission_status: "wait",
      bounty: 0,
      asset: "smoke.mcp-test.local",
      program: programName,
      description: "Created by automated MCP smoke test",
      references: [],
      tags: ["smoke-test"],
    });
    const ok = !r.result?.isError;
    result("create_vulnerability", ok, JSON.stringify(r).slice(0, 300));
    if (ok) {
      const text = r.result?.content?.[0]?.text ?? "{}";
      vulnId = JSON.parse(text).id;
    }
  }

  {
    const r = await callTool("list_vulnerabilities");
    result("list_vulnerabilities", !r.result?.isError, JSON.stringify(r).slice(0, 200));
  }

  if (vulnId) {
    {
      const r = await callTool("get_vulnerability", { id: vulnId });
      result("get_vulnerability", !r.result?.isError, JSON.stringify(r).slice(0, 200));
    }
    {
      const r = await callTool("update_vulnerability", {
        id: vulnId,
        title: "MCP smoke test vuln (updated)",
        severity: "info",
        submission_status: "na",
        bounty: 0,
        asset: "smoke.mcp-test.local",
        program: programName,
        description: "Updated by MCP smoke test",
        references: [],
        tags: ["smoke-test"],
        expected_version: 1,
      });
      result("update_vulnerability", !r.result?.isError, JSON.stringify(r).slice(0, 200));
    }
    {
      const r = await callTool("delete_vulnerability", { id: vulnId });
      result("delete_vulnerability", !r.result?.isError, JSON.stringify(r).slice(0, 200));
    }
  }

  // ── host annotations ──────────────────────────────────────────────────────────

  {
    const r = await callTool("list_host_annotations");
    result("list_host_annotations", !r.result?.isError, JSON.stringify(r).slice(0, 200));
  }

  {
    const r = await callTool("upsert_host_annotation", {
      hostname: "smoke.mcp-test.local",
      description: "Created by MCP smoke test",
      review_status: "reviewing",
      expected_version: 0,
    });
    result("upsert_host_annotation", !r.result?.isError, JSON.stringify(r).slice(0, 200));
  }

  // ── cleanup ───────────────────────────────────────────────────────────────────

  if (programName) {
    const r = await callTool("delete_program", { name: programName });
    result("delete_program (cleanup)", !r.result?.isError, JSON.stringify(r));
  }

  // ── summary ───────────────────────────────────────────────────────────────────
  console.log(`\n${passed + failed} tests — \x1b[32m${passed} passed\x1b[0m, \x1b[31m${failed} failed\x1b[0m`);
  proc.stdin.end();
  process.exit(failed > 0 ? 1 : 0);
}

// ── spawn server + wire up stdio ──────────────────────────────────────────────

proc = spawn("node", ["dist/index.js"], {
  env: { ...process.env, RECON0_URL: BASE },
  stdio: ["pipe", "pipe", "inherit"],
});

const rl = createInterface({ input: proc.stdout });
rl.on("line", (line) => {
  try {
    const msg = JSON.parse(line);
    if (msg.id != null && pending.has(msg.id)) {
      const { resolve } = pending.get(msg.id);
      pending.delete(msg.id);
      resolve(msg);
    }
  } catch {
    // not a JSON-RPC message, ignore
  }
});

proc.on("exit", (code) => {
  if (pending.size > 0) {
    console.error("Server exited with pending requests");
    process.exit(1);
  }
});

run().catch((err) => {
  console.error(err);
  proc.stdin.end();
  process.exit(1);
});
