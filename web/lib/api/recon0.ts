// recon0 REST client. All functions are async and use the configured
// instance URL. The URL is read at call time so settings changes take
// effect immediately. Errors throw — callers catch via TanStack Query.

import type {
  AttachmentUploadResponse,
  AttackSurface,
  CreateProgramBody,
  CreateVulnBody,
  Endpoint,
  Finding,
  Host,
  HostAnnotation,
  HostAnnotationsMap,
  Investigation,
  LogsResponse,
  Program,
  QueueState,
  RunSummary,
  ScanResponse,
  SmartfuzzFinding,
  StatusResponse,
  UpdateProgramBody,
  UpdateVulnBody,
  UpsertAnnotationBody,
  Vulnerability,
} from "./types";

const DEFAULT_BASE_URL =
  process.env.NEXT_PUBLIC_RECON0_URL ?? "http://localhost:8484";

let baseUrl = DEFAULT_BASE_URL;

export function setBaseUrl(url: string) {
  baseUrl = url.replace(/\/+$/, "");
}

export function getBaseUrl(): string {
  return baseUrl;
}

class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${baseUrl}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    cache: "no-store",
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new ApiError(res.status, text || res.statusText);
  }
  return (await res.json()) as T;
}

export const recon0 = {
  health: () => request<{ ok: boolean }>("/api/health"),

  status: () => request<StatusResponse>("/api/status"),

  runStatus: (runId: string) =>
    request<StatusResponse>(`/api/status/${encodeURIComponent(runId)}`),

  runs: () => request<RunSummary[] | null>("/api/runs"),

  logs: (runId: string, lines = 200) =>
    request<LogsResponse>(
      `/api/logs/${encodeURIComponent(runId)}?lines=${lines}`,
    ),

  queue: () => request<QueueState>("/api/queue"),

  scan: (body: { domain: string; program?: string }) =>
    request<ScanResponse>("/api/scan", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  removeQueued: (id: string) =>
    request<{ removed: string }>(`/api/queue/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),

  // ── Run sub-resources (F3) ──
  runHosts: (runId: string) =>
    request<Host[]>(`/api/runs/${encodeURIComponent(runId)}/hosts`),

  runFindings: (runId: string) =>
    request<Finding[]>(`/api/runs/${encodeURIComponent(runId)}/findings`),

  runEndpoints: (runId: string) =>
    request<Endpoint[]>(`/api/runs/${encodeURIComponent(runId)}/endpoints`),

  runSmartfuzz: (runId: string) =>
    request<SmartfuzzFinding[]>(
      `/api/runs/${encodeURIComponent(runId)}/smartfuzz`,
    ),

  runInvestigations: (runId: string) =>
    request<Investigation[] | null>(
      `/api/runs/${encodeURIComponent(runId)}/investigations`,
    ),

  runAttackSurface: (runId: string) =>
    request<AttackSurface | null>(
      `/api/runs/${encodeURIComponent(runId)}/attack-surface`,
    ),

  // ── Host annotations (F4) ──
  hostAnnotations: () => request<HostAnnotationsMap>(`/api/host-annotations`),

  upsertHostAnnotation: (hostname: string, body: UpsertAnnotationBody) =>
    request<HostAnnotation>(
      `/api/host-annotations/${encodeURIComponent(hostname)}`,
      { method: "PUT", body: JSON.stringify(body) },
    ),

  deleteHostAnnotation: (hostname: string) =>
    request<{ removed: string }>(
      `/api/host-annotations/${encodeURIComponent(hostname)}`,
      { method: "DELETE" },
    ),

  // ── Programs (F1) ──
  programs: () => request<Program[]>(`/api/programs`),

  program: (name: string) =>
    request<Program>(`/api/programs/${encodeURIComponent(name)}`),

  createProgram: (body: CreateProgramBody) =>
    request<Program>(`/api/programs`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  updateProgram: (name: string, body: UpdateProgramBody) =>
    request<Program>(`/api/programs/${encodeURIComponent(name)}`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),

  deleteProgram: (name: string) =>
    request<{ removed: string }>(
      `/api/programs/${encodeURIComponent(name)}`,
      { method: "DELETE" },
    ),

  // ── Vulnerabilities (F2/F5) ──
  vulnerabilities: () => request<Vulnerability[]>(`/api/vulnerabilities`),

  vulnerability: (id: string) =>
    request<Vulnerability>(`/api/vulnerabilities/${encodeURIComponent(id)}`),

  createVuln: (body: CreateVulnBody) =>
    request<Vulnerability>(`/api/vulnerabilities`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  updateVuln: (id: string, body: UpdateVulnBody) =>
    request<Vulnerability>(`/api/vulnerabilities/${encodeURIComponent(id)}`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),

  deleteVuln: (id: string) =>
    request<{ removed: string }>(
      `/api/vulnerabilities/${encodeURIComponent(id)}`,
      { method: "DELETE" },
    ),

  // ── Vuln attachments (F8) ──
  // FormData uploads — bypass the JSON content-type set by `request`.
  uploadVulnAttachment: async (
    vulnID: string,
    file: File | Blob,
    filename?: string,
  ): Promise<AttachmentUploadResponse> => {
    const fd = new FormData();
    fd.append("file", file, filename ?? (file as File).name ?? "upload.png");
    const res = await fetch(
      `${baseUrl}/api/vulnerabilities/${encodeURIComponent(vulnID)}/attachments`,
      { method: "POST", body: fd, cache: "no-store" },
    );
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new ApiError(res.status, text || res.statusText);
    }
    return res.json();
  },

  deleteVulnAttachment: (vulnID: string, filename: string) =>
    request<{ removed: string }>(
      `/api/vulnerabilities/${encodeURIComponent(vulnID)}/attachments/${encodeURIComponent(filename)}`,
      { method: "DELETE" },
    ),
};

export { ApiError };
