// Types mirror recon0 Go structs (internal/pipeline/state.go, internal/queue/queue.go).

export type RunStatus =
  | "running"
  | "done"
  | "failed"
  | "cancelled"
  | "gate_failed"
  | "disk_full";

export type StageStatus = "pending" | "running" | "done" | "skipped" | "error";

export type ProviderStatus = "running" | "done" | "skipped" | "error" | "disabled";

export interface ProviderState {
  status: ProviderStatus;
  count: number;
  duration_s: number;
  output_file?: string;
}

export interface StageState {
  status: StageStatus;
  started_at?: string;
  finished_at?: string;
  duration_s?: number;
  providers?: Record<string, ProviderState>;
  stats?: Record<string, number>;
}

export interface ProgressInfo {
  stages_done: number;
  stages_total: number;
  current_provider?: string;
  current_provider_lines?: number;
  current_provider_elapsed_s?: number;
}

export interface StateResources {
  cores: number;
  ram_gb: number;
  threads_full: number;
  threads_heavy: number;
  threads_light: number;
}

export interface StateError {
  time: string;
  stage: string;
  provider: string;
  error: string;
  fatal: boolean;
}

export interface RunState {
  version: number;
  job_id: string;
  program: string;
  domain: string;
  domains?: string[];
  started_at: string;
  finished_at: string | null;
  status: RunStatus;
  current_stage: string;
  config_hash?: string;
  resources?: StateResources;
  progress?: ProgressInfo;
  stages: Record<string, StageState>;
  errors: StateError[];
  summary: Record<string, number>;
}

export interface RunSummary {
  id: string;
  program: string;
  domain: string;
  status: RunStatus;
  started_at: string;
  finished_at?: string;
}

export type JobStatus = "queued" | "running" | "done" | "failed" | "cancelled";

export interface QueueJob {
  id: string;
  domain: string;
  program: string;
  status: JobStatus;
  created_at: string;
  started_at?: string;
  done_at?: string;
  run_id?: string;
  error?: string;
}

export interface QueueState {
  current: QueueJob | null;
  pending: number;
  jobs: QueueJob[];
}

export interface IdleStatus {
  status: "idle";
  message: string;
}

export type StatusResponse = RunState | IdleStatus;

export function isIdle(s: StatusResponse | undefined | null): s is IdleStatus {
  return !!s && (s as IdleStatus).status === "idle";
}

export interface ScanResponse {
  queue_id: string;
  position: number;
  domain: string;
  program: string;
  status: JobStatus;
}

export interface LogsResponse {
  run_id: string;
  lines: string[];
}

// ── Run output types (httpx hosts, findings, investigations, etc.) ──
//
// Keep shapes loose ([key: string]: unknown for unmapped fields) — the
// underlying Go structs evolve faster than these types, and the panel
// only needs the well-known subset for rendering.

export interface TLSInfo {
  tls_version?: string;
  cipher?: string;
  subject_cn?: string;
  subject_dn?: string;
  subject_an?: string[];
  issuer_cn?: string;
  issuer_dn?: string;
  issuer_org?: string[];
  not_before?: string;
  not_after?: string;
  fingerprint_hash?: { sha256?: string; sha1?: string; md5?: string };
}

export interface Host {
  url: string;
  host: string;
  port?: string;
  scheme?: string;
  status_code?: number;
  title?: string;
  tech?: string[];
  webserver?: string;
  cdn?: boolean;
  cdn_name?: string;
  cdn_type?: string;
  content_type?: string;
  content_length?: number;
  http2?: boolean;
  a?: string[];
  cname?: string[];
  tls?: TLSInfo;
  [key: string]: unknown;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  rule_id: string;
  rule_name: string;
  severity: Severity;
  value: string;
  source: string; // js | har | har_headers | endpoints
  file?: string;
  url?: string;
}

export interface Endpoint {
  url: string;
  method: string;
  source: string;
  source_file?: string;
  status_code?: number;
  content_type?: string;
}

export interface SmartfuzzFinding {
  "template-id": string;
  name: string;
  severity: Severity | string;
  host: string;
  "matched-at": string;
  type: string;
  description?: string;
  evidence?: string;
  source?: string;
}

export interface Investigation {
  id: string;
  vuln_type: string;
  confidence: "low" | "medium" | "high";
  severity: Severity;
  title: string;
  description: string;
  found_at?: { source?: string; url?: string };
  evidence?: unknown;
  context?: unknown;
  verify_steps?: unknown;
  question?: string;
}

export interface AttackSurface {
  api_endpoints: string[];
  admin_panels: string[];
  exposed_files: string[];
}

// ── Vulnerabilities (F2/F5/F8) ──

export type SubmissionStatus =
  | "wait"
  | "submitted"
  | "triaged"
  | "na"
  | "duplicate";

export const SUBMISSION_STATUSES: SubmissionStatus[] = [
  "wait",
  "submitted",
  "triaged",
  "na",
  "duplicate",
];

export interface Vulnerability {
  id: string;
  title: string;
  severity: Severity;
  submission_status: SubmissionStatus;
  bounty: number;
  asset: string;
  program?: string;
  description: string;
  references: string[];
  tags: string[];
  source_run_id?: string;
  source_finding_id?: string;
  created_at: string;
  updated_at: string;
  version: number;
}

export interface CreateVulnBody {
  title: string;
  severity: Severity;
  submission_status: SubmissionStatus;
  bounty: number;
  asset: string;
  program?: string;
  description: string;
  references: string[];
  tags: string[];
  source_run_id?: string;
  source_finding_id?: string;
}

export interface UpdateVulnBody extends CreateVulnBody {
  expected_version: number;
}

export interface AttachmentUploadResponse {
  filename: string;
  url: string;
}

// ── Programs (F1) ──

export interface Program {
  name: string;
  description: string;
  vendor: string;
  vendor_link: string;
  scope: string[];
  created_at: string;
  updated_at: string;
  version: number;
}

export interface CreateProgramBody {
  name: string;
  description: string;
  vendor: string;
  vendor_link: string;
  scope: string[];
}

export interface UpdateProgramBody {
  description: string;
  vendor: string;
  vendor_link: string;
  scope: string[];
  expected_version: number;
}

// ── Host annotations (F4) ──

export type ReviewStatus = "not_reviewed" | "reviewing" | "reviewed";

export const REVIEW_STATUSES: ReviewStatus[] = [
  "not_reviewed",
  "reviewing",
  "reviewed",
];

export interface HostAnnotation {
  description: string;
  review_status: ReviewStatus;
  created_at: string;
  updated_at: string;
  version: number;
}

export type HostAnnotationsMap = Record<string, HostAnnotation>;

export interface UpsertAnnotationBody {
  description: string;
  review_status: ReviewStatus;
  expected_version: number;
}

// Pipeline stage order — matches recon0 stage.go Stages slice.
// "permute" is temporarily disabled in the Go pipeline (see stage.go); we
// keep its label for backwards-compat with old state.json files but
// don't list it here, so it doesn't show as a pending stage.
export const STAGE_ORDER = [
  "enum",
  "resolve",
  "probe",
  "crawl",
  "portscan",
  "discover",
  "analyze",
  "vuln",
  "collect",
] as const;

export type StageName = (typeof STAGE_ORDER)[number];

export const STAGE_LABEL: Record<string, string> = {
  enum: "Enum",
  resolve: "Resolve",
  permute: "Permute",
  probe: "Probe",
  crawl: "Crawl",
  portscan: "Port Scan",
  discover: "Discover",
  analyze: "Analyze",
  vuln: "Vuln",
  collect: "Collect",
};
