"use client";

import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { recon0 } from "./recon0";
import { isIdle, type RunSummary, type StatusResponse } from "./types";

const POLL_FAST = 2000;
const POLL_SLOW = 10000;

export function useHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: () => recon0.health(),
    refetchInterval: POLL_SLOW,
    retry: false,
  });
}

export function useQueue() {
  return useQuery({
    queryKey: ["queue"],
    queryFn: () => recon0.queue(),
    refetchInterval: (q) => {
      const data = q.state.data;
      return data?.current ? POLL_FAST : POLL_SLOW;
    },
  });
}

export function useStatus(opts?: { enabled?: boolean }) {
  return useQuery<StatusResponse>({
    queryKey: ["status"],
    queryFn: () => recon0.status(),
    refetchInterval: (q) => {
      const data = q.state.data;
      if (!data || isIdle(data)) return POLL_SLOW;
      return data.status === "running" ? POLL_FAST : false;
    },
    enabled: opts?.enabled ?? true,
  });
}

export function useRunStatus(runId: string | undefined) {
  return useQuery<StatusResponse>({
    queryKey: ["runStatus", runId],
    queryFn: () => recon0.runStatus(runId!),
    enabled: !!runId,
    refetchInterval: (q) => {
      const data = q.state.data;
      if (!data || isIdle(data)) return false;
      return data.status === "running" ? POLL_FAST : false;
    },
  });
}

export function useRuns() {
  return useQuery<RunSummary[]>({
    queryKey: ["runs"],
    queryFn: async () => (await recon0.runs()) ?? [],
    refetchInterval: POLL_SLOW,
  });
}

export function useLogs(runId: string | undefined, lines = 200) {
  return useQuery({
    queryKey: ["logs", runId, lines],
    queryFn: () => recon0.logs(runId!, lines),
    enabled: !!runId,
    refetchInterval: POLL_FAST,
  });
}

export function useCreateRun() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { domain: string; program?: string }) =>
      recon0.scan(body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["queue"] });
      qc.invalidateQueries({ queryKey: ["runs"] });
    },
  });
}

export function useRemoveQueued() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => recon0.removeQueued(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["queue"] });
    },
  });
}

// ── Run output hooks (F3) ──
//
// These responses can be megabytes (investigations ~1.6MB) so we keep them
// in cache aggressively (staleTime infinity-ish) and let the user
// re-fetch via refetch() if they want fresh data.

const FIVE_MIN = 5 * 60 * 1000;

export function useRunHosts(runId: string | undefined) {
  return useQuery({
    queryKey: ["runHosts", runId],
    queryFn: () => recon0.runHosts(runId!),
    enabled: !!runId,
    staleTime: FIVE_MIN,
  });
}

export function useRunFindings(runId: string | undefined) {
  return useQuery({
    queryKey: ["runFindings", runId],
    queryFn: () => recon0.runFindings(runId!),
    enabled: !!runId,
    staleTime: FIVE_MIN,
  });
}

export function useRunEndpoints(runId: string | undefined) {
  return useQuery({
    queryKey: ["runEndpoints", runId],
    queryFn: () => recon0.runEndpoints(runId!),
    enabled: !!runId,
    staleTime: FIVE_MIN,
  });
}

export function useRunSmartfuzz(runId: string | undefined) {
  return useQuery({
    queryKey: ["runSmartfuzz", runId],
    queryFn: () => recon0.runSmartfuzz(runId!),
    enabled: !!runId,
    staleTime: FIVE_MIN,
  });
}

export function useRunInvestigations(runId: string | undefined) {
  return useQuery({
    queryKey: ["runInvestigations", runId],
    queryFn: () => recon0.runInvestigations(runId!),
    enabled: !!runId,
    staleTime: FIVE_MIN,
  });
}

export function useRunAttackSurface(runId: string | undefined) {
  return useQuery({
    queryKey: ["runAttackSurface", runId],
    queryFn: () => recon0.runAttackSurface(runId!),
    enabled: !!runId,
    staleTime: FIVE_MIN,
  });
}

// ── Host annotations (F4) ──

export function useHostAnnotations() {
  return useQuery({
    queryKey: ["hostAnnotations"],
    queryFn: () => recon0.hostAnnotations(),
    staleTime: 30 * 1000,
  });
}

export function useUpsertHostAnnotation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      hostname,
      ...body
    }: {
      hostname: string;
      description: string;
      review_status: import("./types").ReviewStatus;
      expected_version: number;
    }) => recon0.upsertHostAnnotation(hostname, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["hostAnnotations"] });
    },
  });
}

export function useDeleteHostAnnotation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (hostname: string) => recon0.deleteHostAnnotation(hostname),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["hostAnnotations"] });
    },
  });
}

// ── Programs (F1) ──

export function usePrograms() {
  return useQuery({
    queryKey: ["programs"],
    queryFn: () => recon0.programs(),
    staleTime: 30 * 1000,
  });
}

export function useProgram(name: string | undefined) {
  return useQuery({
    queryKey: ["program", name],
    queryFn: () => recon0.program(name!),
    enabled: !!name,
    staleTime: 30 * 1000,
  });
}

export function useCreateProgram() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: import("./types").CreateProgramBody) =>
      recon0.createProgram(body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["programs"] });
    },
  });
}

export function useUpdateProgram() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      name,
      ...body
    }: { name: string } & import("./types").UpdateProgramBody) =>
      recon0.updateProgram(name, body),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ["programs"] });
      qc.invalidateQueries({ queryKey: ["program", vars.name] });
    },
  });
}

export function useDeleteProgram() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => recon0.deleteProgram(name),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["programs"] });
    },
  });
}

// ── Vulnerabilities (F2/F5) ──

export function useVulnerabilities() {
  return useQuery({
    queryKey: ["vulnerabilities"],
    queryFn: () => recon0.vulnerabilities(),
    staleTime: 30 * 1000,
  });
}

export function useVulnerability(id: string | undefined) {
  return useQuery({
    queryKey: ["vulnerability", id],
    queryFn: () => recon0.vulnerability(id!),
    enabled: !!id,
    staleTime: 30 * 1000,
  });
}

export function useCreateVuln() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: import("./types").CreateVulnBody) =>
      recon0.createVuln(body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["vulnerabilities"] });
    },
  });
}

export function useUpdateVuln() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      ...body
    }: { id: string } & import("./types").UpdateVulnBody) =>
      recon0.updateVuln(id, body),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ["vulnerabilities"] });
      qc.invalidateQueries({ queryKey: ["vulnerability", vars.id] });
    },
  });
}

export function useDeleteVuln() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => recon0.deleteVuln(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["vulnerabilities"] });
    },
  });
}
