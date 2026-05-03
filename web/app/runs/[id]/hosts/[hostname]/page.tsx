import { HostDetailView } from "@/components/runs/host-detail-view";

export default async function HostDetailPage({
  params,
}: {
  params: Promise<{ id: string; hostname: string }>;
}) {
  const { id, hostname } = await params;
  return (
    <HostDetailView
      runId={id}
      hostname={decodeURIComponent(hostname)}
    />
  );
}
