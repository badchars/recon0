import { RunDetailView } from "@/components/runs/run-detail-view";

export default async function RunDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <RunDetailView runId={id} />;
}
