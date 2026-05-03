import { ProgramDashboard } from "@/components/programs/program-dashboard";

export default async function ProgramDetailPage({
  params,
}: {
  params: Promise<{ name: string }>;
}) {
  const { name } = await params;
  return <ProgramDashboard name={decodeURIComponent(name)} />;
}
