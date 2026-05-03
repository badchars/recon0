import { VulnForm } from "@/components/vulnerabilities/vuln-form";

export default async function EditVulnPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <VulnForm id={id} />;
}
