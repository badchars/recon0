import { VulnsTable } from "@/components/vulnerabilities/vulns-table";

export default function VulnerabilitiesPage() {
  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          Vulnerabilities
        </h1>
        <p className="text-sm text-muted-foreground">
          Manuel ve scan&apos;den taşınan zafiyetlerin envanteri.
        </p>
      </div>

      <VulnsTable />
    </div>
  );
}
