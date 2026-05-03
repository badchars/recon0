import { RunsTable } from "@/components/runs/runs-table";

export default function RunsPage() {
  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Runs</h1>
        <p className="text-sm text-muted-foreground">
          Pipeline çalıştırma geçmişi.
        </p>
      </div>

      <RunsTable />
    </div>
  );
}
