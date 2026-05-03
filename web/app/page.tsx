import { ActiveScanCard } from "@/components/dashboard/active-scan-card";
import { PendingQueue } from "@/components/dashboard/pending-queue";
import { RecentRuns } from "@/components/dashboard/recent-runs";

export default function DashboardPage() {
  return (
    <div className="p-6 space-y-6 max-w-6xl">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p className="text-sm text-muted-foreground">
          Active scan, queue, and recent runs.
        </p>
      </div>

      <ActiveScanCard />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <PendingQueue />
        <RecentRuns />
      </div>
    </div>
  );
}
