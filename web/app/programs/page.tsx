import { ProgramsTable } from "@/components/programs/programs-table";

export default function ProgramsPage() {
  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Programs</h1>
        <p className="text-sm text-muted-foreground">
          Bug bounty programs — name, vendor, link, scope.
        </p>
      </div>
      <ProgramsTable />
    </div>
  );
}
