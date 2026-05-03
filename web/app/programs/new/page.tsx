import { ProgramForm } from "@/components/programs/program-form";

export default async function NewProgramPage({
  searchParams,
}: {
  searchParams: Promise<{ name?: string }>;
}) {
  const { name } = await searchParams;
  return <ProgramForm defaultName={name} />;
}
