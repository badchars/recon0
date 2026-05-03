"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Toaster } from "sonner";
import { setBaseUrl } from "@/lib/api/recon0";
import { useSettings } from "@/lib/store/settings";
import { VulnMigration } from "@/components/vuln-migration";

export function Providers({ children }: { children: React.ReactNode }) {
  const [client] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 1000,
            refetchOnWindowFocus: false,
            retry: 1,
          },
        },
      }),
  );

  const instanceUrl = useSettings((s) => s.instanceUrl);
  useEffect(() => {
    if (instanceUrl) setBaseUrl(instanceUrl);
  }, [instanceUrl]);

  return (
    <QueryClientProvider client={client}>
      <VulnMigration />
      {children}
      <Toaster position="bottom-right" richColors closeButton />
    </QueryClientProvider>
  );
}
