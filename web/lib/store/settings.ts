"use client";

import { create } from "zustand";
import { persist } from "zustand/middleware";

interface SettingsState {
  instanceUrl: string;
  setInstanceUrl: (url: string) => void;
}

// Keep this string identical on server and client to avoid hydration
// mismatch. Dynamic detection (e.g. for LAN access) is left to the user
// via Settings → Test → Save.
const DEFAULT_INSTANCE_URL = "http://localhost:8484";

export const useSettings = create<SettingsState>()(
  persist(
    (set) => ({
      instanceUrl: DEFAULT_INSTANCE_URL,
      setInstanceUrl: (instanceUrl) => set({ instanceUrl }),
    }),
    { name: "recon0-panel-settings" },
  ),
);
