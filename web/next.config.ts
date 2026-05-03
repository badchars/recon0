import type { NextConfig } from "next";
import path from "node:path";

const nextConfig: NextConfig = {
  // Pin Turbopack root to this project — without this, Next.js walks up
  // and picks a stray package-lock.json from $HOME or a parent dir.
  turbopack: {
    root: path.resolve(__dirname),
  },
  // Allow LAN-IP access during development. Without this, Next.js 16 blocks
  // HMR/devtools requests from anything but localhost.
  allowedDevOrigins: ["192.168.1.149", "147.135.60.70"],
};

export default nextConfig;
