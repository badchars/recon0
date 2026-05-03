import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Allow LAN-IP access during development. Without this, Next.js 16 blocks
  // HMR/devtools requests from anything but localhost.
  allowedDevOrigins: ["192.168.1.149"],
};

export default nextConfig;
