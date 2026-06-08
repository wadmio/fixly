import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Compile the workspace source packages instead of expecting pre-built dist.
  transpilePackages: ["@fixly/core", "@fixly/ui"],
};

export default nextConfig;
