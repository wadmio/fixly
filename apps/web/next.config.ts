import type { NextConfig } from "next";

// Content-Security-Policy: defense-in-depth for the scan report, which renders
// third-party OSV data (advisory titles, reference links). Reference URLs are
// already filtered to http(s) in @fixly/core, but this backstops the whole
// origin: no external script/frame/object, and clickjacking is blocked.
// 'unsafe-inline'/'unsafe-eval' are required by Next's runtime (no nonce setup).
const csp = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

const nextConfig: NextConfig = {
  // Compile the workspace source packages instead of expecting pre-built dist.
  transpilePackages: ["@fixly/core", "@fixly/ui"],
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Content-Security-Policy", value: csp },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
        ],
      },
    ];
  },
};

export default nextConfig;
